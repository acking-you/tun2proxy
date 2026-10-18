use super::*;
use crate::{
    ProcessBypass, VirtualDnsState,
    no_proxy::NoProxyManager,
    proxy_handler::ProxyHandlerManager,
    session_info::{IpProtocol, SessionInfo},
};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::mpsc,
};

pub(super) fn request(name: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.id = 42;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}
fn reply(request: &[u8], physical: bool) -> Vec<u8> {
    dns::build_dns_response(
        Message::from_vec(request).unwrap(),
        Some(if physical { "192.0.2.1" } else { "192.0.2.2" }.parse().unwrap()),
        10,
    )
    .unwrap()
    .to_vec()
    .unwrap()
}
fn assert_reply(bytes: &[u8], name: &str, physical: bool) {
    let message = Message::from_vec(bytes).unwrap();
    assert_eq!(message.id, 42);
    assert_eq!(message.queries[0].name().to_ascii(), name);
    assert_eq!(
        dns::extract_ipaddr_from_dns_message(&message).unwrap().to_string(),
        if physical { "192.0.2.1" } else { "192.0.2.2" }
    );
}
async fn frame(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let size = stream.read_u16().await.unwrap();
    let mut data = vec![0; usize::from(size)];
    stream.read_exact(&mut data).await.unwrap();
    data
}
async fn send_frame(stream: &mut (impl AsyncWrite + Unpin), data: &[u8]) {
    stream.write_u16(data.len() as u16).await.unwrap();
    stream.write_all(data).await.unwrap();
}
async fn handler(address: std::net::SocketAddr) -> Arc<Mutex<dyn ProxyHandler>> {
    NoProxyManager::new()
        .new_proxy_handler(
            SessionInfo::new("127.0.0.1:10001".parse().unwrap(), address, IpProtocol::Tcp),
            None,
            false,
        )
        .await
        .unwrap()
}

#[derive(Clone)]
struct TestResolver {
    policy: ProcessBypass,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    gate: Option<Arc<tokio::sync::Notify>>,
}
impl TestResolver {
    fn new() -> Self {
        Self {
            policy: ProcessBypass::new(["excluded.exe".into()]),
            calls: Arc::default(),
            gate: None,
        }
    }
}
impl DnsOverride for TestResolver {
    async fn matches(&self, request: &[u8]) -> crate::Result<bool> {
        let message = dns::parse_data_to_dns_message(request, false)?;
        let identities = if message.queries[0].name().to_ascii() == "google.com." {
            vec!["browser".into()]
        } else {
            vec!["excluded".into()]
        };
        Ok(crate::process::matches_policy(&self.policy, &identities))
    }
    async fn answer(&self, request: Vec<u8>, _: bool) -> crate::Result<Vec<u8>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(gate) = &self.gate {
            gate.notified().await;
        }
        Ok(reply(&request, true))
    }
}

#[tokio::test]
async fn arbitrary_process_dns_policy_updates_apply_to_new_questions() {
    let resolver = TestResolver::new();
    assert!(resolver.matches(&request("arbitrary.example.")).await.unwrap());
    assert!(!resolver.matches(&request("google.com.")).await.unwrap());
    resolver.policy.set_names(["browser.exe".into()]);
    assert!(!resolver.matches(&request("arbitrary.example.")).await.unwrap());
    assert!(resolver.matches(&request("google.com.")).await.unwrap());
}

// Unlike a byte-stream duplex, one channel item is exactly one UDP datagram.
struct Packets {
    input: mpsc::UnboundedReceiver<Vec<u8>>,
    output: mpsc::UnboundedSender<Vec<u8>>,
}
impl AsyncRead for Packets {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.input.poll_recv(cx).map(|data| {
            if let Some(data) = data {
                assert!(data.len() <= buf.remaining());
                buf.put_slice(&data);
            }
            Ok(())
        })
    }
}
impl AsyncWrite for Packets {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<std::io::Result<usize>> {
        Poll::Ready(
            self.output
                .send(bytes.to_vec())
                .map(|()| bytes.len())
                .map_err(|_| std::io::ErrorKind::BrokenPipe.into()),
        )
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(windows)]
pub(super) async fn verify_real_process_dns_routing(host: &str, policy: ProcessBypass, origins: QueryOrigins) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let interface = Arc::new(crate::direct::detect(None, None).unwrap());
        let resolver = ProcessDns {
            processes: policy.clone(),
            origins: Some(origins),
            interface: Some(interface.clone()),
            configured_dns: "223.5.5.5".parse().unwrap(),
            ipv6: false,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let handler = handler(listener.local_addr().unwrap()).await;
        let (tx, input) = mpsc::unbounded_channel();
        let (output, mut rx) = mpsc::unbounded_channel();
        let relay = tokio::spawn(crate::handle_dns_over_tcp_session(
            Packets { input, output },
            handler,
            None,
            false,
            resolver,
        ));
        let query = request(host);
        let started = std::time::Instant::now();
        tx.send(query.clone()).unwrap();
        // No upstream server answers this request: it must complete through the
        // actual physical-bound resolver selected by the real child PID event.
        let response = Message::from_vec(&rx.recv().await.unwrap()).unwrap();
        dns::validate_dns_response(&response, 42, &Message::from_vec(&query).unwrap().queries[0]).unwrap();
        assert_ne!(response.response_code, hickory_proto::op::ResponseCode::ServFail);
        println!(
            "Real physical DNS via {interface}: {:?} in {:?}",
            response.response_code,
            started.elapsed()
        );

        policy.set_names(["unrelated.exe".into()]);
        tx.send(query).unwrap();
        let (mut upstream, _) = listener.accept().await.unwrap();
        let forwarded = frame(&mut upstream).await;
        send_frame(&mut upstream, &reply(&forwarded, false)).await;
        assert_reply(&rx.recv().await.unwrap(), &format!("{host}."), false);
        println!("Removing the process exclusion restored the upstream DNS path on the same socket");
        drop(tx);
        relay.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shared_udp_socket_splits_routes_and_coalesces_retries_with_colliding_ids() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let handler = handler(listener.local_addr().unwrap()).await;
        let mut resolver = TestResolver::new();
        let gate = Arc::new(tokio::sync::Notify::new());
        resolver.gate = Some(gate.clone());
        let (tx, input) = mpsc::unbounded_channel();
        let (output, mut rx) = mpsc::unbounded_channel();
        let relay = tokio::spawn(crate::handle_dns_over_tcp_session(
            Packets { input, output },
            handler,
            None,
            false,
            resolver.clone(),
        ));
        let game = request("hn1-k8s-sgp.lol.qq.com.");
        tx.send(game.clone()).unwrap();
        tx.send(game).unwrap();
        tx.send(request("google.com.")).unwrap();
        let (mut upstream, _) = listener.accept().await.unwrap();
        let forwarded = frame(&mut upstream).await;
        assert_eq!(Message::from_vec(&forwarded).unwrap().queries[0].name().to_ascii(), "google.com.");
        assert_ne!(Message::from_vec(&forwarded).unwrap().id, 42);
        send_frame(&mut upstream, &reply(&forwarded, false)).await;
        assert_reply(&rx.recv().await.unwrap(), "google.com.", false);
        gate.notify_one();
        assert_reply(&rx.recv().await.unwrap(), "hn1-k8s-sgp.lol.qq.com.", true);
        assert_eq!(resolver.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        drop(tx);
        relay.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_and_fake_ip_queries_keep_game_answers_physical_and_other_routes_unchanged() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for virtual_mode in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let handler = handler(listener.local_addr().unwrap()).await;
            let (mut client, mut server) = tokio::io::duplex(4096);
            let resolver = TestResolver::new();
            let relay = tokio::spawn(async move {
                if virtual_mode {
                    crate::handle_virtual_dns_tcp_session(server, VirtualDnsState::default().resolver(), resolver).await
                } else {
                    tcp(&mut server, handler, None, false, resolver).await
                }
            });
            // A direct question must complete before any upstream is accepted.
            send_frame(&mut client, &request("lol.qq.com.")).await;
            assert_reply(&frame(&mut client).await, "lol.qq.com.", true);
            send_frame(&mut client, &request("google.com.")).await;
            if virtual_mode {
                let response = Message::from_vec(&frame(&mut client).await).unwrap();
                assert!(
                    dns::extract_ipaddr_from_dns_message(&response)
                        .unwrap()
                        .to_string()
                        .starts_with("198.")
                );
            } else {
                let (mut stream, _) = listener.accept().await.unwrap();
                let forwarded = frame(&mut stream).await;
                send_frame(&mut stream, &reply(&forwarded, false)).await;
                assert_reply(&frame(&mut client).await, "google.com.", false);
            }
            drop(client);
            relay.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}
