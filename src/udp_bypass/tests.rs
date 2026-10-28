use super::*;
use tokio::time::timeout;

fn interface() -> Arc<BindInterface> {
    Arc::new(BindInterface {
        ipv4_index: 1,
        ipv6_index: 1,
        ipv4_addr: None,
        dns_servers: Vec::new(),
        name: "test-loopback".into(),
    })
}

fn owner() -> SocketOwner {
    SocketOwner { pid: 7, bound_at: 10 }
}

fn loopback_interface() -> Arc<BindInterface> {
    let adapter = netdev::get_interfaces()
        .into_iter()
        .find(|adapter| adapter.ipv4.iter().any(|ip| ip.addr().is_loopback()))
        .unwrap();
    Arc::new(BindInterface {
        ipv4_index: adapter.index,
        ipv6_index: adapter.index,
        ipv4_addr: Some(std::net::Ipv4Addr::LOCALHOST),
        dns_servers: Vec::new(),
        name: adapter.name,
    })
}

fn open(pool: &Pool, source: SocketAddr, peer: SocketAddr, owner: SocketOwner, interface: Arc<BindInterface>) -> Flow {
    pool.open_with(source, peer, owner, interface, std::future::pending(), |ipv6, _| {
        let socket = std::net::UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    })
    .unwrap()
    .unwrap()
}

async fn observed_source(server: &UdpSocket, payload: &[u8]) -> SocketAddr {
    let mut bytes = [0; 64];
    let (length, source) = timeout(Duration::from_secs(2), server.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..length], payload);
    source
}

async fn reply(flow: &mut Flow, expected: &[u8]) {
    let packet = timeout(Duration::from_secs(2), flow.receiver.recv()).await.unwrap().unwrap();
    assert_eq!(packet.bytes, expected);
}

#[tokio::test]
async fn same_source_shares_mapping_and_routes_only_contacted_peer_replies() {
    for (bind, source, other_source) in [
        ("127.0.0.1:0", "10.0.0.2:12345", "10.0.0.2:12346"),
        ("[::1]:0", "[fd00::2]:12345", "[fd00::2]:12346"),
    ] {
        let pool = Pool::new(8, None);
        let a = UdpSocket::bind(bind).await.unwrap();
        let b = UdpSocket::bind(bind).await.unwrap();
        let stranger = UdpSocket::bind(bind).await.unwrap();
        let mut fa = open(&pool, source.parse().unwrap(), a.local_addr().unwrap(), owner(), interface());
        let mut fb = open(&pool, source.parse().unwrap(), b.local_addr().unwrap(), owner(), interface());
        let mut physical = None;
        for flow in [&fa, &fb, &fa, &fb] {
            flow.send(b"probe").await.unwrap();
            let server = if flow.peer == a.local_addr().unwrap() { &a } else { &b };
            let address = observed_source(server, b"probe").await;
            assert_eq!(*physical.get_or_insert(address), address);
        }
        let physical = physical.unwrap();
        stranger.send_to(b"uncontacted", physical).await.unwrap();
        b.send_to(b"p2p", physical).await.unwrap();
        a.send_to(b"stun", physical).await.unwrap();
        reply(&mut fb, b"p2p").await;
        reply(&mut fa, b"stun").await;

        // Ending the STUN flow leaves the P2P mapping alive; even a gap with
        // no target flows does not immediately throw away that mapping.
        drop(fa);
        fb.send(b"after-stun").await.unwrap();
        assert_eq!(observed_source(&b, b"after-stun").await, physical);
        drop(fb);
        let fa = open(&pool, source.parse().unwrap(), a.local_addr().unwrap(), owner(), interface());
        fa.send(b"reopen").await.unwrap();
        assert_eq!(observed_source(&a, b"reopen").await, physical);

        let mut other = open(&pool, other_source.parse().unwrap(), a.local_addr().unwrap(), owner(), interface());
        other.send(b"isolated").await.unwrap();
        let other_physical = observed_source(&a, b"isolated").await;
        assert_ne!(other_physical, physical);
        a.send_to(b"other", other_physical).await.unwrap();
        reply(&mut other, b"other").await;
        pool.shutdown().await;
        assert!(fa.send(b"closed").await.is_err());
    }
}

#[tokio::test]
async fn shared_relay_restores_original_peer_and_preserves_empty_and_fragmented_datagrams() {
    let pool = Pool::new(4, None);
    let source = "10.0.0.2:12345".parse().unwrap();
    let original_peer = "198.18.0.10:443".parse().unwrap();
    for payload in [Vec::new(), vec![42; 4096]] {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let flow = open(&pool, source, server.local_addr().unwrap(), owner(), interface());
        let (sender, mut packets) = mpsc::unbounded_channel();
        let stack = IpStackUdpStream::new(source, original_peer, payload.clone(), sender, 1500, Duration::from_secs(30), None);
        let relay = flow.relay(stack);
        tokio::pin!(relay);
        let peer = async {
            let mut received = vec![0; 65535];
            let (length, physical) = server.recv_from(&mut received).await.unwrap();
            assert_eq!(&received[..length], payload);
            server.send_to(&payload, physical).await.unwrap();
            let mut datagram = Vec::new();
            while datagram.len() < payload.len() + 8 {
                let wire = packets.recv().await.unwrap().to_bytes().unwrap();
                assert_eq!(&wire[12..16], &[198, 18, 0, 10]);
                assert_eq!(&wire[16..20], &[10, 0, 0, 2]);
                let offset = u16::from_be_bytes([wire[6], wire[7]]) & 0x1fff;
                assert_eq!(usize::from(offset) * 8, datagram.len());
                datagram.extend_from_slice(&wire[20..]);
            }
            assert_eq!(u16::from_be_bytes([datagram[0], datagram[1]]), 443);
            assert_eq!(u16::from_be_bytes([datagram[2], datagram[3]]), 12345);
            assert_eq!(&datagram[8..], payload);
        };
        timeout(Duration::from_secs(2), async {
            tokio::select! { result = &mut relay => panic!("relay ended: {result:?}"), _ = peer => {} }
        })
        .await
        .unwrap();
    }
    pool.shutdown().await;
}

#[tokio::test]
async fn rebind_and_egress_change_close_previous_flows() {
    let pool = Pool::new(2, None);
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = "10.0.0.2:12345".parse().unwrap();
    let first = open(&pool, source, server.local_addr().unwrap(), owner(), interface());
    first.send(b"old").await.unwrap();
    let old_port = observed_source(&server, b"old").await;
    // Bind timestamps are wall clock observations, not ordered generations.
    let replacement = SocketOwner { bound_at: 9, ..owner() };
    let second = open(&pool, source, server.local_addr().unwrap(), replacement, interface());
    assert!(first.send(b"stale").await.is_err());
    second.send(b"new").await.unwrap();
    assert_ne!(observed_source(&server, b"new").await, old_port);

    let mut changed = (*interface()).clone();
    changed.ipv4_index += 1;
    let third = open(&pool, source, server.local_addr().unwrap(), replacement, Arc::new(changed));
    assert!(second.send(b"stale-egress").await.is_err());
    first.endpoint.close(); // Retired-flow cleanup cannot close its successor.
    third.send(b"alive").await.unwrap();
    observed_source(&server, b"alive").await;
    third.endpoint.close();
    assert!(third.send(b"revoked").await.is_err());
    pool.shutdown().await;
}

#[tokio::test]
async fn live_validation_preserves_bindings_and_revokes_idle_endpoints() {
    use crate::{ProcessBypass, process::ProcessMatcher};

    let application = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let source = application.local_addr().unwrap();
    let executable = std::env::current_exe().unwrap();
    let rules = ProcessBypass::new([executable.file_name().unwrap().to_str().unwrap().to_owned()]);
    let matcher = Arc::new(ProcessMatcher::new(rules.clone()).unwrap());
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = server.local_addr().unwrap();
    let interface = loopback_interface();
    let (egress, updates) = watch::channel(interface.clone());
    let pool = Pool::new(2, Some(updates));
    let policy = matcher.match_session(crate::session_info::IpProtocol::Udp, source, peer).await;
    let first = pool.open(source, peer, policy).await.unwrap().unwrap();
    first.send(b"first").await.unwrap();
    let physical = observed_source(&server, b"first").await;
    let endpoint = first.endpoint.clone();
    drop(first);

    let mut changed_dns = (*interface).clone();
    changed_dns.dns_servers.push("192.0.2.53".parse().unwrap());
    changed_dns.ipv6_index += 1; // An IPv4 socket does not depend on this index.
    changed_dns.ipv4_addr = None; // Used only for multicast binding.
    egress.send_replace(Arc::new(changed_dns));
    pool.maintain().await;
    let policy = matcher.match_session(crate::session_info::IpProtocol::Udp, source, peer).await;
    let second = pool.open(source, peer, policy).await.unwrap().unwrap();
    second.send(b"same-bind").await.unwrap();
    assert_eq!(observed_source(&server, b"same-bind").await, physical);
    drop(second);

    // No flow remains to observe policy changes. The endpoint must retire itself.
    rules.set_names(Vec::new());
    timeout(Duration::from_secs(2), endpoint.closed.cancelled()).await.unwrap();
    rules.set_names([executable.file_name().unwrap().to_str().unwrap().to_owned()]);
    let policy = matcher.match_session(crate::session_info::IpProtocol::Udp, source, peer).await;
    let third = pool.open(source, peer, policy).await.unwrap().unwrap();
    third.send(b"replacement").await.unwrap();
    assert_ne!(observed_source(&server, b"replacement").await, physical);
    endpoint.close();
    third.send(b"still-alive").await.unwrap();
    observed_source(&server, b"still-alive").await;

    // Observed disappearance retires a mapping even if a later rebind gets an
    // identical FILETIME fingerprint. No elapsed-time assumption is required.
    drop(application);
    pool.maintain().await;
    assert!(third.send(b"owner-gone").await.is_err());
    let (validation, stale_owners) = pool.snapshot().await;
    let _replacement = std::net::UdpSocket::bind(source).unwrap();
    let policy = matcher.match_session(crate::session_info::IpProtocol::Udp, source, peer).await;
    let opening = pool.open(source, peer, policy);
    tokio::pin!(opening);
    tokio::select! {
        biased;
        _ = &mut opening => panic!("open overtook the older pending validation"),
        _ = tokio::task::yield_now() => {}
    }
    // Complete an older maintenance observation before registration can proceed.
    pool.maintain_with(Some(&stale_owners.unwrap()), Some(&interface));
    drop(validation);
    let fourth = opening.await.unwrap().unwrap();
    assert!(!Arc::ptr_eq(&third.endpoint, &fourth.endpoint));
    fourth.send(b"rebound").await.unwrap();
    observed_source(&server, b"rebound").await;
    pool.shutdown().await;
}

#[tokio::test]
async fn resource_pressure_drops_packets_without_reassigning_active_endpoints() {
    let mut pool = Pool::new(1, None);
    pool.budget = Arc::new(Semaphore::new(4));
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = "10.0.0.2:12345".parse().unwrap();
    let mut flow = open(&pool, source, server.local_addr().unwrap(), owner(), interface());
    assert!(
        pool.open_with(
            source,
            flow.peer,
            owner(),
            interface(),
            std::future::pending(),
            direct::bind_udp_unconnected
        )
        .unwrap()
        .is_none()
    );
    assert!(
        pool.open_with(
            "10.0.0.2:23456".parse().unwrap(),
            flow.peer,
            owner(),
            interface(),
            std::future::pending(),
            direct::bind_udp_unconnected
        )
        .unwrap()
        .is_none()
    );
    flow.send(b"probe").await.unwrap();
    let physical = observed_source(&server, b"probe").await;
    server.send_to(b"over-budget", physical).await.unwrap();
    server.send_to(b"ok", physical).await.unwrap();
    reply(&mut flow, b"ok").await;
    assert_eq!(pool.budget.available_permits(), 4);
    pool.maintain_with(Some(&UdpOwners::default()), Some(&interface()));
    assert!(flow.send(b"unverified-owner").await.is_err());
    pool.shutdown().await;
}

#[tokio::test]
async fn high_fanout_and_unreachable_peers_preserve_the_shared_endpoint() {
    let pool = Pool::new(400, None);
    let source = "10.0.0.2:12345".parse().unwrap();
    let interface = loopback_interface();
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut flow = pool
        .open_with(
            source,
            server.local_addr().unwrap(),
            owner(),
            interface.clone(),
            std::future::pending(),
            bind_shared_udp,
        )
        .unwrap()
        .unwrap();
    let mut peers = Vec::new();
    for port in 10000..10300 {
        let peer = SocketAddr::from(([127, 0, 0, 2], port));
        let next = open(&pool, source, peer, owner(), interface.clone());
        assert!(Arc::ptr_eq(&flow.endpoint, &next.endpoint));
        peers.push(next);
    }
    let unreachable = open(
        &pool,
        source,
        SocketAddr::from(([127, 0, 0, 2], server.local_addr().unwrap().port())),
        owner(),
        interface,
    );
    unreachable.send(b"probe").await.unwrap();
    flow.send(b"reachable").await.unwrap();
    let physical = observed_source(&server, b"reachable").await;
    server.send_to(b"reply", physical).await.unwrap();
    reply(&mut flow, b"reply").await;
    assert!(!flow.endpoint.closed.is_cancelled());
    pool.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn transient_owner_lookup_failure_has_a_bounded_grace_period() {
    let pool = Pool::new(1, None);
    let flow = open(
        &pool,
        "10.0.0.2:12345".parse().unwrap(),
        "127.0.0.1:12346".parse().unwrap(),
        owner(),
        interface(),
    );
    pool.maintain_with(None, Some(&interface()));
    assert!(!flow.endpoint.closed.is_cancelled());
    tokio::time::advance(OWNER_FAILURE_GRACE - Duration::from_secs(1)).await;
    pool.maintain_with(None, Some(&interface()));
    assert!(!flow.endpoint.closed.is_cancelled());
    tokio::time::advance(Duration::from_secs(1)).await;
    pool.maintain_with(None, Some(&interface()));
    assert!(flow.endpoint.closed.is_cancelled());
    pool.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn idle_endpoint_expires_and_shutdown_releases_receivers() {
    let pool = Pool::new(1, None);
    let source = "10.0.0.2:12345".parse().unwrap();
    let peer = "127.0.0.1:23456".parse().unwrap();
    let flow = open(&pool, source, peer, owner(), interface());
    let old_socket = flow.endpoint.socket.clone();
    let old_port = old_socket.local_addr().unwrap().port();
    drop(flow);
    tokio::time::advance(IDLE_TIMEOUT + Duration::from_secs(1)).await;
    let flow = open(&pool, source, peer, owner(), interface());
    assert_ne!(flow.endpoint.socket.local_addr().unwrap().port(), old_port);
    pool.shutdown().await;
    assert!(pool.is_empty());
    assert!(flow.send(b"closed").await.is_err());
}

#[tokio::test]
async fn captured_windows_udp_uses_process_policy_and_one_physical_socket_across_targets() {
    use crate::{ArgDns, ArgUdpStrategy, Args, NetworkEnvironment, ProcessBypass, ProxyParameters, run_with_preselected_egress};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Use the production classifier, forwarding loop and IP_UNICAST_IF binding,
    // with an in-memory TUN and loopback targets: no system routes are changed.
    let egress = loopback_interface();
    let application = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let source = SocketAddr::from(([10, 0, 0, 2], application.local_addr().unwrap().port()));
    let executable = std::env::current_exe().unwrap();
    let bypass = ProcessBypass::new([executable.file_name().unwrap().to_str().unwrap().to_owned()]);
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut host, device) = tokio::io::duplex(65536);
    let shutdown = CancellationToken::new();
    let mut tasks = JoinSet::new();
    tasks.spawn(run_with_preselected_egress(
        device,
        1500,
        Args {
            setup: false,
            bind_interface: Some(egress.name.clone()),
            dns: ArgDns::Direct,
            udp_strategy: ArgUdpStrategy::Block,
            proxy: ProxyParameters::try_from("socks5://127.0.0.1:9").unwrap(),
            ..Args::default()
        },
        shutdown.clone(),
        bypass,
        None,
        NetworkEnvironment::Physical(Some(egress)),
    ));
    timeout(Duration::from_secs(10), async {
        let mut physical = None;
        for target in [&a, &b, &a, &b] {
            let destination = target.local_addr().unwrap();
            let (sender, mut packets) = mpsc::unbounded_channel();
            let mut encoder = IpStackUdpStream::new(destination, source, Vec::new(), sender, 1500, Duration::from_secs(30), None);
            encoder.send(b"probe").unwrap();
            host.write_all(&packets.try_recv().unwrap().to_bytes().unwrap()).await.unwrap();
            let observed = observed_source(target, b"probe").await;
            assert_eq!(*physical.get_or_insert(observed), observed);
            target.send_to(b"reply", observed).await.unwrap();
            let mut reply = [0; 33];
            host.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[12..16], &[127, 0, 0, 1]);
            assert_eq!(&reply[16..20], &[10, 0, 0, 2]);
            assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), destination.port());
            assert_eq!(u16::from_be_bytes([reply[22], reply[23]]), source.port());
            assert_eq!(&reply[28..], b"reply");
        }
    })
    .await
    .unwrap();
    shutdown.cancel();
    timeout(Duration::from_secs(3), tasks.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .unwrap();
}
