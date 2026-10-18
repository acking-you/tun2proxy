//! Per-question DNS routing: a shared OS resolver can mix games and browsers
//! on the same socket, so socket ownership cannot select one route for it.

use crate::{SocketQueue, dns, proxy_handler::ProxyHandler};
use std::{future::Future, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::QueryOrigins;

pub(crate) trait DnsOverride: Clone + Send + Sync + 'static {
    fn active(&self) -> bool {
        true
    }
    fn matches(&self, request: &[u8]) -> impl Future<Output = crate::Result<bool>> + Send;
    fn answer(&self, request: Vec<u8>, udp: bool) -> impl Future<Output = crate::Result<Vec<u8>>> + Send;
}

#[cfg(any(test, not(any(target_os = "windows", target_os = "linux", target_os = "macos"))))]
#[derive(Clone)]
pub(crate) struct NoDnsOverride;

#[cfg(any(test, not(any(target_os = "windows", target_os = "linux", target_os = "macos"))))]
impl DnsOverride for NoDnsOverride {
    fn active(&self) -> bool {
        false
    }
    async fn matches(&self, _: &[u8]) -> crate::Result<bool> {
        Ok(false)
    }
    async fn answer(&self, _: Vec<u8>, _: bool) -> crate::Result<Vec<u8>> {
        Err("DNS override is unavailable".into())
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[derive(Clone)]
pub(crate) struct ProcessDns {
    #[cfg(windows)]
    pub processes: crate::ProcessBypass,
    #[cfg(windows)]
    pub origins: Option<QueryOrigins>,
    pub interface: Option<Arc<crate::direct::BindInterface>>,
    pub configured_dns: std::net::IpAddr,
    pub ipv6: bool,
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
impl DnsOverride for ProcessDns {
    fn active(&self) -> bool {
        #[cfg(windows)]
        {
            self.interface.is_some() && self.origins.is_some()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
    async fn matches(&self, _request: &[u8]) -> crate::Result<bool> {
        #[cfg(windows)]
        if self.interface.is_some()
            && let Some(origins) = &self.origins
        {
            return origins.bypass(_request, &self.processes).await;
        }
        Ok(false)
    }

    async fn answer(&self, request: Vec<u8>, udp: bool) -> crate::Result<Vec<u8>> {
        let interface = self.interface.as_deref().ok_or("physical DNS interface unavailable")?;
        let started = std::time::Instant::now();
        let response = crate::physical_dns::answer(&request, self.configured_dns, interface, self.ipv6, udp).await?;
        let message = dns::parse_data_to_dns_message(&response, false)?;
        log::info!(
            "Application DNS bypass: name={}, interface={}, elapsed_ms={}, response={:?}, address={:?}",
            dns::extract_domain_from_dns_message(&message)?,
            interface,
            started.elapsed().as_millis(),
            message.response_code,
            dns::extract_ipaddr_from_dns_message(&message).ok()
        );
        Ok(response)
    }
}

/// Open the proxy lazily: physical DNS must work even when no proxy connection
/// has been established. One connection still carries all ordinary questions.
pub(crate) struct Upstream {
    handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    stream: Option<TcpStream>,
}

async fn write_request(stream: &mut (impl tokio::io::AsyncWrite + Unpin), request: &[u8]) -> crate::Result<()> {
    // Keep the length and body in one write, preserving the existing framing
    // path without adding a small prefix write that can trigger delayed ACKs.
    let mut frame = Vec::with_capacity(request.len() + 2);
    frame.extend_from_slice(&u16::try_from(request.len())?.to_be_bytes());
    frame.extend_from_slice(request);
    stream.write_all(&frame).await?;
    crate::traffic_status::traffic_status_update(request.len() + 2, 0)?;
    Ok(())
}

impl Upstream {
    pub fn new(handler: Arc<Mutex<dyn ProxyHandler>>, socket_queue: Option<Arc<SocketQueue>>) -> Self {
        Self {
            handler,
            socket_queue,
            stream: None,
        }
    }

    pub async fn send(&mut self, request: &[u8]) -> crate::Result<()> {
        if self.stream.is_none() {
            let address = self.handler.lock().await.get_server_addr();
            let mut stream = crate::create_tcp_stream(&self.socket_queue, address, None).await?;
            crate::handle_proxy_session(&mut stream, self.handler.clone()).await?;
            self.stream = Some(stream);
        }
        write_request(self.stream.as_mut().expect("upstream was initialized"), request).await
    }

    /// Independently poll upstream negotiation and writes while the shared UDP
    /// socket continues accepting questions for the physical resolver.
    pub async fn forward(
        mut self,
        mut requests: tokio::sync::mpsc::Receiver<Vec<u8>>,
        responses: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> crate::Result<()> {
        let Some(first) = requests.recv().await else { return Ok(()) };
        self.send(&first).await?;
        let mut stream = self.stream.take().expect("send opened the upstream");
        let (mut reader, mut writer) = stream.split();
        let send = async {
            while let Some(request) = requests.recv().await {
                write_request(&mut writer, &request).await?;
            }
            Ok::<_, crate::Error>(())
        };
        let receive = async {
            loop {
                let mut prefix = [0; 2];
                if reader.read(&mut prefix[..1]).await? == 0 {
                    return Ok(());
                }
                reader.read_exact(&mut prefix[1..]).await?;
                let mut response = vec![0; usize::from(u16::from_be_bytes(prefix))];
                reader.read_exact(&mut response).await?;
                crate::traffic_status::traffic_status_update(0, response.len() + 2)?;
                if responses.send(response).await.is_err() {
                    return Ok(());
                }
            }
        };
        // Dropping this owned future cancels both halves, including a stalled
        // negotiation. No detached relay or extra task survives session cleanup.
        tokio::select! {
            result = send => result,
            result = receive => result,
        }
    }

    pub async fn exchange(&mut self, request: &[u8]) -> crate::Result<Vec<u8>> {
        let query = dns::parse_data_to_dns_message(request, false)?;
        let question = dns::validate_dns_query(&query)?;
        self.send(request).await?;
        let stream = self.stream.as_mut().expect("send opened the upstream");
        let size = stream.read_u16().await?;
        let mut response = vec![0; usize::from(size)];
        stream.read_exact(&mut response).await?;
        crate::traffic_status::traffic_status_update(0, response.len() + 2)?;
        let message = dns::parse_data_to_dns_message(&response, false)?;
        dns::validate_dns_response(&message, query.id, question)?;
        Ok(response)
    }
}

pub(crate) async fn tcp<S>(
    stream: &mut S,
    handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6: bool,
    resolver: impl DnsOverride,
) -> crate::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut upstream = Upstream::new(handler, socket_queue);
    loop {
        let mut prefix = [0; 2];
        if stream.read(&mut prefix[..1]).await? == 0 {
            return Ok(());
        }
        stream.read_exact(&mut prefix[1..]).await?;
        let mut request = vec![0; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut request).await?;
        let response = if resolver.matches(&request).await? {
            resolver.answer(request, false).await?
        } else {
            upstream.exchange(&request).await?
        };
        let mut message = dns::parse_data_to_dns_message(&response, false)?;
        if !ipv6 {
            dns::remove_ipv6_entries(&mut message);
        }
        let response = message.to_vec()?;
        stream.write_u16(u16::try_from(response.len())?).await?;
        stream.write_all(&response).await?;
    }
}

#[cfg(all(test, any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod tests;
