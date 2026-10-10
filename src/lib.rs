#[cfg(target_os = "linux")]
extern crate bincode_next as bincode;

#[cfg(feature = "udpgw")]
use crate::udpgw::UdpGwClient;
use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDirection},
    http::HttpManager,
    no_proxy::NoProxyManager,
    session_info::{IpProtocol, SessionInfo},
    virtual_dns::VirtualDns,
};
pub use clap::ValueEnum;
use ipstack::{IpStackStream, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport};
use proxy_handler::{ProxyHandler, ProxyHandlerManager};
use socks::SocksProxyManager;
pub use socks5_impl::protocol::UserKey;
#[cfg(feature = "udpgw")]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::{Mutex, mpsc::Receiver},
};
pub use tokio_util::sync::CancellationToken;
use tproxy_config::is_private_ip;
#[cfg(feature = "udpgw")]
use udpgw::{UDPGW_KEEPALIVE_TIME, UDPGW_MAX_CONNECTIONS, UdpGwClientStream, UdpGwResponse};

pub use {
    args::{ArgDns, ArgProxy, ArgUdpStrategy, ArgVerbosity, Args, ProxyType},
    error::{BoxError, Error, Result},
    process_bypass::{ProcessBypass, normalize_process_name},
    traffic_status::{TrafficStatus, tun2proxy_set_traffic_status_callback},
    virtual_dns::VirtualDnsState,
};

#[cfg(target_os = "macos")]
pub use general_api::validate_macos_capture_routes;
pub use general_api::{
    general_run_async, general_run_async_with_process_bypass, general_run_async_with_process_bypass_and_ready,
    general_run_async_with_process_bypass_and_ready_and_virtual_dns, general_run_async_with_process_bypass_and_virtual_dns,
};

pub const FORCE_EXIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Packet MTU used by tun2proxy unless the caller explicitly overrides it.
///
/// The `tun` crate exposes Wintun's maximum packet size (`u16::MAX`) as its
/// Windows default. That is a driver buffer limit, not a generally routable
/// interface MTU. In particular, WSL mirrored networking presents the Wintun
/// route through a 1500-byte virtual NIC and silently loses oversized TCP
/// packets. Keep the default at the Ethernet-safe value on every platform.
pub const DEFAULT_MTU: u16 = 1500;

mod android;
mod args;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
mod direct;
mod directions;
mod dns;
mod dump_logger;
mod error;
mod general_api;
mod http;
pub mod icmp;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod network_config;
mod no_proxy;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
mod process;
mod process_bypass;
mod proxy_handler;
mod session_info;
pub mod socket_transfer;
mod socks;
mod traffic_status;
#[cfg(feature = "udpgw")]
pub mod udpgw;
mod virtual_dns;
#[doc(hidden)]
pub mod win_svc;
#[cfg(windows)]
#[doc(hidden)]
#[path = "bin/windows_elevation/mod.rs"]
pub mod windows_elevation;
#[cfg(windows)]
mod windows_network_config;

const DNS_PORT: u16 = 53;
const DNS_OVER_TLS_PORT: u16 = 853;
const MAX_OUTSTANDING_DNS_QUERIES: usize = 256;
const ICMP_V4_PROTOCOL: u8 = 1;
const ICMP_V6_PROTOCOL: u8 = 58;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos", test))]
fn is_local_multicast_destination(address: IpAddr) -> bool {
    address.is_multicast()
}

fn icmp_type_code(protocol: u8, payload: &[u8]) -> Option<(u8, u8)> {
    if protocol != ICMP_V4_PROTOCOL && protocol != ICMP_V6_PROTOCOL {
        return None;
    }
    payload.first().zip(payload.get(1)).map(|(&kind, &code)| (kind, code))
}

fn log_unknown_transport(packet: &IpStackUnknownTransport) {
    let protocol = packet.ip_protocol().0;
    let payload = packet.payload();
    let type_code = icmp_type_code(protocol, payload);
    match (protocol, type_code) {
        // Android emits this after a QUIC/UDP socket has already closed and a
        // late relayed response reaches its old port. It is feedback about the
        // dead UDP flow, not evidence that the VPN itself has no connectivity.
        (ICMP_V4_PROTOCOL, Some((3, 3))) | (ICMP_V6_PROTOCOL, Some((1, 4))) => log::debug!(
            "Discarding late UDP port-unreachable feedback {} -> {}, payload {} bytes",
            packet.src_addr(),
            packet.dst_addr(),
            payload.len()
        ),
        (ICMP_V4_PROTOCOL, Some((3, 4))) | (ICMP_V6_PROTOCOL, Some((2, _))) => log::warn!(
            "Discarding path-MTU feedback {} -> {}, ICMP type/code {:?}, payload {} bytes; consider lowering the VPN MTU",
            packet.src_addr(),
            packet.dst_addr(),
            type_code,
            payload.len()
        ),
        (_, Some((kind, code))) => log::info!(
            "Unhandled ICMP transport {} -> {}, protocol {protocol}, type {kind}, code {code}, payload {} bytes",
            packet.src_addr(),
            packet.dst_addr(),
            payload.len()
        ),
        _ => log::info!(
            "Unhandled transport {} -> {}, IP protocol {:?}, payload {} bytes",
            packet.src_addr(),
            packet.dst_addr(),
            packet.ip_protocol(),
            payload.len()
        ),
    }
}

#[derive(Debug, Default)]
struct SessionCounts {
    total: AtomicUsize,
    tcp: AtomicUsize,
    udp: AtomicUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionCountSnapshot {
    total: usize,
    tcp: usize,
    udp: usize,
}

impl SessionCounts {
    fn try_acquire(self: &Arc<Self>, protocol: IpProtocol, max_sessions: usize) -> Option<SessionPermit> {
        self.total
            .fetch_update(Relaxed, Relaxed, |count| (count < max_sessions).then_some(count + 1))
            .ok()?;
        self.protocol_count(protocol).fetch_add(1, Relaxed);
        let snapshot = self.snapshot();
        log::trace!("Session count total={}, TCP={}, UDP={}", snapshot.total, snapshot.tcp, snapshot.udp);
        Some(SessionPermit {
            counts: Arc::clone(self),
            protocol,
        })
    }

    fn snapshot(&self) -> SessionCountSnapshot {
        SessionCountSnapshot {
            total: self.total.load(Relaxed),
            tcp: self.tcp.load(Relaxed),
            udp: self.udp.load(Relaxed),
        }
    }

    fn protocol_count(&self, protocol: IpProtocol) -> &AtomicUsize {
        match protocol {
            IpProtocol::Tcp => &self.tcp,
            IpProtocol::Udp => &self.udp,
            _ => unreachable!("only TCP and UDP sessions are admitted"),
        }
    }
}

#[derive(Debug)]
struct SessionPermit {
    counts: Arc<SessionCounts>,
    protocol: IpProtocol,
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        self.counts.protocol_count(self.protocol).fetch_sub(1, Relaxed);
        self.counts.total.fetch_sub(1, Relaxed);
        let snapshot = self.counts.snapshot();
        log::trace!("Session count total={}, TCP={}, UDP={}", snapshot.total, snapshot.tcp, snapshot.udp);
    }
}

fn log_session_limit(protocol: IpProtocol, max_sessions: usize, counts: &SessionCounts) {
    let snapshot = counts.snapshot();
    log::warn!(
        "TUN session limit reached: total={}/{}, TCP={}, UDP={}; dropping new {} session",
        snapshot.total,
        max_sessions,
        snapshot.tcp,
        snapshot.udp,
        protocol
    );
}

/// Physical interface a process-bypass direct relay egresses through. On
/// platforms without the feature this is an uninhabited type, so the threaded
/// `Option<DirectBind>` is always `None` and carries zero cost.
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
type DirectBind = Arc<direct::BindInterface>;
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
type DirectBind = std::convert::Infallible;

/// Outcome of constructing a per-session proxy handler.
type HandlerResult = std::io::Result<Arc<Mutex<dyn ProxyHandler>>>;

/// Run one established relay until it finishes normally or a live process
/// policy update changes whether its source process should bypass the proxy.
/// A `None` result requires the TCP caller to explicitly reset the captured
/// stream: dropping a userspace relay alone does not notify the application.
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
async fn run_until_process_policy_change<F, T>(relay: F, policy: Option<process::SessionPolicy>) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    let Some(policy) = policy else {
        return Some(relay.await);
    };
    tokio::select! {
        result = relay => Some(result),
        _ = policy.wait_for_routing_change() => None,
    }
}

#[allow(unused)]
#[derive(Hash, Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    target_os = "linux",
    derive(bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize)
)]
pub enum SocketProtocol {
    Tcp,
    Udp,
}

#[allow(unused)]
#[derive(Hash, Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    target_os = "linux",
    derive(bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize)
)]
pub enum SocketDomain {
    IpV4,
    IpV6,
}

impl From<IpAddr> for SocketDomain {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self::IpV4,
            IpAddr::V6(_) => Self::IpV6,
        }
    }
}

struct SocketQueue {
    tcp_v4: Mutex<Receiver<TcpSocket>>,
    tcp_v6: Mutex<Receiver<TcpSocket>>,
    udp_v4: Mutex<Receiver<UdpSocket>>,
    udp_v6: Mutex<Receiver<UdpSocket>>,
}

impl SocketQueue {
    async fn recv_tcp(&self, domain: SocketDomain) -> Result<TcpSocket, std::io::Error> {
        match domain {
            SocketDomain::IpV4 => &self.tcp_v4,
            SocketDomain::IpV6 => &self.tcp_v6,
        }
        .lock()
        .await
        .recv()
        .await
        .ok_or(ErrorKind::Other.into())
    }
    async fn recv_udp(&self, domain: SocketDomain) -> Result<UdpSocket, std::io::Error> {
        match domain {
            SocketDomain::IpV4 => &self.udp_v4,
            SocketDomain::IpV6 => &self.udp_v6,
        }
        .lock()
        .await
        .recv()
        .await
        .ok_or(ErrorKind::Other.into())
    }
}

async fn create_tcp_stream(
    socket_queue: &Option<Arc<SocketQueue>>,
    peer: SocketAddr,
    bind: Option<&DirectBind>,
) -> std::io::Result<TcpStream> {
    // Process-bypass direct relays must egress through the physical interface so
    // they are not re-captured by the TUN. This only applies on the normal
    // (non-socket-transfer) path.
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    if let Some(iface) = bind {
        if socket_queue.is_none() {
            return direct::connect_tcp_bound(peer, iface).await;
        }
        log::warn!("process-bypass direct relay is incompatible with socket transfer; using default routing");
    }
    let _ = &bind;
    match &socket_queue {
        None => TcpStream::connect(peer).await,
        Some(queue) => queue.recv_tcp(peer.ip().into()).await?.connect(peer).await,
    }
}

/// A connected UDP socket must use send/recv. udp-stream's send_to on a
/// connected socket returns EISCONN on macOS. Keeping the socket here also
/// gives session cancellation ownership of the receiver, without a detached
/// background task or a second packet queue.
struct ConnectedUdpStream(UdpSocket);

impl AsyncRead for ConnectedUdpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_recv(cx, buf)
    }
}

impl AsyncWrite for ConnectedUdpStream {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

async fn create_udp_stream(
    socket_queue: &Option<Arc<SocketQueue>>,
    peer: SocketAddr,
    bind: Option<&DirectBind>,
) -> std::io::Result<ConnectedUdpStream> {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    if let Some(iface) = bind {
        if socket_queue.is_none() {
            let socket = direct::bind_udp_bound(peer, iface)?;
            return Ok(ConnectedUdpStream(socket));
        }
        log::warn!("process-bypass direct relay is incompatible with socket transfer; using default routing");
    }
    let _ = &bind;
    match &socket_queue {
        None => {
            let bind_addr = match peer {
                SocketAddr::V4(_) => SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
            };
            let socket = UdpSocket::bind(bind_addr).await?;
            socket.connect(peer).await?;
            Ok(ConnectedUdpStream(socket))
        }
        Some(queue) => {
            let socket = queue.recv_udp(peer.ip().into()).await?;
            socket.connect(peer).await?;
            Ok(ConnectedUdpStream(socket))
        }
    }
}

/// Replace a stale virtual-DNS destination with a real address before opening a
/// physical-interface-bound process bypass relay.
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
async fn restore_bypass_destination(
    info: &mut SessionInfo,
    virtual_dns: Option<&Arc<Mutex<VirtualDns>>>,
    dns_addr: IpAddr,
    bind: Option<&DirectBind>,
) -> std::io::Result<()> {
    let domain = resolve_virtual_domain(virtual_dns, info.dst.ip()).await?;
    let Some(domain) = domain else {
        return Ok(());
    };
    let bind = bind.ok_or_else(|| std::io::Error::other("process-bypass physical interface is unavailable"))?;
    let fake_destination = info.dst;
    let destination = direct::resolve_domain_bound(&domain, info.dst.port(), dns_addr, info.dst.is_ipv6(), bind).await?;
    info.dst = destination;
    log::info!("restored process-bypass destination `{domain}` from virtual address {fake_destination} to {destination}");
    Ok(())
}

/// Resolve a fake-IP destination and reject stale fake addresses explicitly.
/// Forwarding an unmapped 198.18.0.0/15 address to the upstream proxy only
/// turns a recoverable application DNS-cache miss into a long timeout.
async fn resolve_virtual_domain(virtual_dns: Option<&Arc<Mutex<VirtualDns>>>, destination: IpAddr) -> std::io::Result<Option<Arc<str>>> {
    let Some(virtual_dns) = virtual_dns else {
        return Ok(None);
    };
    let mut virtual_dns = virtual_dns.lock().await;
    virtual_dns.touch_ip(&destination);
    if let Some(domain) = virtual_dns.resolve_ip(&destination) {
        return Ok(Some(domain));
    }
    if virtual_dns.contains_address(destination) {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            format!("stale virtual DNS address {destination}; reconnect after refreshing DNS"),
        ));
    }
    Ok(None)
}

/// Resolve a virtual-DNS name before a direct UDP relay. Resolution itself uses
/// DNS-over-TCP through the configured proxy, so an Android resolver call
/// cannot re-enter the VPN DNS portal and return another fake IP.
async fn restore_direct_udp_destination(
    info: &mut SessionInfo,
    domain: Option<&str>,
    dns_addr: IpAddr,
    mgr: &Arc<dyn ProxyHandlerManager>,
    socket_queue: &Option<Arc<SocketQueue>>,
    bind: Option<&DirectBind>,
) -> std::io::Result<()> {
    let Some(domain) = domain else {
        return Ok(());
    };

    let virtual_destination = info.dst;
    let destination = resolve_domain_over_proxy(domain, info.dst.port(), dns_addr, info.dst.is_ipv6(), mgr, socket_queue, bind).await?;
    info.dst = destination;
    log::debug!("restored direct UDP destination `{domain}` from virtual address {virtual_destination} to {destination} via proxied DNS");
    Ok(())
}

async fn resolve_domain_over_proxy(
    domain: &str,
    port: u16,
    dns_server: IpAddr,
    want_ipv6: bool,
    mgr: &Arc<dyn ProxyHandlerManager>,
    socket_queue: &Option<Arc<SocketQueue>>,
    bind: Option<&DirectBind>,
) -> std::io::Result<SocketAddr> {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{Name, RecordType},
    };
    use std::{str::FromStr, sync::atomic::Ordering};

    static NEXT_QUERY_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);
    const DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    let resolver = SocketAddr::new(dns_server, DNS_PORT);
    let resolver_source = match resolver {
        SocketAddr::V4(_) => SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
    };
    let query_type = if want_ipv6 { RecordType::AAAA } else { RecordType::A };
    let mut current = domain.to_string();

    for _ in 0..dns::MAX_CNAME_DEPTH {
        let name = Name::from_str(&current).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let query = Query::query(name, query_type);
        let request_id = NEXT_QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let mut request = Message::new(request_id, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(query.clone());
        let request = request.to_vec().map_err(std::io::Error::other)?;

        let response = tokio::time::timeout(DNS_TIMEOUT, async {
            let info = SessionInfo::new(resolver_source, resolver, IpProtocol::Tcp);
            let proxy_handler = mgr.new_proxy_handler(info, None, false).await?;
            let proxy_addr = proxy_handler.lock().await.get_server_addr();
            let mut stream = create_tcp_stream(socket_queue, proxy_addr, bind).await?;
            handle_proxy_session(&mut stream, proxy_handler)
                .await
                .map_err(|error| std::io::Error::other(error.to_string()))?;

            let length = u16::try_from(request.len()).map_err(std::io::Error::other)?;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(&request).await?;

            let mut length = [0_u8; 2];
            stream.read_exact(&mut length).await?;
            let mut response = vec![0_u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut response).await?;
            std::io::Result::Ok(response)
        })
        .await
        .map_err(|_| std::io::Error::new(ErrorKind::TimedOut, format!("proxied DNS query for `{current}` timed out")))??;

        let response = Message::from_vec(&response).map_err(std::io::Error::other)?;
        dns::validate_dns_response(&response, request_id, &query).map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))?;
        if response.response_code != ResponseCode::NoError {
            return Err(std::io::Error::other(format!(
                "proxied DNS query for `{current}` failed with {:?}",
                response.response_code
            )));
        }
        match dns::extract_address_or_cname(&response, &query).map_err(|error| std::io::Error::new(ErrorKind::NotFound, error))? {
            dns::AddressLookup::Address(ip) => return Ok(SocketAddr::new(ip, port)),
            dns::AddressLookup::Cname(name) => current = name,
        }
    }

    Err(std::io::Error::new(
        ErrorKind::InvalidData,
        format!("proxied DNS resolution for `{domain}` exceeded the CNAME limit"),
    ))
}

/// Run the proxy server
/// # Arguments
/// * `device` - The network device to use
/// * `mtu` - The MTU of the network device
/// * `args` - The arguments to use
/// * `shutdown_token` - The token to exit the server
/// # Returns
/// * The number of sessions while exiting
pub async fn run<D>(device: D, mtu: u16, args: Args, shutdown_token: CancellationToken) -> crate::Result<usize>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let process_bypass = ProcessBypass::new(args.bypass_process.clone());
    run_with_process_bypass(device, mtu, args, shutdown_token, process_bypass).await
}

/// Run the proxy server with a process list that may be replaced at runtime.
pub async fn run_with_process_bypass<D>(
    device: D,
    mtu: u16,
    args: Args,
    shutdown_token: CancellationToken,
    process_bypass: ProcessBypass,
) -> crate::Result<usize>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_with_process_bypass_and_virtual_dns(device, mtu, args, shutdown_token, process_bypass, None).await
}

/// Run with an optional fake-IP state owned by an embedding application.
///
/// The regular CLI leaves this as `None` and receives an isolated resolver.
/// Long-running embedders can reuse one state across route restarts so cached
/// fake IPs do not become unreachable during an upstream hot switch.
pub async fn run_with_process_bypass_and_virtual_dns<D>(
    device: D,
    mtu: u16,
    args: Args,
    shutdown_token: CancellationToken,
    process_bypass: ProcessBypass,
    virtual_dns_state: Option<VirtualDnsState>,
) -> crate::Result<usize>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_with_preselected_egress(
        device,
        mtu,
        args,
        shutdown_token,
        process_bypass,
        virtual_dns_state,
        NetworkEnvironment::Physical(None),
    )
    .await
}

/// The platform provider owns routes, DNS and exemption of its own sockets.
/// This entry point never creates a device, discovers an egress interface or
/// enumerates other processes. Only use it inside a system-managed VPN provider.
pub async fn run_with_system_managed_network<D>(
    device: D,
    mtu: u16,
    args: Args,
    shutdown_token: CancellationToken,
    virtual_dns_state: Option<VirtualDnsState>,
) -> crate::Result<usize>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if args.setup || !args.bypass_process.is_empty() || args.bind_interface.is_some() {
        return Err("system-managed packet tunnels cannot configure routes, bind an interface or match processes".into());
    }
    run_with_preselected_egress(
        device,
        mtu,
        args,
        shutdown_token,
        ProcessBypass::new(Vec::new()),
        virtual_dns_state,
        NetworkEnvironment::Provider,
    )
    .await
}

enum NetworkEnvironment {
    Physical(Option<DirectBind>),
    Provider,
}

async fn run_with_preselected_egress<D>(
    device: D,
    mtu: u16,
    args: Args,
    shutdown_token: CancellationToken,
    process_bypass: ProcessBypass,
    virtual_dns_state: Option<VirtualDnsState>,
    network_environment: NetworkEnvironment,
) -> crate::Result<usize>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    log::info!("{} {} starting...", env!("CARGO_PKG_NAME"), version_info!());
    log::info!("Proxy {} server: {}", args.proxy.proxy_type, args.proxy.addr);

    let server_addr = args.proxy.addr;
    let key = args.proxy.credentials.clone();
    let dns_addr = args.dns_addr;
    let ipv6_enabled = args.ipv6_enabled;
    let udp_strategy = args.udp_strategy;
    let virtual_dns_portals = Arc::new(args.virtual_dns_portals.clone());
    // Keep every task created by this forwarding instance under one owner.
    // Dropping a bare tokio JoinHandle detaches its task, which previously let
    // old TCP/UDP sessions survive a TUN stop or hot switch. JoinSet aborts all
    // remaining children on drop and also lets normal shutdown await their
    // cancellation before route and DNS teardown begins.
    let mut managed_tasks = tokio::task::JoinSet::new();
    // Keep reverse mappings when Fake-IP is disabled: applications can retain
    // previous DNS answers across an upgrade or a change of DNS mode. Only the
    // Virtual branches below allocate new fake addresses.
    let virtual_dns = virtual_dns_state
        .map(|state| state.resolver())
        .or_else(|| (args.dns == ArgDns::Virtual).then(|| Arc::new(Mutex::new(VirtualDns::new(args.virtual_dns_pool)))));

    use socks5_impl::protocol::Version::{V4, V5};
    let mgr: Arc<dyn ProxyHandlerManager> = match args.proxy.proxy_type {
        ProxyType::Socks5 => Arc::new(SocksProxyManager::new(server_addr, V5, key)),
        ProxyType::Socks4 => Arc::new(SocksProxyManager::new(server_addr, V4, key)),
        ProxyType::Http => Arc::new(HttpManager::new(server_addr, key)),
        ProxyType::None => Arc::new(NoProxyManager::new()),
    };

    // Process-based bypass: sessions whose originating local process matches
    // `--bypass-process` are relayed directly to their destination through the
    // physical interface instead of being forwarded to the proxy.
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    let process_matcher = match &network_environment {
        NetworkEnvironment::Physical(_) => process::ProcessMatcher::new(process_bypass.clone()).map(Arc::new),
        NetworkEnvironment::Provider => None,
    };
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    // Local multicast cannot be meaningfully forwarded through an Internet
    // proxy. Keep a physical egress available even when no process bypass or
    // global UDP-direct policy was configured, so discovery traffic never
    // recurses through the TUN.
    let direct_bind = match network_environment {
        NetworkEnvironment::Provider => None,
        NetworkEnvironment::Physical(preselected_egress) => {
            // Keep the whole pre-setup snapshot. Looking up the same name again
            // after setup reads our virtual resolver as the physical DNS server.
            let iface = match preselected_egress {
                Some(iface) => iface,
                None => Arc::new(direct::detect(args.bind_interface.as_deref(), args.tun.as_deref())?),
            };
            log::info!("Direct relays and local multicast egress via {iface}");
            Some(iface)
        }
    };
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    let direct_bind: Option<DirectBind> = match network_environment {
        NetworkEnvironment::Physical(egress) => egress,
        NetworkEnvironment::Provider => None,
    };
    // Windows can replace interface indices and DHCP DNS settings on reconnect.
    // Refresh off the forwarding executor; existing streams retain their bind.
    #[cfg(target_os = "windows")]
    let egress_updates = direct_bind.as_ref().map(|initial| {
        let (updates, current) = tokio::sync::watch::channel(Arc::clone(initial));
        let manual = args.bind_interface.clone();
        let tun = args.tun.clone();
        managed_tasks.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let manual = manual.clone();
                let tun = tun.clone();
                match tokio::task::spawn_blocking(move || direct::detect(manual.as_deref(), tun.as_deref())).await {
                    Ok(Ok(next)) => {
                        if **updates.borrow() != next {
                            log::info!("Physical egress changed; new direct sessions will use {next}");
                            updates.send_replace(Arc::new(next));
                        }
                    }
                    Ok(Err(error)) => log::debug!("Physical egress unavailable; retaining last known interface: {error}"),
                    Err(error) => log::warn!("Physical egress lookup failed: {error}"),
                }
            }
        });
        current
    });
    let no_proxy_mgr: Arc<dyn ProxyHandlerManager> = Arc::new(NoProxyManager::new());
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    if process_bypass.is_configured() {
        log::info!("Process bypass enabled for {:?}", process_bypass.names());
    }
    if udp_strategy == ArgUdpStrategy::Direct {
        log::warn!("Non-DNS UDP direct fallback enabled; UDP traffic will bypass the proxy");
    } else if udp_strategy == ArgUdpStrategy::Block {
        log::warn!("Non-DNS UDP is blocked by policy");
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    if process_bypass.is_configured() {
        log::warn!("--bypass-process is not supported on this platform; ignoring it");
    }

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(mtu)?;
    let mut tcp_cfg = ipstack::TcpConfig::default();
    tcp_cfg.timeout = std::time::Duration::from_secs(args.tcp_timeout);
    if args.tcp_read_buffer_size > 0 {
        tcp_cfg.read_buffer_size = args.tcp_read_buffer_size;
    }
    ipstack_config.with_tcp_config(tcp_cfg);
    ipstack_config.udp_timeout(std::time::Duration::from_secs(args.udp_timeout));

    let mut ip_stack = ipstack::IpStack::new(ipstack_config, device);
    let mut echo_flows = icmp::EchoFlows::new(&args, mtu)?;

    // Delay spawning socket-transfer producers until all fallible forwarding
    // initialization above has succeeded. From this point onward every return
    // path goes through the common JoinSet drain below.
    #[cfg(target_os = "linux")]
    let socket_queue = match args.socket_transfer_fd {
        None => None,
        Some(fd) => {
            use crate::socket_transfer::{reconstruct_socket, reconstruct_transfer_socket, request_sockets};
            use tokio::sync::mpsc::channel;

            let fd = reconstruct_socket(fd)?;
            let socket = reconstruct_transfer_socket(fd)?;
            let socket = Arc::new(Mutex::new(socket));

            macro_rules! create_socket_queue {
                ($domain:ident) => {{
                    const SOCKETS_PER_REQUEST: usize = 64;

                    let socket = socket.clone();
                    let (tx, rx) = channel(SOCKETS_PER_REQUEST);
                    managed_tasks.spawn(async move {
                        loop {
                            let sockets =
                                match request_sockets(socket.lock().await, SocketDomain::$domain, SOCKETS_PER_REQUEST as u32).await {
                                    Ok(sockets) => sockets,
                                    Err(err) => {
                                        log::warn!("Socket allocation request failed: {err}");
                                        continue;
                                    }
                                };
                            for s in sockets {
                                if tx.send(s).await.is_err() {
                                    return;
                                }
                            }
                        }
                    });
                    Mutex::new(rx)
                }};
            }

            Some(Arc::new(SocketQueue {
                tcp_v4: create_socket_queue!(IpV4),
                tcp_v6: create_socket_queue!(IpV6),
                udp_v4: create_socket_queue!(IpV4),
                udp_v6: create_socket_queue!(IpV6),
            }))
        }
    };

    #[cfg(not(target_os = "linux"))]
    let socket_queue = None;

    #[cfg(feature = "udpgw")]
    let udpgw_client = args.udpgw_server.map(|addr| {
        log::info!("UDP Gateway enabled, server: {addr}");
        use std::time::Duration;
        let client = Arc::new(UdpGwClient::new(
            mtu,
            args.udpgw_connections.unwrap_or(UDPGW_MAX_CONNECTIONS),
            args.udpgw_keepalive.map(Duration::from_secs).unwrap_or(UDPGW_KEEPALIVE_TIME),
            args.udp_timeout,
            addr,
        ));
        let client_keepalive = client.clone();
        let shutdown_clone = shutdown_token.clone();
        managed_tasks.spawn(async move {
            if let Err(err) = client_keepalive.heartbeat_task(shutdown_clone).await {
                log::error!("UDP Gateway heartbeat task error: {err}");
            }
        });
        client
    });

    let session_counts = Arc::new(SessionCounts::default());

    // Concurrent sessions are the term that multiplies every per-session buffer,
    // and `tcp_timeout` keeps idle ones alive for minutes. Without a periodic
    // reading there is no way to tell a busy device from a memory problem, since
    // the existing counters only surface at trace level or when the cap is hit.
    managed_tasks.spawn({
        let session_counts = Arc::clone(&session_counts);
        let shutdown_token = shutdown_token.clone();
        let max_sessions = args.max_sessions;
        async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = shutdown_token.cancelled() => break,
                    _ = ticker.tick() => {
                        let snapshot = session_counts.snapshot();
                        log::info!(
                            "TUN sessions: total={}/{}, TCP={}, UDP={}",
                            snapshot.total,
                            max_sessions,
                            snapshot.tcp,
                            snapshot.udp
                        );
                    }
                }
            }
        }
    });

    let forwarding_result: crate::Result<()> = loop {
        // JoinSet keeps completed task outputs until they are observed. Reap
        // them continuously so a long-lived TUN with many short connections
        // does not accumulate completed task records.
        while let Some(result) = managed_tasks.try_join_next() {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                log::error!("Managed TUN child task failed: {error}");
            }
        }

        let session_counts = session_counts.clone();
        let virtual_dns = virtual_dns.clone();
        let ip_stack_stream = tokio::select! {
            _ = shutdown_token.cancelled() => {
                log::info!("Shutdown received");
                break Ok(());
            }
            ip_stack_stream = ip_stack.accept() => {
                match ip_stack_stream {
                    Ok(stream) => stream,
                    Err(error) => break Err(error.into()),
                }
            }
        };
        let max_sessions = args.max_sessions;
        match ip_stack_stream {
            IpStackStream::Tcp(mut tcp) => {
                let Some(session_permit) = session_counts.try_acquire(IpProtocol::Tcp, max_sessions) else {
                    let _ = tcp.abort();
                    if args.exit_on_fatal_error {
                        log::info!("Too many sessions that over {max_sessions}, exiting...");
                        break Ok(());
                    }
                    log_session_limit(IpProtocol::Tcp, max_sessions, &session_counts);
                    continue;
                };
                let info = SessionInfo::new(tcp.local_addr(), tcp.peer_addr(), IpProtocol::Tcp);
                let mgr = mgr.clone();
                let socket_queue = socket_queue.clone();
                let dns = args.dns;
                let virtual_dns_portals = virtual_dns_portals.clone();
                #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                let process_matcher = process_matcher.clone();
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                let direct_bind = direct_bind.clone();
                #[cfg(target_os = "windows")]
                let direct_bind = egress_updates.as_ref().map(|updates| Arc::clone(&updates.borrow()));
                #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                let no_proxy_mgr = no_proxy_mgr.clone();
                // The source-process lookup may briefly touch the OS, so the
                // bypass decision and handler creation run inside the per-session
                // task rather than on the accept loop.
                managed_tasks.spawn(async move {
                    let _session_permit = session_permit;
                    let mut tcp = tcp;
                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    let policy = match &process_matcher {
                        Some(matcher) => Some(matcher.match_session(IpProtocol::Tcp, info.src, info.dst).await),
                        None => None,
                    };
                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    let bypass = policy.as_ref().is_some_and(process::SessionPolicy::bypass);
                    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                    let bypass = false;

                    // Windows and platform VPNs advertise a private DNS portal.
                    // TCP fallback must use the same upstream resolver as UDP
                    // DNS; connecting the portal through SOCKS would loop/fail.
                    let mut info = info;
                    if !bypass && dns == ArgDns::OverTcp && info.dst.port() == DNS_PORT && is_private_ip(info.dst.ip()) {
                        info.dst.set_ip(dns_addr);
                    }

                    if !bypass && dns == ArgDns::Virtual && info.dst.port() == DNS_PORT {
                        let relay = async {
                            match virtual_dns.clone() {
                                Some(virtual_dns) => handle_virtual_dns_tcp_session(&mut tcp, virtual_dns).await,
                                None => Err("virtual DNS manager is unavailable".into()),
                            }
                        };
                        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                        let result = run_until_process_policy_change(relay, policy).await;
                        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                        let result = Some(relay.await);
                        if result.is_none() {
                            reset_tcp_after_policy_change(&mut tcp, info);
                        }
                        if let Some(Err(error)) = result {
                            log::debug!("{info} virtual DNS TCP session ended: {error}");
                        }
                        return;
                    }

                    if !bypass && is_virtual_dns_tls_probe(dns, &virtual_dns_portals, info.dst) {
                        log::debug!("Rejecting opportunistic DNS-over-TLS probe to virtual DNS portal {}", info.dst);
                        let mut tcp = tcp;
                        if let Err(error) = tcp.shutdown().await {
                            log::debug!("{info} failed to close virtual DNS TLS probe: {error}");
                        }
                        return;
                    }

                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    let (handler_result, bind): (HandlerResult, Option<DirectBind>) = {
                        let mut info = info;
                        let dns_destination = if bypass && info.dst.port() == DNS_PORT && is_private_ip(info.dst.ip()) {
                            direct_bind
                                .as_deref()
                                .and_then(|bind| direct::preferred_dns_server(dns_addr, bind))
                                .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no usable physical DNS resolver"))
                                .map(Some)
                        } else {
                            Ok(None)
                        };
                        let bypass_destination = match dns_destination {
                            Ok(Some(resolver)) => {
                                info.dst.set_ip(resolver);
                                restore_bypass_destination(&mut info, virtual_dns.as_ref(), dns_addr, direct_bind.as_ref()).await
                            }
                            Ok(None) if bypass => {
                                restore_bypass_destination(&mut info, virtual_dns.as_ref(), dns_addr, direct_bind.as_ref()).await
                            }
                            Ok(None) => Ok(()),
                            Err(error) => Err(error),
                        };
                        let domain_name = resolve_virtual_domain(virtual_dns.as_ref(), info.dst.ip()).await;
                        match (bypass_destination, domain_name, bypass) {
                            (Err(error), _, _) | (_, Err(error), _) => (Err(error), direct_bind.clone()),
                            (Ok(()), Ok(domain_name), true) => {
                                (no_proxy_mgr.new_proxy_handler(info, domain_name, false).await, direct_bind.clone())
                            }
                            (Ok(()), Ok(domain_name), false) => (mgr.new_proxy_handler(info, domain_name, false).await, None),
                        }
                    };
                    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                    let (handler_result, bind): (HandlerResult, Option<DirectBind>) = {
                        let handler_result = match resolve_virtual_domain(virtual_dns.as_ref(), info.dst.ip()).await {
                            Ok(domain_name) => mgr.new_proxy_handler(info, domain_name, false).await,
                            Err(error) => Err(error),
                        };
                        (handler_result, None)
                    };

                    let filter_dns_ipv6 = !bypass && dns == ArgDns::OverTcp && info.dst.port() == DNS_PORT && !ipv6_enabled;
                    match handler_result {
                        Ok(proxy_handler) => {
                            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                            let result = run_until_process_policy_change(
                                handle_tcp_session(&mut tcp, proxy_handler, socket_queue, bind, filter_dns_ipv6),
                                policy,
                            )
                            .await;
                            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                            let result = Some(handle_tcp_session(&mut tcp, proxy_handler, socket_queue, bind, filter_dns_ipv6).await);

                            if result.is_none() {
                                reset_tcp_after_policy_change(&mut tcp, info);
                            }

                            if let Some(Err(err)) = result {
                                let _ = tcp.abort();
                                log::error!("{info} error \"{err}\"");
                            }
                        }
                        Err(err) => {
                            let _ = tcp.abort();
                            log::error!("{info} failed to create proxy handler: {err}");
                        }
                    }
                });
            }
            IpStackStream::Udp(udp) => {
                let Some(session_permit) = session_counts.try_acquire(IpProtocol::Udp, max_sessions) else {
                    if args.exit_on_fatal_error {
                        log::info!("Too many sessions that over {max_sessions}, exiting...");
                        break Ok(());
                    }
                    log_session_limit(IpProtocol::Udp, max_sessions, &session_counts);
                    continue;
                };
                let mgr = mgr.clone();
                let socket_queue = socket_queue.clone();
                let proxy_type = args.proxy.proxy_type;
                let dns = args.dns;
                let udp_strategy = args.udp_strategy;
                #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                let process_matcher = process_matcher.clone();
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                let direct_bind = direct_bind.clone();
                #[cfg(target_os = "windows")]
                let direct_bind = egress_updates.as_ref().map(|updates| Arc::clone(&updates.borrow()));
                let no_proxy_mgr = no_proxy_mgr.clone();
                #[cfg(feature = "udpgw")]
                let udpgw_client = udpgw_client.clone();
                let udp_setup_timeout = Duration::from_secs(args.udp_timeout.max(1));
                managed_tasks.spawn(async move {
                    let _session_permit = session_permit;
                    let mut info = SessionInfo::new(udp.local_addr(), udp.peer_addr(), IpProtocol::Udp);
                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    let local_multicast = is_local_multicast_destination(info.dst.ip());
                    // Decide process bypass before DNS or UdpGW handling. A
                    // bypassed process must see real DNS answers and raw UDP;
                    // otherwise its own traffic can recurse through the local
                    // proxy or attempt to connect to a virtual-DNS fake IP.
                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    let policy = if local_multicast {
                        None
                    } else {
                        match &process_matcher {
                            Some(matcher) => Some(matcher.match_session(IpProtocol::Udp, info.src, info.dst).await),
                            None => None,
                        }
                    };
                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    let bypass = local_multicast || policy.as_ref().is_some_and(process::SessionPolicy::bypass);
                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    if local_multicast {
                        log::debug!(
                            "Relaying local multicast UDP {} -> {} through the physical interface",
                            info.src,
                            info.dst
                        );
                    }

                    let relay = async {
                        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                        if bypass {
                            if info.dst.port() == DNS_PORT && is_private_ip(info.dst.ip()) {
                                let resolver = direct_bind
                                    .as_deref()
                                    .and_then(|bind| direct::preferred_dns_server(dns_addr, bind))
                                    .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no usable physical DNS resolver"))?;
                                info.dst.set_ip(resolver);
                            }
                            restore_bypass_destination(&mut info, virtual_dns.as_ref(), dns_addr, direct_bind.as_ref()).await?;
                            let proxy_handler = no_proxy_mgr.new_proxy_handler(info, None, true).await?;
                            return handle_udp_associate_session(
                                udp,
                                ProxyType::None,
                                proxy_handler,
                                socket_queue,
                                ipv6_enabled,
                                direct_bind,
                                udp_setup_timeout,
                            )
                            .await;
                        }

                        if info.dst.port() == DNS_PORT {
                            if is_private_ip(info.dst.ip()) {
                                info.dst.set_ip(dns_addr);
                            }
                            if dns == ArgDns::OverTcp {
                                info.protocol = IpProtocol::Tcp;
                                let proxy_handler = mgr.new_proxy_handler(info, None, false).await?;
                                return handle_dns_over_tcp_session(udp, proxy_handler, socket_queue, ipv6_enabled).await;
                            }
                            if dns == ArgDns::Virtual {
                                let virtual_dns = virtual_dns.ok_or("virtual DNS manager is unavailable")?;
                                return handle_virtual_dns_session(udp, virtual_dns).await;
                            }
                            assert_eq!(dns, ArgDns::Direct);
                        }

                        if udp_strategy == ArgUdpStrategy::Block {
                            return Err(format!("non-DNS UDP blocked by policy for {}", info.dst).into());
                        }

                        let domain_name = resolve_virtual_domain(virtual_dns.as_ref(), info.dst.ip()).await?;

                        if udp_strategy == ArgUdpStrategy::Direct {
                            let dns_bind = if proxy_type == ProxyType::None {
                                direct_bind.as_ref()
                            } else {
                                None
                            };
                            restore_direct_udp_destination(&mut info, domain_name.as_deref(), dns_addr, &mgr, &socket_queue, dns_bind)
                                .await?;
                            let proxy_handler = no_proxy_mgr.new_proxy_handler(info, None, true).await?;
                            return handle_udp_associate_session(
                                udp,
                                ProxyType::None,
                                proxy_handler,
                                socket_queue,
                                ipv6_enabled,
                                direct_bind,
                                udp_setup_timeout,
                            )
                            .await;
                        }

                        #[cfg(feature = "udpgw")]
                        if let Some(udpgw) = udpgw_client {
                            let tcp_src = match info.dst {
                                SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                                SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
                            };
                            let tcpinfo = SessionInfo::new(tcp_src, udpgw.get_udpgw_server_addr(), IpProtocol::Tcp);
                            let proxy_handler = mgr.new_proxy_handler(tcpinfo, None, false).await?;
                            let dst_addr = match domain_name {
                                Some(ref domain) => socks5_impl::protocol::Address::from((domain.to_string(), info.dst.port())),
                                None => info.dst.into(),
                            };
                            return handle_udp_gateway_session(udp, udpgw, &dst_addr, proxy_handler, socket_queue, ipv6_enabled).await;
                        }

                        let proxy_handler = mgr.new_proxy_handler(info, domain_name, true).await?;
                        handle_udp_associate_session(udp, proxy_type, proxy_handler, socket_queue, ipv6_enabled, None, udp_setup_timeout)
                            .await
                    };

                    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
                    let result = run_until_process_policy_change(relay, policy).await;
                    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                    let result = Some(relay.await);

                    if let Some(Err(err)) = result {
                        log::debug!("Ending {info} with \"{err}\"");
                    }
                });
            }
            IpStackStream::UnknownTransport(u) => {
                if let Some(flows) = echo_flows.as_mut()
                    && flows.is_echo(&u)
                {
                    let destination = resolve_virtual_domain(virtual_dns.as_ref(), u.dst_addr()).await;
                    match destination {
                        Ok(domain) => flows.dispatch(u, domain, &mut managed_tasks),
                        Err(error) => log::debug!("Cannot resolve ICMP Echo destination: {error}"),
                    }
                    continue;
                }
                log_unknown_transport(&u);
                continue;
            }
            IpStackStream::UnknownNetwork(pkt) => {
                log::info!("#0 unknown transport - {} bytes", pkt.len());
                continue;
            }
        }
    };
    let active_sessions = session_counts.snapshot().total;
    if !managed_tasks.is_empty() {
        log::debug!("Stopping {} managed TUN child task(s) before network teardown", managed_tasks.len());
        managed_tasks.abort_all();
        while let Some(result) = managed_tasks.join_next().await {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                log::error!("Managed TUN child task failed during shutdown: {error}");
            }
        }
    }
    forwarding_result?;
    Ok(active_sessions)
}

#[cfg(all(test, any(target_os = "windows", target_os = "linux", target_os = "macos")))]
#[tokio::test]
async fn forwarding_keeps_pre_setup_egress_instead_of_rereading_system_dns() {
    let (_, device) = tokio::io::duplex(4096);
    let token = CancellationToken::new();
    token.cancel();
    // Re-querying this intentionally nonexistent device would fail. The
    // complete pre-setup snapshot must reach the forwarding loop unchanged.
    let name = "test-physical-dns-snapshot".to_owned();
    let egress = Arc::new(direct::BindInterface {
        name: name.clone(),
        ipv4_index: 1,
        ipv6_index: 1,
        ipv4_addr: Some("192.0.2.2".parse().unwrap()),
        dns_servers: vec!["192.0.2.1".parse().unwrap()],
    });
    let args = Args {
        bind_interface: Some(name),
        dns: ArgDns::Virtual,
        ..Args::default()
    };
    let result = run_with_preselected_egress(
        device,
        DEFAULT_MTU,
        args,
        token,
        ProcessBypass::new(Vec::new()),
        None,
        NetworkEnvironment::Physical(Some(egress)),
    )
    .await;
    assert_eq!(result.unwrap(), 0);
}

#[cfg(test)]
#[tokio::test]
async fn system_managed_provider_rejects_os_setup_and_process_matching() {
    for args in [
        Args {
            setup: true,
            ..Args::default()
        },
        Args {
            setup: false,
            bypass_process: vec!["example".into()],
            ..Args::default()
        },
        Args {
            setup: false,
            bind_interface: Some("invalid-interface".into()),
            ..Args::default()
        },
    ] {
        let (_, device) = tokio::io::duplex(4096);
        let error = run_with_system_managed_network(device, DEFAULT_MTU, args, CancellationToken::new(), None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("system-managed packet tunnels cannot"));
    }
    let (_host, device) = tokio::io::duplex(4096);
    let token = CancellationToken::new();
    token.cancel();
    assert_eq!(
        run_with_system_managed_network(
            device,
            DEFAULT_MTU,
            Args {
                setup: false,
                ..Args::default()
            },
            token,
            None
        )
        .await
        .unwrap(),
        0
    );
}

async fn handle_virtual_dns_session(mut udp: IpStackUdpStream, dns: Arc<Mutex<VirtualDns>>) -> crate::Result<()> {
    let mut buf = [0_u8; 4096];
    loop {
        let len = match udp.read(&mut buf).await {
            Err(e) => {
                // indicate UDP read fails not an error.
                log::debug!("Virtual DNS session error: {e}");
                break;
            }
            Ok(len) => len,
        };
        if len == 0 {
            break;
        }
        let (msg, qname, ip) = dns.lock().await.generate_query(&buf[..len])?;
        udp.write_all(&msg).await?;
        log::debug!("Virtual DNS query: {qname} -> {ip:?}");
    }
    Ok(())
}

fn is_virtual_dns_tls_probe(dns: ArgDns, portals: &[IpAddr], destination: SocketAddr) -> bool {
    dns != ArgDns::Direct && destination.port() == DNS_OVER_TLS_PORT && portals.contains(&destination.ip())
}

async fn handle_virtual_dns_tcp_session<S>(mut tcp: S, dns: Arc<Mutex<VirtualDns>>) -> crate::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let query_len = match tcp.read_u16().await {
            Ok(query_len) => usize::from(query_len),
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.into()),
        };
        if query_len == 0 {
            return Err("empty DNS-over-TCP query".into());
        }

        let mut query = vec![0_u8; query_len];
        tcp.read_exact(&mut query).await?;
        let (response, qname, ip) = dns.lock().await.generate_query(&query)?;
        let response_len = u16::try_from(response.len()).map_err(|_| "virtual DNS response exceeds TCP framing limit")?;
        tcp.write_u16(response_len).await?;
        tcp.write_all(&response).await?;
        log::debug!("Virtual DNS TCP query: {qname} -> {ip:?}");
    }
    Ok(())
}

async fn copy_and_record_traffic<R, W>(reader: &mut R, writer: &mut W, is_tx: bool) -> tokio::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0; 8192];
    let mut total = 0;
    loop {
        match reader.read(&mut buf).await? {
            0 => break, // EOF
            n => {
                total += n as u64;
                let (tx, rx) = if is_tx { (n, 0) } else { (0, n) };
                if let Err(e) = crate::traffic_status::traffic_status_update(tx, rx) {
                    log::debug!("Record traffic status error: {e}");
                }
                writer.write_all(&buf[..n]).await?;
            }
        }
    }
    Ok(total)
}

fn reset_tcp_after_policy_change(tcp: &mut IpStackTcpStream, info: SessionInfo) {
    log::info!("{info} process bypass decision changed; resetting the connection for reconnection");
    if let Err(error) = tcp.abort() {
        log::warn!("{info} could not send the policy-change TCP reset: {error}");
    }
}

async fn handle_tcp_session(
    tcp_stack: &mut (impl AsyncRead + AsyncWrite + Unpin),
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    bind: Option<DirectBind>,
    filter_dns_ipv6: bool,
) -> crate::Result<()> {
    let (session_info, server_addr) = {
        let handler = proxy_handler.lock().await;

        (handler.get_session_info(), handler.get_server_addr())
    };

    // For a process-bypass session `server_addr` is the original destination and
    // `bind` pins the egress to the physical interface; otherwise it is the proxy
    // and `bind` is `None` (normal routing).
    let (server, prefetched) = tokio::time::timeout(Duration::from_secs(10), async {
        let mut server = create_tcp_stream(&socket_queue, server_addr, bind.as_ref()).await?;
        handle_proxy_session(&mut server, proxy_handler.clone()).await?;
        // The last handshake read can also contain server-first application
        // data. Preserve it before switching from the parser to raw TCP reads.
        let mut handler = proxy_handler.lock().await;
        let prefetched = handler.peek_data(OutgoingDirection::ToClient).buffer.to_vec();
        handler.consume_data(OutgoingDirection::ToClient, prefetched.len());
        Ok::<_, Error>((server, prefetched))
    })
    .await
    .map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "TUN TCP setup exceeded 10 seconds"))??;

    log::debug!("Beginning {session_info}");

    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    // EOF still half-closes the opposite writer. An error must cancel the
    // other pump instead of retaining a dead session until the idle timeout.
    let res = tokio::try_join!(
        async move {
            let copied = copy_and_record_traffic(&mut t_rx, &mut s_tx, true).await?;
            if let Err(err) = s_tx.shutdown().await {
                log::trace!("{session_info} s_tx shutdown error {err}");
            }
            Ok::<_, std::io::Error>(copied)
        },
        async move {
            // These bytes were already counted by the handshake reader.
            let copied = if filter_dns_ipv6 {
                copy_ipv4_dns_responses(&mut s_rx, &mut t_tx, prefetched).await?
            } else {
                t_tx.write_all(&prefetched).await?;
                copy_and_record_traffic(&mut s_rx, &mut t_tx, false).await?
            };
            if let Err(err) = t_tx.shutdown().await {
                log::trace!("{session_info} t_tx shutdown error {err}");
            }
            Ok::<_, std::io::Error>(copied)
        },
    );
    log::debug!("Ending {session_info} with {res:?}");

    res?;
    Ok(())
}

// DNS over TCP can fragment or pipeline frames, including data prefetched by
// the proxy handshake. Never emit a partial unfiltered reply to an IPv4 TUN.
async fn copy_ipv4_dns_responses(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    mut pending: Vec<u8>,
) -> std::io::Result<u64> {
    let mut total = 0;
    let mut buffer = [0; 4096];
    loop {
        for mut message in dns::drain_tcp_messages(&mut pending).map_err(std::io::Error::other)? {
            dns::remove_ipv6_entries(&mut message);
            let packet = message.to_vec().map_err(std::io::Error::other)?;
            let length = u16::try_from(packet.len()).map_err(std::io::Error::other)?;
            writer.write_u16(length).await?;
            writer.write_all(&packet).await?;
        }
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return if pending.is_empty() {
                Ok(total)
            } else {
                Err(std::io::Error::new(ErrorKind::UnexpectedEof, "incomplete DNS-over-TCP response"))
            };
        }
        total += count as u64;
        let _ = crate::traffic_status::traffic_status_update(0, count);
        pending.extend_from_slice(&buffer[..count]);
    }
}

#[cfg(feature = "udpgw")]
async fn handle_udp_gateway_session(
    mut udp_stack: IpStackUdpStream,
    udpgw_client: Arc<UdpGwClient>,
    udp_dst: &socks5_impl::protocol::Address,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    let proxy_server_addr = { proxy_handler.lock().await.get_server_addr() };
    let udp_mtu = udpgw_client.get_udp_mtu();
    let udp_timeout = udpgw_client.get_udp_timeout();

    let mut stream = loop {
        match udpgw_client.pop_server_connection_from_queue().await {
            Some(stream) => {
                if stream.is_closed() {
                    continue;
                } else {
                    break stream;
                }
            }
            None => {
                let mut tcp_server_stream = create_tcp_stream(&socket_queue, proxy_server_addr, None).await?;
                if let Err(e) = handle_proxy_session(&mut tcp_server_stream, proxy_handler).await {
                    return Err(format!("udpgw connection error: {e}").into());
                }
                break UdpGwClientStream::new(tcp_server_stream);
            }
        }
    };

    let tcp_local_addr = stream.local_addr();
    let sn = stream.serial_number();

    log::debug!("[UdpGw] Beginning stream {} {} -> {}", sn, &tcp_local_addr, udp_dst);

    let Some(mut reader) = stream.get_reader() else {
        return Err("get reader failed".into());
    };

    let Some(mut writer) = stream.get_writer() else {
        return Err("get writer failed".into());
    };

    let mut tmp_buf = vec![0; udp_mtu.into()];

    loop {
        tokio::select! {
            len = udp_stack.read(&mut tmp_buf) => {
                let read_len = match len {
                    Ok(0) => {
                        log::debug!("[UdpGw] Ending stream {} {} <> {}", sn, &tcp_local_addr, udp_dst);
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        log::debug!("[UdpGw] Ending stream {} {} <> {} with udp stack \"{}\"", sn, &tcp_local_addr, udp_dst, e);
                        break;
                    }
                };
                crate::traffic_status::traffic_status_update(read_len, 0)?;
                let sn = stream.serial_number();
                if let Err(e) = UdpGwClient::send_udpgw_packet(ipv6_enabled, &tmp_buf[0..read_len], udp_dst, sn, &mut writer).await {
                    log::debug!("[UdpGw] Ending stream {} {} <> {} with send_udpgw_packet {}", sn, &tcp_local_addr, udp_dst, e);
                    break;
                }
                log::debug!("[UdpGw] stream {} {} -> {} send len {}", sn, &tcp_local_addr, udp_dst, read_len);
                stream.update_activity();
            }
            ret = UdpGwClient::recv_udpgw_packet(udp_mtu, udp_timeout, &mut reader) => {
                if let Ok((len, _)) = ret {
                    crate::traffic_status::traffic_status_update(0, len)?;
                }
                match ret {
                    Err(e) => {
                        log::warn!("[UdpGw] Ending stream {} {} <> {} with recv_udpgw_packet {}", sn, &tcp_local_addr, udp_dst, e);
                        stream.close();
                        break;
                    }
                    Ok((_, packet)) => match packet {
                        //should not received keepalive
                        UdpGwResponse::KeepAlive => {
                            log::error!("[UdpGw] Ending stream {} {} <> {} with recv keepalive", sn, &tcp_local_addr, udp_dst);
                            stream.close();
                            break;
                        }
                        //server udp may be timeout,can continue to receive udp data?
                        UdpGwResponse::Error => {
                            log::debug!("[UdpGw] Ending stream {} {} <> {} with recv udp error", sn, &tcp_local_addr, udp_dst);
                            stream.update_activity();
                            continue;
                        }
                        UdpGwResponse::TcpClose => {
                            log::error!("[UdpGw] Ending stream {} {} <> {} with tcp closed", sn, &tcp_local_addr, udp_dst);
                            stream.close();
                            break;
                        }
                        UdpGwResponse::Data(data) => {
                            use socks5_impl::protocol::StreamOperation;
                            let len = data.len();
                            let f = data.header.flags;
                            log::debug!("[UdpGw] stream {sn} {} <- {} receive {f} len {len}", &tcp_local_addr, udp_dst);
                            if let Err(e) = udp_stack.write_all(&data.data).await {
                                log::error!("[UdpGw] Ending stream {} {} <> {} with send_udp_packet {}", sn, &tcp_local_addr, udp_dst, e);
                                break;
                            }
                        }
                    }
                }
                stream.update_activity();
            }
        }
    }

    if !stream.is_closed() {
        udpgw_client.store_server_connection_full(stream, reader, writer).await;
    }

    Ok(())
}

async fn handle_udp_associate_session(
    mut udp_stack: IpStackUdpStream,
    proxy_type: ProxyType,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6_enabled: bool,
    bind: Option<DirectBind>,
    setup_timeout: Duration,
) -> crate::Result<()> {
    use socks5_impl::protocol::{Address, StreamOperation, UdpHeader};

    let (session_info, server_addr, domain_name, udp_addr) = {
        let handler = proxy_handler.lock().await;
        (
            handler.get_session_info(),
            handler.get_server_addr(),
            handler.get_domain_name(),
            handler.get_udp_associate(),
        )
    };

    log::debug!("Beginning {session_info}");

    let setup = async {
        // `_server` is meaningful here, it must be alive all the time
        // to ensure that UDP transmission will not be interrupted accidentally.
        // The bypass path always reports a udp-associate address (its destination),
        // so the proxy-handshake branch below is only taken for real proxies, where
        // `bind` is `None`.
        let (server, udp_addr) = match udp_addr {
            Some(udp_addr) => (None, udp_addr),
            None => {
                let mut server = create_tcp_stream(&socket_queue, server_addr, None).await?;
                let udp_addr = handle_proxy_session(&mut server, proxy_handler).await?;
                (Some(server), udp_addr.ok_or("udp associate failed")?)
            }
        };
        let udp_server = create_udp_stream(&socket_queue, udp_addr, bind.as_ref()).await?;
        Ok::<_, Error>((server, udp_server))
    };
    let (_server, mut udp_server) = tokio::time::timeout(setup_timeout, setup)
        .await
        .map_err(|_| Error::from(format!("{session_info} UDP association setup timed out after {setup_timeout:?}")))??;

    let mut buf1 = [0_u8; 4096];
    let mut buf2 = [0_u8; 4096];
    loop {
        tokio::select! {
            len = udp_stack.read(&mut buf1) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf1 = &buf1[..len];

                crate::traffic_status::traffic_status_update(len, 0)?;

                if let ProxyType::Socks4 | ProxyType::Socks5 = proxy_type {
                    let s5addr = if let Some(domain_name) = &domain_name {
                        Address::DomainAddress(domain_name.to_string().into(), session_info.dst.port())
                    } else {
                        session_info.dst.into()
                    };

                    // Add SOCKS5 UDP header to the incoming data
                    let mut s5_udp_data = Vec::<u8>::new();
                    UdpHeader::new(0, s5addr).write_to_stream(&mut s5_udp_data)?;
                    s5_udp_data.extend_from_slice(buf1);

                    udp_server.write_all(&s5_udp_data).await?;
                } else {
                    udp_server.write_all(buf1).await?;
                }
            }
            len = udp_server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf2 = &buf2[..len];

                crate::traffic_status::traffic_status_update(0, len)?;

                if let ProxyType::Socks4 | ProxyType::Socks5 = proxy_type {
                    // Remove SOCKS5 UDP header from the server data
                    let header = UdpHeader::retrieve_from_stream(&mut &buf2[..])?;
                    let data = &buf2[header.len()..];

                    let buf = if session_info.dst.port() == DNS_PORT {
                        let mut message = dns::parse_data_to_dns_message(data, false)?;
                        if !ipv6_enabled {
                            dns::remove_ipv6_entries(&mut message);
                        }
                        message.to_vec()?
                    } else {
                        data.to_vec()
                    };

                    udp_stack.write_all(&buf).await?;
                } else {
                    udp_stack.write_all(buf2).await?;
                }
            }
        }
    }

    log::debug!("Ending {session_info}");

    Ok(())
}

async fn handle_dns_over_tcp_session(
    mut udp_stack: IpStackUdpStream,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    ipv6_enabled: bool,
) -> crate::Result<()> {
    let (session_info, server_addr) = {
        let handler = proxy_handler.lock().await;

        (handler.get_session_info(), handler.get_server_addr())
    };

    let mut server = create_tcp_stream(&socket_queue, server_addr, None).await?;

    log::debug!("Beginning {session_info}");

    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

    let mut buf1 = [0_u8; 4096];
    let mut buf2 = [0_u8; 4096];
    let mut server_buffer = Vec::with_capacity(4096);
    let mut outstanding_queries = HashMap::new();
    loop {
        tokio::select! {
            len = udp_stack.read(&mut buf1) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                let buf1 = &buf1[..len];

                let query = dns::parse_data_to_dns_message(buf1, false)?;
                let question = dns::validate_dns_query(&query)?.clone();
                if outstanding_queries.contains_key(&query.id) {
                    return Err(format!("duplicate in-flight DNS query ID {}", query.id).into());
                }
                if outstanding_queries.len() >= MAX_OUTSTANDING_DNS_QUERIES {
                    return Err(format!(
                        "DNS-over-TCP outstanding query limit reached ({MAX_OUTSTANDING_DNS_QUERIES})"
                    )
                    .into());
                }
                outstanding_queries.insert(query.id, question);

                // Insert the DNS message length in front of the payload
                let len = u16::try_from(buf1.len())?;
                let mut buf = Vec::with_capacity(std::mem::size_of::<u16>() + usize::from(len));
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(buf1);

                server.write_all(&buf).await?;

                crate::traffic_status::traffic_status_update(buf.len(), 0)?;
            }
            len = server.read(&mut buf2) => {
                let len = len?;
                if len == 0 {
                    break;
                }
                server_buffer.extend_from_slice(&buf2[..len]);

                crate::traffic_status::traffic_status_update(0, len)?;

                for mut message in dns::drain_tcp_messages(&mut server_buffer)? {
                    let expected_query = outstanding_queries
                        .remove(&message.id)
                        .ok_or_else(|| format!("unsolicited DNS-over-TCP response ID {}", message.id))?;
                    dns::validate_dns_response(&message, message.id, &expected_query)?;

                    let name = dns::extract_domain_from_dns_message(&message)?;
                    let ip = dns::extract_ipaddr_from_dns_message(&message);
                    log::trace!("DNS over TCP query result: {name} -> {ip:?}");

                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }

                    let packet = message.to_vec()?;
                    udp_stack.write_all(&packet).await?;
                }
            }
        }
    }

    log::debug!("Ending {session_info}");

    Ok(())
}

/// This function is used to handle the business logic of tun2proxy and SOCKS5 server.
/// When handling UDP proxy, the return value UDP associate IP address is the result of this business logic.
/// However, when handling TCP business logic, the return value Ok(None) is meaningless, just indicating that the operation was successful.
async fn handle_proxy_session(server: &mut TcpStream, proxy_handler: Arc<Mutex<dyn ProxyHandler>>) -> crate::Result<Option<SocketAddr>> {
    let mut launched = false;
    let mut proxy_handler = proxy_handler.lock().await;
    let dir = OutgoingDirection::ToServer;
    let (mut tx, mut rx) = (0, 0);

    loop {
        if proxy_handler.connection_established() {
            break;
        }

        if !launched {
            let data = proxy_handler.peek_data(dir).buffer;
            let len = data.len();
            if len == 0 {
                return Err("proxy_handler launched went wrong".into());
            }
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);
            tx += len;

            launched = true;
        }

        let mut buf = [0_u8; 4096];
        let len = server.read(&mut buf).await?;
        if len == 0 {
            return Err("server closed accidentially".into());
        }
        rx += len;
        let event = IncomingDataEvent {
            direction: IncomingDirection::FromServer,
            buffer: &buf[..len],
        };
        proxy_handler.push_data(event).await?;

        let data = proxy_handler.peek_data(dir).buffer;
        let len = data.len();
        if len > 0 {
            server.write_all(data).await?;
            proxy_handler.consume_data(dir, len);
            tx += len;
        }
    }
    crate::traffic_status::traffic_status_update(tx, rx)?;
    Ok(proxy_handler.get_udp_associate())
}

#[cfg(test)]
mod tcp_handshake_tests {
    use super::*;

    #[tokio::test]
    async fn server_first_data_survives_coalesced_proxy_reply() {
        for protocol in [ProxyType::Socks4, ProxyType::Socks5, ProxyType::Http] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let manager: Arc<dyn ProxyHandlerManager> = match protocol {
                ProxyType::Socks4 => Arc::new(SocksProxyManager::new(address, socks5_impl::protocol::Version::V4, None)),
                ProxyType::Socks5 => Arc::new(SocksProxyManager::new(address, socks5_impl::protocol::Version::V5, None)),
                ProxyType::Http => Arc::new(HttpManager::new(address, None)),
                _ => unreachable!(),
            };
            let info = SessionInfo::new("127.0.0.1:12345".parse().unwrap(), "127.0.0.1:22".parse().unwrap(), IpProtocol::Tcp);
            let handler = manager.new_proxy_handler(info, None, false).await.unwrap();
            let peer = async {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut reply = match protocol {
                    ProxyType::Socks4 => {
                        let mut request = [0; 9];
                        socket.read_exact(&mut request).await.unwrap();
                        assert_eq!(&request[..2], &[4, 1]);
                        vec![0, 0x5a, 0, 0, 0, 0, 0, 0]
                    }
                    ProxyType::Socks5 => {
                        let mut hello = [0; 2];
                        socket.read_exact(&mut hello).await.unwrap();
                        assert_eq!(hello[0], 5);
                        socket.read_exact(&mut vec![0; hello[1] as usize]).await.unwrap();
                        socket.write_all(&[5, 0]).await.unwrap();
                        let mut request = [0; 10];
                        socket.read_exact(&mut request).await.unwrap();
                        assert_eq!(&request[..4], &[5, 1, 0, 1]);
                        vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
                    }
                    ProxyType::Http => {
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            request.push(socket.read_u8().await.unwrap());
                        }
                        b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec()
                    }
                    _ => unreachable!(),
                };
                // SSH/SMTP send a greeting before the client writes anything.
                // A proxy may coalesce it with its successful CONNECT response.
                reply.extend_from_slice(b"SSH-2.0-test\r\n");
                socket.write_all(&reply).await.unwrap();
                let mut acknowledgement = [0; 2];
                socket.read_exact(&mut acknowledgement).await.unwrap();
                assert_eq!(&acknowledgement, b"ok");
            };
            let (mut client, mut stack) = tokio::io::duplex(1024);
            let relay = handle_tcp_session(&mut stack, handler, None, None, false);
            let application = async {
                let mut greeting = [0; 14];
                client.read_exact(&mut greeting).await.unwrap();
                assert_eq!(&greeting, b"SSH-2.0-test\r\n");
                client.write_all(b"ok").await.unwrap();
                client.shutdown().await.unwrap();
                let mut tail = Vec::new();
                client.read_to_end(&mut tail).await.unwrap();
                assert!(tail.is_empty(), "greeting must be delivered exactly once");
            };
            // No detached tasks: a timeout drops both sides and their sockets.
            tokio::time::timeout(Duration::from_secs(2), async {
                let (result, (), ()) = tokio::join!(relay, peer, application);
                result.unwrap();
            })
            .await
            .unwrap_or_else(|_| panic!("{protocol:?} lost the server greeting"));
        }
    }
}

#[cfg(test)]
mod virtual_dns_transport_tests {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };

    use super::*;

    #[tokio::test]
    async fn ipv4_tcp_dns_filters_prefetched_and_fragmented_pipelined_answers() {
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii("example.test").unwrap(), RecordType::AAAA));
        let mut answer = dns::build_dns_response(query, Some("2001:db8::7".parse().unwrap()), 30).unwrap();
        answer.metadata.authentic_data = true;
        let bytes = answer.to_vec().unwrap();
        let mut frame = (bytes.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&bytes);
        let frames = [frame.as_slice(), frame.as_slice()].concat();
        let (mut input, mut reader) = tokio::io::duplex(16);
        let (mut writer, mut output) = tokio::io::duplex(1024);
        let prefetched = frames[..3].to_vec();
        let source = async {
            for chunk in frames[3..].chunks(3) {
                input.write_all(chunk).await.unwrap();
            }
            input.shutdown().await.unwrap();
        };
        let relay = async {
            copy_ipv4_dns_responses(&mut reader, &mut writer, prefetched).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let sink = async {
            let mut filtered = Vec::new();
            output.read_to_end(&mut filtered).await.unwrap();
            let messages = dns::drain_tcp_messages(&mut filtered).unwrap();
            assert_eq!(messages.len(), 2);
            assert!(filtered.is_empty());
            for message in messages {
                assert_eq!(message.id, 7);
                assert!(message.answers.is_empty());
                assert!(!message.authentic_data);
                assert_eq!(message.queries[0].query_type(), RecordType::AAAA);
            }
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(source, relay, sink);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn ipv4_tcp_dns_rejects_truncated_frames_without_forwarding_bytes() {
        let mut reader = std::io::Cursor::new(vec![0, 12, 1]);
        let mut output = Vec::new();
        let error = copy_ipv4_dns_responses(&mut reader, &mut output, Vec::new()).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        assert!(output.is_empty());
    }

    #[test]
    fn session_permits_enforce_limit_and_release_on_drop() {
        let counts = Arc::new(SessionCounts::default());
        let tcp = counts.try_acquire(IpProtocol::Tcp, 2).unwrap();
        let udp = counts.try_acquire(IpProtocol::Udp, 2).unwrap();

        assert!(counts.try_acquire(IpProtocol::Tcp, 2).is_none());
        assert_eq!(counts.snapshot(), SessionCountSnapshot { total: 2, tcp: 1, udp: 1 });

        drop(udp);
        let replacement = counts.try_acquire(IpProtocol::Tcp, 2).unwrap();
        assert_eq!(counts.snapshot(), SessionCountSnapshot { total: 2, tcp: 2, udp: 0 });

        drop((tcp, replacement));
        assert_eq!(counts.snapshot(), SessionCountSnapshot { total: 0, tcp: 0, udp: 0 });
    }

    #[test]
    fn dns_tls_probe_only_matches_configured_virtual_portal() {
        assert!(is_virtual_dns_tls_probe(
            ArgDns::OverTcp,
            &["172.19.0.2".parse().unwrap()],
            "172.19.0.2:853".parse().unwrap()
        ));
        let portals = ["172.19.0.2".parse().unwrap()];

        assert!(is_virtual_dns_tls_probe(
            ArgDns::Virtual,
            &portals,
            "172.19.0.2:853".parse().unwrap()
        ));
        assert!(!is_virtual_dns_tls_probe(
            ArgDns::Virtual,
            &portals,
            "172.19.0.3:853".parse().unwrap()
        ));
        assert!(!is_virtual_dns_tls_probe(
            ArgDns::Virtual,
            &portals,
            "172.19.0.2:443".parse().unwrap()
        ));
        assert!(!is_virtual_dns_tls_probe(
            ArgDns::Direct,
            &portals,
            "172.19.0.2:853".parse().unwrap()
        ));
    }

    #[test]
    fn classifies_icmp_type_and_code() {
        assert_eq!(icmp_type_code(ICMP_V4_PROTOCOL, &[3, 3]), Some((3, 3)));
        assert_eq!(icmp_type_code(ICMP_V6_PROTOCOL, &[2, 0]), Some((2, 0)));
        assert_eq!(icmp_type_code(6, &[3, 3]), None);
        assert_eq!(icmp_type_code(ICMP_V4_PROTOCOL, &[3]), None);
    }

    #[test]
    fn local_multicast_destinations_bypass_internet_proxies() {
        assert!(is_local_multicast_destination("239.255.255.250".parse().unwrap()));
        assert!(is_local_multicast_destination("ff02::c".parse().unwrap()));
        assert!(!is_local_multicast_destination("198.18.0.1".parse().unwrap()));
        assert!(!is_local_multicast_destination("1.1.1.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn stale_virtual_dns_addresses_are_rejected_without_proxying() {
        let state = VirtualDnsState::default();
        let resolver = state.resolver();
        let stale = "198.18.0.1".parse().unwrap();

        let error = resolve_virtual_domain(Some(&resolver), stale).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert!(error.to_string().contains("stale virtual DNS address"));
        assert_eq!(
            resolve_virtual_domain(Some(&resolver), "8.8.8.8".parse().unwrap()).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn virtual_dns_answers_length_prefixed_tcp_queries() {
        let (mut client, server) = tokio::io::duplex(4096);
        let resolver = VirtualDnsState::default().resolver();
        let server_task = tokio::spawn(handle_virtual_dns_tcp_session(server, resolver));

        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A));
        let query = query.to_vec().unwrap();
        client.write_u16(query.len() as u16).await.unwrap();
        client.write_all(&query).await.unwrap();

        let response_len = client.read_u16().await.unwrap();
        let mut response = vec![0_u8; usize::from(response_len)];
        client.read_exact(&mut response).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.message_type, MessageType::Response);
        assert_eq!(response.answers.len(), 1);

        drop(client);
        server_task.await.unwrap().unwrap();
    }
}
