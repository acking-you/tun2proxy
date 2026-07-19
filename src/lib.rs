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
use ipstack::{IpStackStream, IpStackTcpStream, IpStackUdpStream};
use proxy_handler::{ProxyHandler, ProxyHandlerManager};
use socks::SocksProxyManager;
pub use socks5_impl::protocol::UserKey;
#[cfg(feature = "udpgw")]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::{
    collections::VecDeque,
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
use udp_stream::UdpStream;
#[cfg(feature = "udpgw")]
use udpgw::{UDPGW_KEEPALIVE_TIME, UDPGW_MAX_CONNECTIONS, UdpGwClientStream, UdpGwResponse};

pub use {
    args::{ArgDns, ArgProxy, ArgUdpStrategy, ArgVerbosity, Args, ProxyType},
    error::{BoxError, Error, Result},
    process_bypass::{ProcessBypass, normalize_process_name},
    traffic_status::{TrafficStatus, tun2proxy_set_traffic_status_callback},
    virtual_dns::VirtualDnsState,
};

pub use general_api::{
    general_run_async, general_run_async_with_process_bypass, general_run_async_with_process_bypass_and_ready,
    general_run_async_with_process_bypass_and_ready_and_virtual_dns,
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
#[cfg(any(target_os = "windows", target_os = "linux"))]
mod direct;
mod directions;
mod dns;
mod dump_logger;
mod error;
mod general_api;
mod http;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod network_config;
mod no_proxy;
#[cfg(any(target_os = "windows", target_os = "linux"))]
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
#[cfg(any(target_os = "windows", target_os = "linux"))]
type DirectBind = Arc<direct::BindInterface>;
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
type DirectBind = std::convert::Infallible;

/// Outcome of constructing a per-session proxy handler.
type HandlerResult = std::io::Result<Arc<Mutex<dyn ProxyHandler>>>;

/// Run one established relay until it finishes normally or a live process
/// policy update changes whether its source process should bypass the proxy.
/// Dropping the relay future closes both halves; the application can then
/// reconnect and receive a fresh handler on the new route.
#[cfg(any(target_os = "windows", target_os = "linux"))]
async fn run_until_process_policy_change<F, T>(
    relay: F,
    matcher: Option<Arc<process::ProcessMatcher>>,
    changes: Option<tokio::sync::watch::Receiver<u64>>,
    protocol: IpProtocol,
    src: SocketAddr,
    dst: SocketAddr,
    initial_bypass: bool,
) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    let Some(matcher) = matcher else {
        return Some(relay.await);
    };
    let Some(changes) = changes else {
        return Some(relay.await);
    };
    tokio::select! {
        result = relay => Some(result),
        _ = matcher.wait_for_routing_change(changes, protocol, src, dst, initial_bypass) => None,
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
    #[cfg(any(target_os = "windows", target_os = "linux"))]
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

async fn create_udp_stream(
    socket_queue: &Option<Arc<SocketQueue>>,
    peer: SocketAddr,
    bind: Option<&DirectBind>,
) -> std::io::Result<UdpStream> {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    if let Some(iface) = bind {
        if socket_queue.is_none() {
            let socket = direct::bind_udp_bound(peer, iface)?;
            return UdpStream::from_tokio(socket, peer).await;
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
            UdpStream::from_tokio(socket, peer).await
        }
        Some(queue) => {
            let socket = queue.recv_udp(peer.ip().into()).await?;
            socket.connect(peer).await?;
            UdpStream::from_tokio(socket, peer).await
        }
    }
}

/// Replace a stale virtual-DNS destination with a real address before opening a
/// physical-interface-bound process bypass relay.
#[cfg(any(target_os = "windows", target_os = "linux"))]
async fn restore_bypass_destination(
    info: &mut SessionInfo,
    virtual_dns: Option<&Arc<Mutex<VirtualDns>>>,
    dns_addr: IpAddr,
    bind: Option<&DirectBind>,
) -> std::io::Result<()> {
    let Some(virtual_dns) = virtual_dns else {
        return Ok(());
    };
    let domain = {
        let mut virtual_dns = virtual_dns.lock().await;
        virtual_dns.touch_ip(&info.dst.ip());
        virtual_dns.resolve_ip(&info.dst.ip()).cloned()
    };
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
        rr::{Name, RData, RecordType},
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

    for _ in 0..4 {
        let name = Name::from_str(&current).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let request_id = NEXT_QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let mut request = Message::new(request_id, MessageType::Query, OpCode::Query);
        request.set_recursion_desired(true);
        request.add_query(Query::query(name, query_type));
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
        if response.id() != request_id {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("proxied DNS response ID mismatch for `{current}`"),
            ));
        }
        if response.response_code() != ResponseCode::NoError {
            return Err(std::io::Error::other(format!(
                "proxied DNS query for `{current}` failed with {:?}",
                response.response_code()
            )));
        }

        let mut cname = None;
        for answer in response.answers() {
            match answer.data() {
                RData::A(address) if !want_ipv6 => {
                    return Ok(SocketAddr::new(IpAddr::V4((*address).into()), port));
                }
                RData::AAAA(address) if want_ipv6 => {
                    return Ok(SocketAddr::new(IpAddr::V6((*address).into()), port));
                }
                RData::CNAME(name) => cname = Some(name.to_ascii()),
                _ => {}
            }
        }
        current = cname.ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::NotFound,
                format!("proxied DNS response for `{current}` contained no {query_type} address"),
            )
        })?;
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
    let virtual_dns = if args.dns == ArgDns::Virtual {
        Some(match virtual_dns_state {
            Some(state) => state.resolver(),
            None => Arc::new(Mutex::new(VirtualDns::new(args.virtual_dns_pool))),
        })
    } else {
        None
    };

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
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    let process_matcher = process::ProcessMatcher::new(process_bypass.clone()).map(Arc::new);
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    let direct_bind = if process_matcher.is_some() || udp_strategy == ArgUdpStrategy::Direct {
        let iface = direct::detect(args.bind_interface.as_deref())?;
        log::info!("Direct relays egress via {iface}");
        Some(Arc::new(iface) as DirectBind)
    } else {
        None
    };
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let direct_bind: Option<DirectBind> = None;
    let no_proxy_mgr: Arc<dyn ProxyHandlerManager> = Arc::new(NoProxyManager::new());
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    if process_bypass.is_configured() {
        log::info!("Process bypass enabled for {:?}", process_bypass.names());
    }
    if udp_strategy == ArgUdpStrategy::Direct {
        log::warn!("Non-DNS UDP direct fallback enabled; UDP traffic will bypass the proxy");
    } else if udp_strategy == ArgUdpStrategy::Block {
        log::warn!("Non-DNS UDP is blocked by policy");
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    if process_bypass.is_configured() {
        log::warn!("--bypass-process is not supported on this platform; ignoring it");
    }

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(mtu)?;
    let mut tcp_cfg = ipstack::TcpConfig::default();
    tcp_cfg.timeout = std::time::Duration::from_secs(args.tcp_timeout);
    ipstack_config.with_tcp_config(tcp_cfg);
    ipstack_config.udp_timeout(std::time::Duration::from_secs(args.udp_timeout));

    let mut ip_stack = ipstack::IpStack::new(ipstack_config, device);

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
            IpStackStream::Tcp(tcp) => {
                let Some(session_permit) = session_counts.try_acquire(IpProtocol::Tcp, max_sessions) else {
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
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                let process_matcher = process_matcher.clone();
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                let direct_bind = direct_bind.clone();
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                let no_proxy_mgr = no_proxy_mgr.clone();
                // The source-process lookup may briefly touch the OS, so the
                // bypass decision and handler creation run inside the per-session
                // task rather than on the accept loop.
                managed_tasks.spawn(async move {
                    let _session_permit = session_permit;
                    #[cfg(any(target_os = "windows", target_os = "linux"))]
                    let policy_changes = process_matcher.as_ref().map(|matcher| matcher.subscribe());
                    #[cfg(any(target_os = "windows", target_os = "linux"))]
                    let bypass = match &process_matcher {
                        Some(matcher) => matcher.matches(IpProtocol::Tcp, info.src, info.dst).await,
                        None => false,
                    };
                    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
                    let bypass = false;

                    if !bypass && dns == ArgDns::Virtual && info.dst.port() == DNS_PORT {
                        let result = match virtual_dns.clone() {
                            Some(virtual_dns) => handle_virtual_dns_tcp_session(tcp, virtual_dns).await,
                            None => Err("virtual DNS manager is unavailable".into()),
                        };
                        if let Err(error) = result {
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

                    #[cfg(any(target_os = "windows", target_os = "linux"))]
                    let (handler_result, bind, bypass, policy_changes): (
                        HandlerResult,
                        Option<DirectBind>,
                        bool,
                        Option<tokio::sync::watch::Receiver<u64>>,
                    ) = {
                        let mut info = info;
                        if bypass && info.dst.port() == DNS_PORT && is_private_ip(info.dst.ip()) {
                            info.dst.set_ip(dns_addr);
                        }
                        let bypass_destination = if bypass {
                            restore_bypass_destination(&mut info, virtual_dns.as_ref(), dns_addr, direct_bind.as_ref()).await
                        } else {
                            Ok(())
                        };
                        let domain_name = if let Some(virtual_dns) = &virtual_dns {
                            let mut virtual_dns = virtual_dns.lock().await;
                            virtual_dns.touch_ip(&info.dst.ip());
                            virtual_dns.resolve_ip(&info.dst.ip()).cloned()
                        } else {
                            None
                        };
                        match (bypass_destination, bypass) {
                            (Err(error), _) => (Err(error), direct_bind.clone(), bypass, policy_changes),
                            (Ok(()), true) => (
                                no_proxy_mgr.new_proxy_handler(info, domain_name, false).await,
                                direct_bind.clone(),
                                bypass,
                                policy_changes,
                            ),
                            (Ok(()), false) => (mgr.new_proxy_handler(info, domain_name, false).await, None, bypass, policy_changes),
                        }
                    };
                    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
                    let (handler_result, bind): (HandlerResult, Option<DirectBind>) = {
                        let domain_name = if let Some(virtual_dns) = &virtual_dns {
                            let mut virtual_dns = virtual_dns.lock().await;
                            virtual_dns.touch_ip(&info.dst.ip());
                            virtual_dns.resolve_ip(&info.dst.ip()).cloned()
                        } else {
                            None
                        };
                        (mgr.new_proxy_handler(info, domain_name, false).await, None)
                    };

                    match handler_result {
                        Ok(proxy_handler) => {
                            #[cfg(any(target_os = "windows", target_os = "linux"))]
                            let result = run_until_process_policy_change(
                                handle_tcp_session(tcp, proxy_handler, socket_queue, bind),
                                process_matcher,
                                policy_changes,
                                IpProtocol::Tcp,
                                info.src,
                                info.dst,
                                bypass,
                            )
                            .await;
                            #[cfg(not(any(target_os = "windows", target_os = "linux")))]
                            let result = Some(handle_tcp_session(tcp, proxy_handler, socket_queue, bind).await);

                            if let Some(Err(err)) = result {
                                log::error!("{info} error \"{err}\"");
                            }
                        }
                        Err(err) => log::error!("{info} failed to create proxy handler: {err}"),
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
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                let process_matcher = process_matcher.clone();
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                let direct_bind = direct_bind.clone();
                let no_proxy_mgr = no_proxy_mgr.clone();
                #[cfg(feature = "udpgw")]
                let udpgw_client = udpgw_client.clone();
                let udp_setup_timeout = Duration::from_secs(args.udp_timeout.max(1));
                managed_tasks.spawn(async move {
                    let _session_permit = session_permit;
                    let mut info = SessionInfo::new(udp.local_addr(), udp.peer_addr(), IpProtocol::Udp);
                    #[cfg(any(target_os = "windows", target_os = "linux"))]
                    let original_src = info.src;
                    #[cfg(any(target_os = "windows", target_os = "linux"))]
                    let original_dst = info.dst;
                    #[cfg(any(target_os = "windows", target_os = "linux"))]
                    let policy_changes = process_matcher.as_ref().map(|matcher| matcher.subscribe());
                    // Decide process bypass before DNS or UdpGW handling. A
                    // bypassed process must see real DNS answers and raw UDP;
                    // otherwise its own traffic can recurse through the local
                    // proxy or attempt to connect to a virtual-DNS fake IP.
                    #[cfg(any(target_os = "windows", target_os = "linux"))]
                    let bypass = match &process_matcher {
                        Some(matcher) => matcher.matches(IpProtocol::Udp, info.src, info.dst).await,
                        None => false,
                    };

                    let relay = async {
                        #[cfg(any(target_os = "windows", target_os = "linux"))]
                        if bypass {
                            if info.dst.port() == DNS_PORT && is_private_ip(info.dst.ip()) {
                                info.dst.set_ip(dns_addr);
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

                        let domain_name = if let Some(virtual_dns) = &virtual_dns {
                            let mut virtual_dns = virtual_dns.lock().await;
                            virtual_dns.touch_ip(&info.dst.ip());
                            virtual_dns.resolve_ip(&info.dst.ip()).cloned()
                        } else {
                            None
                        };

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
                                Some(ref domain) => socks5_impl::protocol::Address::from((domain.clone(), info.dst.port())),
                                None => info.dst.into(),
                            };
                            return handle_udp_gateway_session(udp, udpgw, &dst_addr, proxy_handler, socket_queue, ipv6_enabled).await;
                        }

                        let proxy_handler = mgr.new_proxy_handler(info, domain_name, true).await?;
                        handle_udp_associate_session(udp, proxy_type, proxy_handler, socket_queue, ipv6_enabled, None, udp_setup_timeout)
                            .await
                    };

                    #[cfg(any(target_os = "windows", target_os = "linux"))]
                    let result = run_until_process_policy_change(
                        relay,
                        process_matcher,
                        policy_changes,
                        IpProtocol::Udp,
                        original_src,
                        original_dst,
                        bypass,
                    )
                    .await;
                    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
                    let result = Some(relay.await);

                    if let Some(Err(err)) = result {
                        log::info!("Ending {info} with \"{err}\"");
                    }
                });
            }
            IpStackStream::UnknownTransport(u) => {
                let len = u.payload().len();
                log::info!("#0 unhandled transport - Ip Protocol {:?}, length {}", u.ip_protocol(), len);
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
        log::debug!("Virtual DNS query: {qname} -> {ip}");
    }
    Ok(())
}

fn is_virtual_dns_tls_probe(dns: ArgDns, portals: &[IpAddr], destination: SocketAddr) -> bool {
    dns == ArgDns::Virtual && destination.port() == DNS_OVER_TLS_PORT && portals.contains(&destination.ip())
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
        log::debug!("Virtual DNS TCP query: {qname} -> {ip}");
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

async fn handle_tcp_session(
    mut tcp_stack: IpStackTcpStream,
    proxy_handler: Arc<Mutex<dyn ProxyHandler>>,
    socket_queue: Option<Arc<SocketQueue>>,
    bind: Option<DirectBind>,
) -> crate::Result<()> {
    let (session_info, server_addr) = {
        let handler = proxy_handler.lock().await;

        (handler.get_session_info(), handler.get_server_addr())
    };

    // For a process-bypass session `server_addr` is the original destination and
    // `bind` pins the egress to the physical interface; otherwise it is the proxy
    // and `bind` is `None` (normal routing).
    let mut server = create_tcp_stream(&socket_queue, server_addr, bind.as_ref()).await?;

    log::info!("Beginning {session_info}");

    if let Err(e) = handle_proxy_session(&mut server, proxy_handler).await {
        tcp_stack.shutdown().await?;
        return Err(e);
    }

    let (mut t_rx, mut t_tx) = tokio::io::split(tcp_stack);
    let (mut s_rx, mut s_tx) = tokio::io::split(server);

    let res = tokio::join!(
        async move {
            let r = copy_and_record_traffic(&mut t_rx, &mut s_tx, true).await;
            if let Err(err) = s_tx.shutdown().await {
                log::trace!("{session_info} s_tx shutdown error {err}");
            }
            r
        },
        async move {
            let r = copy_and_record_traffic(&mut s_rx, &mut t_tx, false).await;
            if let Err(err) = t_tx.shutdown().await {
                log::trace!("{session_info} t_tx shutdown error {err}");
            }
            r
        },
    );
    log::info!("Ending {session_info} with {res:?}");

    Ok(())
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

    log::info!("[UdpGw] Beginning stream {} {} -> {}", sn, &tcp_local_addr, udp_dst);

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
                        log::info!("[UdpGw] Ending stream {} {} <> {}", sn, &tcp_local_addr, udp_dst);
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        log::info!("[UdpGw] Ending stream {} {} <> {} with udp stack \"{}\"", sn, &tcp_local_addr, udp_dst, e);
                        break;
                    }
                };
                crate::traffic_status::traffic_status_update(read_len, 0)?;
                let sn = stream.serial_number();
                if let Err(e) = UdpGwClient::send_udpgw_packet(ipv6_enabled, &tmp_buf[0..read_len], udp_dst, sn, &mut writer).await {
                    log::info!("[UdpGw] Ending stream {} {} <> {} with send_udpgw_packet {}", sn, &tcp_local_addr, udp_dst, e);
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
                            log::info!("[UdpGw] Ending stream {} {} <> {} with recv udp error", sn, &tcp_local_addr, udp_dst);
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

    log::info!("Beginning {session_info}");

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
                        Address::DomainAddress(domain_name.clone().into(), session_info.dst.port())
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

    log::info!("Ending {session_info}");

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

    log::info!("Beginning {session_info}");

    let _ = handle_proxy_session(&mut server, proxy_handler).await?;

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

                _ = dns::parse_data_to_dns_message(buf1, false)?;

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
                let mut buf = buf2[..len].to_vec();

                crate::traffic_status::traffic_status_update(0, len)?;

                let mut to_send: VecDeque<Vec<u8>> = VecDeque::new();
                loop {
                    if buf.len() < 2 {
                        break;
                    }
                    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if buf.len() < len + 2 {
                        break;
                    }

                    // remove the length field
                    let data = buf[2..len + 2].to_vec();

                    let mut message = dns::parse_data_to_dns_message(&data, false)?;

                    let name = dns::extract_domain_from_dns_message(&message)?;
                    let ip = dns::extract_ipaddr_from_dns_message(&message);
                    log::trace!("DNS over TCP query result: {name} -> {ip:?}");

                    if !ipv6_enabled {
                        dns::remove_ipv6_entries(&mut message);
                    }

                    to_send.push_back(message.to_vec()?);
                    if len + 2 == buf.len() {
                        break;
                    }
                    buf = buf[len + 2..].to_vec();
                }

                while let Some(packet) = to_send.pop_front() {
                    udp_stack.write_all(&packet).await?;
                }
            }
        }
    }

    log::info!("Ending {session_info}");

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
mod virtual_dns_transport_tests {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };

    use super::*;

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
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.answers().len(), 1);

        drop(client);
        server_task.await.unwrap().unwrap();
    }
}
