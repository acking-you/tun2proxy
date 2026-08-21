//! Physical-interface-bound direct relay used by the `--bypass-process` feature.
//!
//! When a session is bypassed we must relay it straight to its destination
//! *and* make sure our own outbound socket leaves through the real network
//! interface. Otherwise the TUN's catch-all route (installed by `--setup`)
//! re-captures the relay and the loop we were trying to break simply moves one
//! hop down. This mirrors mihomo's `auto-detect-interface` behaviour: bind the
//! direct socket to the default route's interface via `SO_BINDTODEVICE`
//! (Linux), `IP_UNICAST_IF` (Windows), or `IP_BOUND_IF` (macOS).
//!
//! Only compiled on Windows, Linux, and macOS.

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

static NEXT_DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);
const DNS_UDP_ATTEMPTS: usize = 2;
const DNS_UDP_TIMEOUT: Duration = Duration::from_millis(750);
const DNS_TCP_TIMEOUT: Duration = Duration::from_millis(1500);

/// The physical interface direct relays egress through.
#[derive(Debug, Clone)]
pub(crate) struct BindInterface {
    /// IPv4 interface index, used by Windows `IP_UNICAST_IF` and macOS
    /// `IP_BOUND_IF`.
    pub ipv4_index: u32,
    /// IPv6 interface index, used by Windows `IPV6_UNICAST_IF` and macOS
    /// `IPV6_BOUND_IF`.
    pub ipv6_index: u32,
    /// IPv4 address used by `IP_MULTICAST_IF`. `IP_UNICAST_IF` alone does not
    /// select the egress interface for multicast datagrams on Windows.
    pub ipv4_addr: Option<Ipv4Addr>,
    /// Resolvers configured on the selected physical interface.
    pub dns_servers: Vec<IpAddr>,
    /// Interface name, used by Linux `SO_BINDTODEVICE`.
    pub name: String,
}

impl std::fmt::Display for BindInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} (IPv4 index {}, IPv6 index {})", self.name, self.ipv4_index, self.ipv6_index)
    }
}

impl BindInterface {
    fn from_netdev(iface: netdev::Interface) -> crate::Result<Self> {
        let ipv4_addr = iface
            .ipv4
            .iter()
            .map(|network| network.addr())
            .find(|address| !address.is_unspecified() && !address.is_loopback());
        #[cfg(target_os = "windows")]
        let (ipv4_index, ipv6_index) = windows_interface_indices(&iface)?;
        // Both BSD-style socket options take the same `if_nametoindex` value for
        // either family, so one index serves both.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let (ipv4_index, ipv6_index) = (iface.index, iface.index);

        if ipv4_index == 0 && ipv6_index == 0 {
            return Err(format!("network interface `{}` has an invalid index 0", iface.name).into());
        }
        Ok(Self {
            ipv4_index,
            ipv6_index,
            ipv4_addr,
            dns_servers: iface.dns_servers,
            name: iface.name,
        })
    }
}

#[cfg(target_os = "windows")]
fn windows_interface_indices(iface: &netdev::Interface) -> std::io::Result<(u32, u32)> {
    use std::ffi::CStr;
    use windows_sys::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
        NetworkManagement::IpHelper::{GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH},
        Networking::WinSock::AF_UNSPEC,
    };

    let mut size = 0_u32;
    let result = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, 0, std::ptr::null(), std::ptr::null_mut(), &mut size) };
    if result != ERROR_BUFFER_OVERFLOW {
        return Err(std::io::Error::from_raw_os_error(result as i32));
    }

    let word_size = std::mem::size_of::<usize>();
    let mut storage = vec![0_usize; (size as usize).div_ceil(word_size)];
    let addresses = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let result = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, 0, std::ptr::null(), addresses, &mut size) };
    if result != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(result as i32));
    }

    let mut current = addresses;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        let ipv4_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let adapter_name = if adapter.AdapterName.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(adapter.AdapterName.cast()) }.to_string_lossy())
        };
        if (iface.index != 0 && ipv4_index == iface.index) || adapter_name.as_deref() == Some(iface.name.as_str()) {
            return Ok((ipv4_index, adapter.Ipv6IfIndex));
        }
        current = adapter.Next;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("network interface `{}` was not found by GetAdaptersAddresses", iface.name),
    ))
}

/// Resolve the interface used for direct relays: an explicit `--bind-interface`
/// value (matched against system, friendly, or description names) or, when
/// omitted, the default route interface.
pub(crate) fn detect(manual: Option<&str>) -> crate::Result<BindInterface> {
    match manual {
        Some(wanted) => {
            let iface = netdev::get_interfaces()
                .into_iter()
                .find(|i| i.name == wanted || i.friendly_name.as_deref() == Some(wanted) || i.description.as_deref() == Some(wanted))
                .ok_or_else(|| crate::Error::from(format!("--bind-interface `{wanted}` was not found")))?;
            BindInterface::from_netdev(iface)
        }
        None => {
            let iface = netdev::get_default_interface().map_err(crate::Error::from)?;
            BindInterface::from_netdev(iface)
        }
    }
}

/// Whether a non-blocking `connect` returned the "in progress" status rather
/// than a real error.
fn connect_in_progress(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(nix::libc::EINPROGRESS)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Bind `socket` to the configured physical interface for the given peer family.
#[cfg(target_os = "linux")]
fn apply_device_bind(socket: &Socket, _peer: SocketAddr, iface: &BindInterface) -> std::io::Result<()> {
    // SO_BINDTODEVICE forces egress through the named interface.
    socket.bind_device(Some(iface.name.as_bytes()))
}

/// Bind `socket` to the configured physical interface for the given peer family.
///
/// macOS has no `SO_BINDTODEVICE`. `IP_BOUND_IF` is the documented equivalent and
/// does override the default route, which is exactly what is needed here: while
/// TUN mode is active the default route points at the utun device, so an unbound
/// direct relay would be recaptured.
#[cfg(target_os = "macos")]
fn apply_device_bind(socket: &Socket, peer: SocketAddr, iface: &BindInterface) -> std::io::Result<()> {
    use nix::libc;
    use std::os::fd::AsRawFd;

    let (level, optname, index) = if peer.is_ipv4() {
        if iface.ipv4_index == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("interface `{}` has no IPv4 index", iface.name),
            ));
        }
        (libc::IPPROTO_IP, libc::IP_BOUND_IF, iface.ipv4_index)
    } else {
        if iface.ipv6_index == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("interface `{}` has no IPv6 index", iface.name),
            ));
        }
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF, iface.ipv6_index)
    };
    // Unlike the Windows `IP_UNICAST_IF` asymmetry, both options take a plain
    // host-order interface index.
    let value = index as libc::c_uint;
    // SAFETY: `value` outlives the call, `optlen` matches its size, and the fd is
    // owned by `socket` for the duration.
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            optname,
            &value as *const libc::c_uint as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Bind `socket` to the configured physical interface for the given peer family.
#[cfg(target_os = "windows")]
fn apply_device_bind(socket: &Socket, peer: SocketAddr, iface: &BindInterface) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, setsockopt};

    let raw = socket.as_raw_socket() as SOCKET;
    // IP_UNICAST_IF takes the interface index in network byte order for IPv4 but
    // host byte order for IPv6 — a well-known Win32 asymmetry.
    let (level, optname, value) = if peer.is_ipv4() {
        if iface.ipv4_index == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("interface `{}` has no IPv4 index", iface.name),
            ));
        }
        (IPPROTO_IP, IP_UNICAST_IF, iface.ipv4_index.to_be())
    } else {
        if iface.ipv6_index == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("interface `{}` has no IPv6 index", iface.name),
            ));
        }
        (IPPROTO_IPV6, IPV6_UNICAST_IF, iface.ipv6_index)
    };
    // SAFETY: `value` is a live `u32` for the duration of the call and `optlen`
    // matches its size; `raw` is this socket's valid handle.
    let ret = unsafe {
        setsockopt(
            raw,
            level,
            optname,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Open a TCP connection to `peer` that egresses through `iface`.
pub(crate) async fn connect_tcp_bound(peer: SocketAddr, iface: &BindInterface) -> std::io::Result<TcpStream> {
    let domain = if peer.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    apply_device_bind(&socket, peer, iface)?;
    socket.set_nonblocking(true)?;

    match socket.connect(&SockAddr::from(peer)) {
        Ok(()) => {}
        Err(err) if connect_in_progress(&err) => {}
        Err(err) => return Err(err),
    }

    let std_stream = std::net::TcpStream::from(socket);
    let stream = TcpStream::from_std(std_stream)?;
    // Non-blocking connect completes asynchronously; wait for writability and
    // surface any pending socket error (e.g. connection refused).
    stream.writable().await?;
    if let Some(err) = stream.take_error()? {
        return Err(err);
    }
    Ok(stream)
}

/// Open a connected UDP socket to `peer` that egresses through `iface`.
pub(crate) fn bind_udp_bound(peer: SocketAddr, iface: &BindInterface) -> std::io::Result<tokio::net::UdpSocket> {
    let domain = if peer.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    apply_device_bind(&socket, peer, iface)?;
    match peer.ip() {
        IpAddr::V4(address) if address.is_multicast() => {
            let interface = iface.ipv4_addr.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    format!("interface `{}` has no IPv4 address for multicast egress", iface.name),
                )
            })?;
            socket.set_multicast_if_v4(&interface)?;
        }
        IpAddr::V6(address) if address.is_multicast() => {
            if iface.ipv6_index == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    format!("interface `{}` has no IPv6 index for multicast egress", iface.name),
                ));
            }
            socket.set_multicast_if_v6(iface.ipv6_index)?;
        }
        _ => {}
    }

    let unspecified = match peer {
        SocketAddr::V4(_) => SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
    };
    socket.bind(&SockAddr::from(unspecified))?;
    // UDP connect only fixes the default peer; it returns immediately.
    socket.connect(&SockAddr::from(peer))?;
    socket.set_nonblocking(true)?;

    let std_socket = std::net::UdpSocket::from(socket);
    tokio::net::UdpSocket::from_std(std_socket)
}

/// Resolve a virtual-DNS name through a DNS socket pinned to the physical
/// interface.
///
/// Calling the operating-system resolver here is not sufficient: its query may
/// itself enter the TUN and receive another virtual address. Sending the DNS
/// packet through `IP_UNICAST_IF`/`SO_BINDTODEVICE` guarantees that a process
/// selected for bypass can recover from a fake address cached before the policy
/// was changed.
pub(crate) async fn resolve_domain_bound(
    domain: &str,
    port: u16,
    dns_server: IpAddr,
    want_ipv6: bool,
    iface: &BindInterface,
) -> std::io::Result<SocketAddr> {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{Name, RecordType},
    };

    let mut current = domain.to_string();
    for _ in 0..crate::dns::MAX_CNAME_DEPTH {
        let name = Name::from_str(&current).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let query_type = if want_ipv6 { RecordType::AAAA } else { RecordType::A };
        let query = Query::query(name, query_type);
        let request_id = NEXT_DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let mut request = Message::new(request_id, MessageType::Query, OpCode::Query);
        request.set_recursion_desired(true);
        request.add_query(query.clone());
        let request = request.to_vec().map_err(std::io::Error::other)?;

        let response = query_dns_bound(&request, request_id, &query, &current, dns_server, iface).await?;
        if response.response_code() != ResponseCode::NoError {
            return Err(std::io::Error::other(format!(
                "direct DNS query for `{current}` failed with {:?}",
                response.response_code()
            )));
        }
        match crate::dns::extract_address_or_cname(&response, &query)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::NotFound, error))?
        {
            crate::dns::AddressLookup::Address(ip) => return Ok(SocketAddr::new(ip, port)),
            crate::dns::AddressLookup::Cname(name) => current = name,
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("direct DNS resolution for `{domain}` exceeded the CNAME limit"),
    ))
}

async fn query_dns_bound(
    request: &[u8],
    request_id: u16,
    expected_query: &hickory_proto::op::Query,
    domain: &str,
    configured_dns: IpAddr,
    iface: &BindInterface,
) -> std::io::Result<hickory_proto::op::Message> {
    let servers = direct_dns_servers(configured_dns, iface);
    let mut last_error = None;

    'servers: for dns_server in &servers {
        let server = SocketAddr::new(*dns_server, 53);
        for _ in 0..DNS_UDP_ATTEMPTS {
            match tokio::time::timeout(DNS_UDP_TIMEOUT, query_dns_udp(request, request_id, expected_query, server, iface)).await {
                Ok(Ok(response)) if response.truncated() => break,
                Ok(Ok(response))
                    if matches!(
                        response.response_code(),
                        hickory_proto::op::ResponseCode::NoError | hickory_proto::op::ResponseCode::NXDomain
                    ) =>
                {
                    return Ok(response);
                }
                Ok(Ok(response)) => {
                    last_error = Some(std::io::Error::other(format!(
                        "UDP DNS query to {dns_server} failed with {:?}",
                        response.response_code()
                    )));
                    continue 'servers;
                }
                Ok(Err(error)) => {
                    log::debug!("Direct UDP DNS query to {dns_server} failed: {error}");
                }
                Err(_) => {
                    log::debug!("Direct UDP DNS query to {dns_server} timed out");
                }
            }
        }

        match tokio::time::timeout(DNS_TCP_TIMEOUT, query_dns_tcp(request, request_id, expected_query, server, iface)).await {
            Ok(Ok(response))
                if matches!(
                    response.response_code(),
                    hickory_proto::op::ResponseCode::NoError | hickory_proto::op::ResponseCode::NXDomain
                ) =>
            {
                return Ok(response);
            }
            Ok(Ok(response)) => {
                last_error = Some(std::io::Error::other(format!(
                    "TCP DNS query to {dns_server} failed with {:?}",
                    response.response_code()
                )));
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("TCP DNS query to {dns_server} timed out"),
                ));
            }
        }
    }

    let detail = last_error
        .map(|error| error.to_string())
        .unwrap_or_else(|| "no DNS resolver is available".to_string());
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!(
            "direct DNS query for `{domain}` through physical resolver(s) {} failed: {detail}",
            servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
        ),
    ))
}

fn direct_dns_servers(configured_dns: IpAddr, iface: &BindInterface) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for address in iface.dns_servers.iter().copied().filter(is_usable_dns_server) {
        if !servers.contains(&address) {
            servers.push(address);
        }
    }
    if is_usable_dns_server(&configured_dns) && !servers.contains(&configured_dns) {
        servers.push(configured_dns);
    }
    servers
}

pub(crate) fn preferred_dns_server(configured_dns: IpAddr, iface: &BindInterface) -> Option<IpAddr> {
    direct_dns_servers(configured_dns, iface).into_iter().next()
}

fn is_usable_dns_server(address: &IpAddr) -> bool {
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    match address {
        IpAddr::V4(address) => *address != Ipv4Addr::BROADCAST,
        IpAddr::V6(address) => !address.is_unicast_link_local(),
    }
}

async fn query_dns_udp(
    request: &[u8],
    request_id: u16,
    expected_query: &hickory_proto::op::Query,
    server: SocketAddr,
    iface: &BindInterface,
) -> std::io::Result<hickory_proto::op::Message> {
    let socket = bind_udp_bound(server, iface)?;
    socket.send(request).await?;
    let mut response = [0u8; 4096];
    let size = socket.recv(&mut response).await?;
    parse_dns_response(&response[..size], request_id, expected_query)
}

async fn query_dns_tcp(
    request: &[u8],
    request_id: u16,
    expected_query: &hickory_proto::op::Query,
    server: SocketAddr,
    iface: &BindInterface,
) -> std::io::Result<hickory_proto::op::Message> {
    let request_len =
        u16::try_from(request.len()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "DNS request is too large"))?;
    let mut stream = connect_tcp_bound(server, iface).await?;
    stream.write_all(&request_len.to_be_bytes()).await?;
    stream.write_all(request).await?;

    let response_len = stream.read_u16().await? as usize;
    if response_len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid TCP DNS response length {response_len}"),
        ));
    }
    let mut response = vec![0; response_len];
    stream.read_exact(&mut response).await?;
    parse_dns_response(&response, request_id, expected_query)
}

fn parse_dns_response(
    response: &[u8],
    request_id: u16,
    expected_query: &hickory_proto::op::Query,
) -> std::io::Result<hickory_proto::op::Message> {
    let response = hickory_proto::op::Message::from_vec(response).map_err(std::io::Error::other)?;
    crate::dns::validate_dns_response(&response, request_id, expected_query)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_interface(dns_servers: Vec<IpAddr>) -> BindInterface {
        BindInterface {
            ipv4_index: 1,
            ipv6_index: 1,
            ipv4_addr: Some(Ipv4Addr::LOCALHOST),
            dns_servers,
            name: "test".to_string(),
        }
    }

    /// A bound socket must source from the interface it was pinned to. UDP
    /// `connect` only records a default peer, so this sends no packets.
    ///
    /// Note this compares against the default interface, so it proves the bind is
    /// accepted and honoured rather than that it beats a *competing* route. The
    /// override itself was confirmed by hand with the default route pointing at a
    /// utun device: unbound sockets left through the tunnel while bound ones still
    /// left through the physical interface. Reproducing that here would require
    /// installing a route, which a unit test must not do.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bound_socket_egresses_through_the_named_interface() {
        use std::net::UdpSocket;

        let Ok(iface) = detect(None) else {
            // No default route on this machine; nothing to compare against.
            return;
        };
        let Some(expected) = iface.ipv4_addr else {
            return;
        };

        // A public address that is merely routed, never contacted here.
        let peer: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        apply_device_bind(&socket, peer, &iface).expect("IP_BOUND_IF must be accepted");
        socket.bind(&SockAddr::from(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))).unwrap();
        socket.connect(&SockAddr::from(peer)).unwrap();

        let bound = UdpSocket::from(socket).local_addr().unwrap();
        assert_eq!(
            bound.ip(),
            IpAddr::V4(expected),
            "a bound socket must egress through `{}`",
            iface.name
        );
    }

    #[test]
    fn direct_dns_prefers_physical_interface_resolvers() {
        let physical = "192.168.21.1".parse().unwrap();
        let configured = "8.8.8.8".parse().unwrap();
        let iface = test_interface(vec![physical]);

        assert_eq!(direct_dns_servers(configured, &iface), vec![physical, configured]);
    }

    #[test]
    fn direct_dns_deduplicates_configured_resolver() {
        let configured = "1.1.1.1".parse().unwrap();
        let iface = test_interface(vec![configured]);

        assert_eq!(direct_dns_servers(configured, &iface), vec![configured]);
    }

    #[test]
    fn direct_dns_ignores_resolvers_that_cannot_be_reached_on_a_physical_bind() {
        let configured = "8.8.8.8".parse().unwrap();
        let iface = test_interface(vec![
            "127.0.0.53".parse().unwrap(),
            "::1".parse().unwrap(),
            "224.0.0.251".parse().unwrap(),
        ]);

        assert_eq!(direct_dns_servers(configured, &iface), vec![configured]);
    }

    #[test]
    fn direct_dns_selects_the_physical_resolver_for_private_virtual_portals() {
        let physical = "192.168.21.1".parse().unwrap();
        let configured = "8.8.8.8".parse().unwrap();
        let iface = test_interface(vec![physical]);

        assert_eq!(preferred_dns_server(configured, &iface), Some(physical));
    }
}
