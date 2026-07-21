//! Physical-interface-bound direct relay used by the `--bypass-process` feature.
//!
//! When a session is bypassed we must relay it straight to its destination
//! *and* make sure our own outbound socket leaves through the real network
//! interface. Otherwise the TUN's catch-all route (installed by `--setup`)
//! re-captures the relay and the loop we were trying to break simply moves one
//! hop down. This mirrors mihomo's `auto-detect-interface` behaviour: bind the
//! direct socket to the default route's interface via `SO_BINDTODEVICE`
//! (Linux) or `IP_UNICAST_IF` (Windows).
//!
//! Only compiled on Windows and Linux.

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};
use tokio::net::TcpStream;

static NEXT_DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);

/// The physical interface direct relays egress through.
#[derive(Debug, Clone)]
pub(crate) struct BindInterface {
    /// IPv4 interface index, used by Windows `IP_UNICAST_IF`.
    pub ipv4_index: u32,
    /// IPv6 interface index, used by Windows `IPV6_UNICAST_IF`.
    pub ipv6_index: u32,
    /// IPv4 address used by `IP_MULTICAST_IF`. `IP_UNICAST_IF` alone does not
    /// select the egress interface for multicast datagrams on Windows.
    pub ipv4_addr: Option<Ipv4Addr>,
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
        #[cfg(target_os = "linux")]
        let (ipv4_index, ipv6_index) = (iface.index, iface.index);

        if ipv4_index == 0 && ipv6_index == 0 {
            return Err(format!("network interface `{}` has an invalid index 0", iface.name).into());
        }
        Ok(Self {
            ipv4_index,
            ipv6_index,
            ipv4_addr,
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
    #[cfg(target_os = "linux")]
    {
        err.raw_os_error() == Some(nix::libc::EINPROGRESS)
    }
    #[cfg(not(target_os = "linux"))]
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
        rr::{Name, RData, RecordType},
    };

    let mut current = domain.to_string();
    for _ in 0..4 {
        let name = Name::from_str(&current).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let query_type = if want_ipv6 { RecordType::AAAA } else { RecordType::A };
        let request_id = NEXT_DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let mut request = Message::new(request_id, MessageType::Query, OpCode::Query);
        request.set_recursion_desired(true);
        request.add_query(Query::query(name, query_type));
        let request = request.to_vec().map_err(std::io::Error::other)?;

        let server = SocketAddr::new(dns_server, 53);
        let socket = bind_udp_bound(server, iface)?;
        socket.send(&request).await?;
        let mut response = [0u8; 4096];
        let size = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut response))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("direct DNS query for `{current}` timed out")))??;
        let response = Message::from_vec(&response[..size]).map_err(std::io::Error::other)?;
        if response.id() != request_id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("direct DNS response ID mismatch for `{current}`"),
            ));
        }
        if response.response_code() != ResponseCode::NoError {
            return Err(std::io::Error::other(format!(
                "direct DNS query for `{current}` failed with {:?}",
                response.response_code()
            )));
        }

        let mut cname = None;
        for answer in response.answers() {
            match answer.data() {
                RData::A(address) if !want_ipv6 => return Ok(SocketAddr::new(IpAddr::V4((*address).into()), port)),
                RData::AAAA(address) if want_ipv6 => return Ok(SocketAddr::new(IpAddr::V6((*address).into()), port)),
                RData::CNAME(name) => cname = Some(name.to_ascii()),
                _ => {}
            }
        }
        match cname {
            Some(name) => current = name,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("direct DNS response for `{current}` contained no {query_type} address"),
                ));
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("direct DNS resolution for `{domain}` exceeded the CNAME limit"),
    ))
}
