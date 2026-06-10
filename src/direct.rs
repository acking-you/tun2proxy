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
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// The physical interface direct relays egress through.
#[derive(Debug, Clone)]
pub(crate) struct BindInterface {
    /// Interface index, used by Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF`.
    pub index: u32,
    /// Interface name, used by Linux `SO_BINDTODEVICE`.
    pub name: String,
}

impl std::fmt::Display for BindInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} (index {})", self.name, self.index)
    }
}

impl BindInterface {
    fn from_netdev(iface: netdev::Interface) -> crate::Result<Self> {
        if iface.index == 0 {
            return Err(format!("network interface `{}` has an invalid index 0", iface.name).into());
        }
        Ok(Self {
            index: iface.index,
            name: iface.name,
        })
    }
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
        (IPPROTO_IP, IP_UNICAST_IF, iface.index.to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, iface.index)
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
