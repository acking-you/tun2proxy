use crate::Result;
use socks5_impl::ProxyParameters;
use std::net::IpAddr;
use std::str::FromStr;
use tproxy_config::IpCidr;

#[macro_export]
macro_rules! version_info {
    () => {
        concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_HASH"), " ", env!("BUILD_TIME"), ")")
    };
}

fn about_info() -> &'static str {
    concat!("Tunnel interface to proxy.\nVersion: ", version_info!())
}

#[derive(Debug, Clone, clap::Parser, serde::Serialize, serde::Deserialize)]
#[command(author, version = version_info!(), about = about_info(), long_about = None)]
pub struct Args {
    /// Proxy URL in the form proto://[username[:password]@]host:port,
    /// where proto is one of socks4, socks5, http.
    /// Username and password are encoded in percent encoding. For example:
    /// socks5://myname:pass%40word@127.0.0.1:1080
    #[arg(short, long, value_parser = |s: &str| ProxyParameters::try_from(s), value_name = "URL")]
    pub proxy: ProxyParameters,

    /// Name of the tun interface, such as tun0, utun4, etc.
    /// If this option is not provided, the OS will generate a random one.
    #[arg(short, long, value_name = "name", value_parser = validate_tun)]
    #[cfg_attr(unix, arg(conflicts_with = "tun_fd"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun: Option<String>,

    /// File descriptor of the tun interface
    #[cfg(unix)]
    #[arg(long, value_name = "fd", conflicts_with = "tun")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_fd: Option<i32>,

    /// Close the received file descriptor on drop (requires --tun-fd).
    #[cfg(unix)]
    #[arg(long, value_name = "BOOL", conflicts_with = "tun", requires = "tun_fd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_fd_on_drop: Option<bool>,

    /// Create a tun interface in a newly created unprivileged namespace
    /// while maintaining proxy connectivity via the global network namespace.
    #[cfg(all(target_os = "linux", feature = "unshare"))]
    #[arg(long)]
    pub unshare: bool,

    /// Create a pidfile of `unshare` process when using `--unshare`.
    #[cfg(all(target_os = "linux", feature = "unshare"))]
    #[arg(long, value_name = "path")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unshare_pidfile: Option<String>,

    /// File descriptor for UNIX datagram socket meant to transfer
    /// network sockets from global namespace to the new one.
    /// See `unshare(1)`, `namespaces(7)`, `sendmsg(2)`, `unix(7)`.
    #[cfg(all(target_os = "linux", feature = "unshare"))]
    #[arg(long, value_name = "fd", hide(true))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_transfer_fd: Option<i32>,

    /// Specify a command to run with root-like capabilities in the new namespace
    /// when using `--unshare`.
    /// This could be useful to start additional daemons, e.g. `openvpn` instance.
    #[cfg(all(target_os = "linux", feature = "unshare"))]
    #[arg(requires = "unshare")]
    pub admin_command: Vec<std::ffi::OsString>,

    /// IPv6 enabled
    #[arg(short = '6', long)]
    pub ipv6_enabled: bool,

    /// Routing and system setup, which decides whether to setup the routing and system configuration.
    /// This option requires root-like privileges on every platform. The Windows
    /// binary automatically requests elevation through UAC when necessary.
    /// It is very important on Linux, see `capabilities(7)`.
    #[arg(short, long)]
    pub setup: bool,

    /// Internal console owner used while a Windows child is elevating.
    #[cfg(windows)]
    #[doc(hidden)]
    #[arg(long, hide = true, value_name = "PID")]
    #[serde(skip)]
    pub elevated_console_pid: Option<u32>,

    /// In-process controller for live upstream host routes; never serialized.
    #[cfg(windows)]
    #[arg(skip)]
    #[serde(skip)]
    pub upstream_bypass: Option<crate::WindowsRouteBypass>,

    /// DNS handling strategy
    #[arg(short, long, value_name = "strategy", value_enum, default_value = "direct")]
    pub dns: ArgDns,

    /// DNS resolver address
    #[arg(long, value_name = "IP", default_value = "8.8.8.8")]
    pub dns_addr: IpAddr,

    /// IP address pool to be used by virtual DNS in CIDR notation.
    #[arg(long, value_name = "CIDR", default_value = "198.18.0.0/15")]
    pub virtual_dns_pool: IpCidr,

    /// Addresses advertised by an embedding platform as local virtual DNS
    /// portals. TCP and UDP port 53 are answered by virtual DNS. Opportunistic
    /// DNS-over-TLS probes to these addresses are rejected locally so the OS
    /// can immediately fall back to plain DNS instead of proxying an
    /// unreachable private address.
    #[arg(long = "virtual-dns-portal", value_name = "IP")]
    #[serde(default)]
    pub virtual_dns_portals: Vec<IpAddr>,

    /// IPs used in routing setup which should bypass the tunnel,
    /// in the form of IP or IP/CIDR. Multiple IPs can be specified,
    /// e.g. --bypass 3.4.5.0/24 --bypass 5.6.7.8
    #[arg(short, long, value_name = "IP/CIDR")]
    pub bypass: Vec<IpCidr>,

    /// Relay sessions originating from the named local process directly to their
    /// destination instead of forwarding them to the proxy. The match is on the
    /// executable file name (case-insensitive), e.g. `--bypass-process curl` or
    /// `--bypass-process my-proxy.exe`. Repeatable. This is primarily meant to
    /// break routing loops when the upstream proxy is a local loopback service:
    /// the proxy's own outbound traffic gets captured by the TUN, and without
    /// this option it would be fed back into the proxy forever. Only implemented
    /// on Windows and Linux; ignored elsewhere.
    #[arg(long, value_name = "PROCESS")]
    pub bypass_process: Vec<String>,

    /// Physical network interface used to egress process-bypass direct relays
    /// (see `--bypass-process`). Direct-relayed sockets must leave through the
    /// real interface, otherwise they are re-captured by the TUN and the loop is
    /// merely moved one hop. When omitted, the default route interface is
    /// auto-detected. Only relevant on Windows and Linux.
    #[arg(long, value_name = "name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,

    /// MTU of the TUN device. Userspace TCP stack uses (MTU - 40) as the
    /// effective MSS for synthesized segments going to the kernel side, so
    /// lower this when the kernel forwards the traffic onwards through a
    /// link with a smaller MTU (e.g. a WireGuard tunnel at 1420) to avoid
    /// having the bigger segments silently dropped.
    #[arg(long, value_name = "bytes", default_value_t = crate::DEFAULT_MTU)]
    pub mtu: u16,

    /// TCP timeout in seconds
    #[arg(long, value_name = "seconds", default_value = "600")]
    pub tcp_timeout: u64,

    /// MSS advertised in the SYN-ACK to the kernel side. By default the userspace
    /// stack sends no MSS option, so the peer OS falls back to its own default
    /// (e.g. 512 on macOS), fragmenting large first segments such as a TLS
    /// ClientHello. Set this to the tunnel's (MTU - 40) to let the peer send big
    /// segments. `None` keeps the previous behaviour (no option advertised).
    #[arg(long, value_name = "bytes")]
    pub tcp_mss: Option<u16>,

    /// UDP timeout in seconds
    #[arg(long, value_name = "seconds", default_value = "10")]
    pub udp_timeout: u64,

    /// Handling strategy for non-DNS UDP sessions. `proxy` forwards them via
    /// the configured proxy, `direct` sends them without using the proxy, and
    /// `block` discards them. DNS continues to follow `--dns`.
    #[arg(long, value_name = "strategy", value_enum, default_value = "proxy")]
    #[serde(default)]
    pub udp_strategy: ArgUdpStrategy,

    /// Optional in-process destination policy. Not serialized or exposed by the CLI.
    #[arg(skip)]
    #[serde(skip)]
    pub udp_router: Option<std::sync::Arc<dyn crate::UdpRouter>>,

    /// Relay ICMP Echo through proxy-everything's loopback SOCKS5 extension.
    /// This is not supported by ordinary SOCKS5 servers.
    #[arg(long)]
    #[serde(default)]
    pub icmp_echo: bool,

    /// Daemonize for unix family or run as Windows service
    #[arg(long)]
    pub daemonize: bool,

    /// Exit immediately when fatal error occurs, useful for running as a service
    #[arg(long)]
    pub exit_on_fatal_error: bool,

    /// Maximum number of sessions to be handled concurrently
    #[arg(long, value_name = "number", default_value = "200")]
    pub max_sessions: usize,

    /// Per-session TCP read buffer, in bytes. Zero keeps the ipstack default.
    ///
    /// Every admitted session holds one of these for as long as it lives, and
    /// `tcp_timeout` keeps idle sessions around for minutes, so this multiplies
    /// straight into the resident set of a busy device.
    #[arg(long, value_name = "bytes", default_value = "0")]
    pub tcp_read_buffer_size: usize,

    /// UDP gateway server address, forwards UDP packets via specified TCP server
    #[cfg(feature = "udpgw")]
    #[arg(long, value_name = "IP:PORT")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udpgw_server: Option<std::net::SocketAddr>,

    /// Max connections for the UDP gateway, default value is 5
    #[cfg(feature = "udpgw")]
    #[arg(long, value_name = "number", requires = "udpgw_server")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udpgw_connections: Option<usize>,

    /// Keepalive interval in seconds for the UDP gateway, default value is 30
    #[cfg(feature = "udpgw")]
    #[arg(long, value_name = "seconds", requires = "udpgw_server")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udpgw_keepalive: Option<u64>,

    /// Verbosity level, possible values [off, error, warn, info, debug, trace]
    #[arg(short, long, value_name = "level", default_value = "info")]
    pub verbosity: log::LevelFilter,
}

fn validate_tun(p: &str) -> Result<String> {
    #[cfg(target_os = "macos")]
    if p.len() <= 4 || &p[..4] != "utun" {
        return Err(crate::Error::from("Invalid tun interface name, please use utunX"));
    }
    Ok(p.to_string())
}

impl Default for Args {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        let setup = false;
        #[cfg(not(target_os = "linux"))]
        let setup = true;
        Args {
            proxy: ProxyParameters::default(),
            tun: None,
            #[cfg(unix)]
            tun_fd: None,
            #[cfg(unix)]
            close_fd_on_drop: None,
            #[cfg(all(target_os = "linux", feature = "unshare"))]
            unshare: false,
            #[cfg(all(target_os = "linux", feature = "unshare"))]
            unshare_pidfile: None,
            #[cfg(all(target_os = "linux", feature = "unshare"))]
            socket_transfer_fd: None,
            #[cfg(all(target_os = "linux", feature = "unshare"))]
            admin_command: Vec::new(),
            ipv6_enabled: false,
            setup,
            #[cfg(windows)]
            elevated_console_pid: None,
            #[cfg(windows)]
            upstream_bypass: None,
            dns: ArgDns::default(),
            dns_addr: "8.8.8.8".parse().unwrap(),
            bypass: vec![],
            bypass_process: vec![],
            bind_interface: None,
            mtu: crate::DEFAULT_MTU,
            tcp_timeout: 600,
            tcp_mss: None,
            udp_timeout: 10,
            udp_strategy: ArgUdpStrategy::default(),
            udp_router: None,
            icmp_echo: false,
            verbosity: log::LevelFilter::Info,
            virtual_dns_pool: IpCidr::from_str("198.18.0.0/15").unwrap(),
            virtual_dns_portals: vec![],
            daemonize: false,
            exit_on_fatal_error: false,
            max_sessions: 200,
            tcp_read_buffer_size: 0,
            #[cfg(feature = "udpgw")]
            udpgw_server: None,
            #[cfg(feature = "udpgw")]
            udpgw_connections: None,
            #[cfg(feature = "udpgw")]
            udpgw_keepalive: None,
        }
    }
}

impl Args {
    #[allow(clippy::let_and_return)]
    pub fn parse_args() -> Self {
        let args = <Self as ::clap::Parser>::parse();
        #[cfg(target_os = "linux")]
        if !args.setup && args.tun.is_none() {
            eprintln!("Missing required argument, '--tun' must present when '--setup' is not used.");
            std::process::exit(-1);
        }
        args
    }

    pub fn proxy(&mut self, proxy: ProxyParameters) -> &mut Self {
        self.proxy = proxy;
        self
    }

    pub fn dns(&mut self, dns: ArgDns) -> &mut Self {
        self.dns = dns;
        self
    }

    #[cfg(feature = "udpgw")]
    pub fn udpgw_server(&mut self, udpgw: std::net::SocketAddr) -> &mut Self {
        self.udpgw_server = Some(udpgw);
        self
    }

    #[cfg(feature = "udpgw")]
    pub fn udpgw_connections(&mut self, udpgw_connections: usize) -> &mut Self {
        self.udpgw_connections = Some(udpgw_connections);
        self
    }

    #[cfg(unix)]
    pub fn tun_fd(&mut self, tun_fd: Option<i32>) -> &mut Self {
        self.tun_fd = tun_fd;
        self
    }

    #[cfg(unix)]
    pub fn close_fd_on_drop(&mut self, close_fd_on_drop: bool) -> &mut Self {
        self.close_fd_on_drop = Some(close_fd_on_drop);
        self
    }

    pub fn verbosity(&mut self, verbosity: log::LevelFilter) -> &mut Self {
        self.verbosity = verbosity;
        self
    }

    pub fn tun(&mut self, tun: String) -> &mut Self {
        self.tun = Some(tun);
        self
    }

    pub fn dns_addr(&mut self, dns_addr: IpAddr) -> &mut Self {
        self.dns_addr = dns_addr;
        self
    }

    pub fn bypass(&mut self, bypass: IpCidr) -> &mut Self {
        self.bypass.push(bypass);
        self
    }

    pub fn ipv6_enabled(&mut self, ipv6_enabled: bool) -> &mut Self {
        self.ipv6_enabled = ipv6_enabled;
        self
    }

    pub fn setup(&mut self, setup: bool) -> &mut Self {
        self.setup = setup;
        self
    }
}

/// DNS query handling strategy
/// - Virtual: Use a virtual DNS server to handle DNS queries, also known as Fake-IP mode
/// - OverTcp: Use TCP to send DNS queries to the DNS server
/// - Direct: Do not handle DNS by relying on DNS server bypassing
/// - Physical: Resolve through ordered local resolvers on the physical interface (desktop only)
#[repr(C)]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
pub enum ArgDns {
    Virtual = 0,
    OverTcp,
    #[default]
    Direct,
    Physical,
}

#[cfg(target_os = "android")]
impl TryFrom<jni::sys::jint> for ArgDns {
    type Error = crate::Error;
    fn try_from(value: jni::sys::jint) -> Result<Self> {
        match value {
            0 => Ok(ArgDns::Virtual),
            1 => Ok(ArgDns::OverTcp),
            2 => Ok(ArgDns::Direct),
            _ => Err(crate::Error::from("Invalid DNS strategy")),
        }
    }
}

/// Non-DNS UDP handling strategy.
#[repr(C)]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
pub enum ArgUdpStrategy {
    #[default]
    Proxy = 0,
    Direct,
    Block,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn cli_and_programmatic_defaults_use_a_routable_mtu() {
        let cli = Args::parse_from(["tun2proxy", "--proxy", "socks5://127.0.0.1:1080"]);

        assert_eq!(crate::DEFAULT_MTU, 1500);
        assert_eq!(cli.mtu, crate::DEFAULT_MTU);
        assert_eq!(Args::default().mtu, crate::DEFAULT_MTU);
    }

    #[test]
    fn udp_strategy_defaults_to_proxy_and_accepts_fallback_policies() {
        let default_args = Args::parse_from(["tun2proxy", "--proxy", "socks5://127.0.0.1:1080"]);
        let direct_args = Args::parse_from(["tun2proxy", "--proxy", "socks5://127.0.0.1:1080", "--udp-strategy", "direct"]);
        let block_args = Args::parse_from(["tun2proxy", "--proxy", "socks5://127.0.0.1:1080", "--udp-strategy", "block"]);

        assert_eq!(default_args.udp_strategy, ArgUdpStrategy::Proxy);
        assert_eq!(Args::default().udp_strategy, ArgUdpStrategy::Proxy);
        assert_eq!(direct_args.udp_strategy, ArgUdpStrategy::Direct);
        assert_eq!(block_args.udp_strategy, ArgUdpStrategy::Block);
    }

    #[test]
    fn virtual_dns_portals_default_empty_and_accept_multiple_addresses() {
        let default_args = Args::parse_from(["tun2proxy", "--proxy", "socks5://127.0.0.1:1080"]);
        let configured = Args::parse_from([
            "tun2proxy",
            "--proxy",
            "socks5://127.0.0.1:1080",
            "--virtual-dns-portal",
            "172.19.0.2",
            "--virtual-dns-portal",
            "fdfe:dcba:9876::2",
        ]);

        assert!(default_args.virtual_dns_portals.is_empty());
        assert!(Args::default().virtual_dns_portals.is_empty());
        assert_eq!(
            configured.virtual_dns_portals,
            vec![
                "172.19.0.2".parse::<IpAddr>().unwrap(),
                "fdfe:dcba:9876::2".parse::<IpAddr>().unwrap(),
            ]
        );
    }
}
