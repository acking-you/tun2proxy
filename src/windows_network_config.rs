//! Transactional Windows route and DNS setup.
//!
//! All routing changes use the IP Helper API.  In particular, this module
//! never deletes or rewrites the machine's existing default route.  Traffic is
//! captured with two more-specific `/1` routes, while proxy and user bypasses
//! are installed through the physical route selected before capture begins.

use std::{
    collections::HashSet,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use tproxy_config::{IpCidr, TproxyArgs};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, FreeLibrary, HMODULE, NO_ERROR},
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToGuid, CreateIpForwardEntry2, DNS_INTERFACE_SETTINGS,
                DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER, DeleteIpForwardEntry2, GetBestRoute2, IP_ADDRESS_PREFIX,
                InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
            },
            Ndis::NET_LUID_LH,
        },
        Networking::WinSock::{
            AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, MIB_IPPROTO_NETMGMT, NlroManual, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0,
            SOCKADDR_INET,
        },
        System::LibraryLoader::{GetProcAddress, LoadLibraryW},
    },
    core::GUID,
};

const CAPTURE_ROUTE_METRIC: u32 = 6;
const BYPASS_ROUTE_METRIC: u32 = 1;

type GetInterfaceDnsSettingsFn = unsafe extern "system" fn(GUID, *mut DNS_INTERFACE_SETTINGS) -> u32;
type SetInterfaceDnsSettingsFn = unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS) -> u32;
type FreeInterfaceDnsSettingsFn = unsafe extern "system" fn(*mut DNS_INTERFACE_SETTINGS);

/// The interface DNS APIs were added in Windows 10 version 2004. Loading them
/// dynamically keeps the executable launchable on older Windows releases and
/// turns an unsupported setup request into a useful runtime error instead of
/// a loader-time failure before argument parsing or logging can start.
struct InterfaceDnsApi {
    module: HMODULE,
    get: GetInterfaceDnsSettingsFn,
    set: SetInterfaceDnsSettingsFn,
    free: FreeInterfaceDnsSettingsFn,
}

impl InterfaceDnsApi {
    fn load() -> io::Result<Self> {
        let module = unsafe { LoadLibraryW(wide_string("iphlpapi.dll").as_ptr()) };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }

        let get = unsafe { GetProcAddress(module, c"GetInterfaceDnsSettings".as_ptr().cast()) };
        let set = unsafe { GetProcAddress(module, c"SetInterfaceDnsSettings".as_ptr().cast()) };
        let free = unsafe { GetProcAddress(module, c"FreeInterfaceDnsSettings".as_ptr().cast()) };
        let (Some(get), Some(set), Some(free)) = (get, set, free) else {
            unsafe { FreeLibrary(module) };
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "transactional Windows TUN DNS setup requires Windows 10 version 2004 (build 19041) or newer",
            ));
        };

        // GetProcAddress returns an untyped function address. These casts are
        // kept next to the exact SDK signatures above so their ABI is auditable.
        Ok(Self {
            module,
            get: unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, GetInterfaceDnsSettingsFn>(get) },
            set: unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, SetInterfaceDnsSettingsFn>(set) },
            free: unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, FreeInterfaceDnsSettingsFn>(free) },
        })
    }
}

impl Drop for InterfaceDnsApi {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.module) };
    }
}

/// An address retained in a route includes the IPv6 scope ID.  Discarding the
/// scope makes link-local physical gateways impossible to delete precisely.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RouteAddress {
    ip: IpAddr,
    scope_id: u32,
}

impl RouteAddress {
    const fn new(ip: IpAddr) -> Self {
        Self { ip, scope_id: 0 }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RouteSpec {
    destination: IpAddr,
    prefix_len: u8,
    next_hop: RouteAddress,
    interface_luid: u64,
    metric: u32,
}

impl fmt::Display for RouteSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{} via {} on LUID {:#x}, metric {}",
            self.destination, self.prefix_len, self.next_hop.ip, self.interface_luid, self.metric
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DnsSnapshot {
    name_servers: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddOutcome {
    Created,
    Preexisting,
}

trait NetworkOperations {
    fn interface_luid(&mut self, alias: &str) -> io::Result<u64>;
    fn best_route(&mut self, destination: IpAddr) -> io::Result<(u64, RouteAddress)>;
    fn create_route(&mut self, route: &RouteSpec) -> io::Result<AddOutcome>;
    fn delete_route(&mut self, route: &RouteSpec) -> io::Result<()>;
    fn snapshot_dns(&mut self, interface_luid: u64) -> io::Result<DnsSnapshot>;
    fn set_dns(&mut self, interface_luid: u64, name_servers: Option<&str>) -> io::Result<()>;
}

#[derive(Debug)]
struct InstallRecord {
    tun_luid: u64,
    dns_before: DnsSnapshot,
    dns_changed: bool,
    owned_routes: Vec<RouteSpec>,
    removed: bool,
}

/// Owns exactly the Windows network rows installed for one TUN session.
///
/// `Drop` is intentionally synchronous: cleanup must still run if the async
/// forwarding task exits with an error or its future is cancelled.
#[derive(Debug)]
pub(crate) struct WindowsNetworkConfig {
    record: InstallRecord,
}

impl WindowsNetworkConfig {
    pub(crate) fn install(args: &TproxyArgs) -> io::Result<Self> {
        let mut operations = IpHelperOperations;
        let record = install_transaction(&mut operations, args)?;
        Ok(Self { record })
    }

    pub(crate) fn remove(mut self) -> io::Result<()> {
        let mut operations = IpHelperOperations;
        cleanup_transaction(&mut operations, &mut self.record)
    }
}

impl Drop for WindowsNetworkConfig {
    fn drop(&mut self) {
        if self.record.removed {
            return;
        }
        log::warn!("Windows network configuration guard dropped before explicit teardown; restoring owned settings now");
        let mut operations = IpHelperOperations;
        if let Err(error) = cleanup_transaction(&mut operations, &mut self.record) {
            log::error!("Failed to fully restore Windows TUN network configuration during drop: {error}");
        }
    }
}

fn install_transaction<O: NetworkOperations>(operations: &mut O, args: &TproxyArgs) -> io::Result<InstallRecord> {
    log::info!(
        "Preparing transactional Windows TUN setup for adapter {:?}; existing default routes will be preserved",
        args.tun_name
    );

    let tun_luid = operations.interface_luid(&args.tun_name).map_err(|error| {
        contextual_error(
            "resolve the TUN adapter through ConvertInterfaceAliasToLuid; the adapter may not be ready or its name may conflict",
            error,
        )
    })?;
    let dns_before = operations
        .snapshot_dns(tun_luid)
        .map_err(|error| contextual_error("snapshot the TUN adapter DNS configuration before changing it", error))?;

    // Resolve every physical path before adding capture routes.  Looking it up
    // afterwards can select the TUN itself and create a forwarding loop.
    let mut bypass_cidrs = args.bypass_ips.clone();
    let proxy_ip = args.proxy_addr.ip();
    if !tproxy_config::is_private_ip(proxy_ip) && !bypass_cidrs.iter().any(|cidr| cidr.contains(&proxy_ip)) {
        let proxy_host = IpCidr::new_host(proxy_ip);
        log::info!("Automatically excluding remote proxy {proxy_host} from TUN capture to prevent a routing loop");
        bypass_cidrs.push(proxy_host);
    }

    let mut planned = Vec::with_capacity(bypass_cidrs.len() + 3);
    let mut unique = HashSet::new();
    for cidr in bypass_cidrs {
        if !unique.insert(cidr) {
            log::debug!("Skipping duplicate Windows bypass route {cidr}");
            continue;
        }
        if cidr.is_ipv4() && cidr.network_length() <= 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Windows bypass {cidr} is too broad for the two /1 TUN capture routes; use prefixes longer than /1"),
            ));
        }
        let destination = cidr.first_address();
        let probe = if destination.is_unspecified() {
            match destination {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V6(_) => "2606:4700:4700::1111".parse().expect("constant IPv6 address"),
            }
        } else {
            destination
        };
        let (physical_luid, next_hop) = operations.best_route(probe).map_err(|error| {
            contextual_error(
                &format!("resolve the physical route for bypass {cidr} before enabling TUN capture"),
                error,
            )
        })?;
        if physical_luid == tun_luid {
            return Err(io::Error::other(format!(
                "Bypass {cidr} resolves back to TUN adapter {:?}; remove stale TUN routes or choose a non-conflicting destination before retrying",
                args.tun_name
            )));
        }
        let route = RouteSpec {
            destination,
            prefix_len: cidr.network_length(),
            next_hop,
            interface_luid: physical_luid,
            metric: BYPASS_ROUTE_METRIC,
        };
        log::info!("Planned physical bypass route: {route}");
        planned.push(route);
    }

    if args.ipv4_default_route {
        let gateway = RouteAddress::new(args.tun_gateway);
        if !gateway.ip.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Windows IPv4 capture requires an IPv4 TUN gateway, got {}", gateway.ip),
            ));
        }
        // Keep an owned 0/0 row as well as the two /1 capture rows. Ordinary
        // host traffic follows the more-specific /1 rows, while forwarding
        // consumers such as WSL HNS NAT select their egress from actual
        // default-route rows when they initialize. The physical 0/0 remains
        // untouched and becomes effective again when this exact TUN row is
        // removed.
        planned.extend([
            RouteSpec {
                destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_len: 0,
                next_hop: gateway,
                interface_luid: tun_luid,
                metric: CAPTURE_ROUTE_METRIC,
            },
            RouteSpec {
                destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_len: 1,
                next_hop: gateway,
                interface_luid: tun_luid,
                metric: CAPTURE_ROUTE_METRIC,
            },
            RouteSpec {
                destination: IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
                prefix_len: 1,
                next_hop: gateway,
                interface_luid: tun_luid,
                metric: CAPTURE_ROUTE_METRIC,
            },
        ]);
    }
    if args.ipv6_default_route {
        log::warn!(
            "IPv6 TUN capture was requested, but this Windows adapter is configured with only an IPv4 gateway; preserving the existing IPv6 routes"
        );
    }

    let mut record = InstallRecord {
        tun_luid,
        dns_before,
        dns_changed: false,
        owned_routes: Vec::with_capacity(planned.len()),
        removed: false,
    };

    for route in planned {
        log::debug!("Creating Windows route with CreateIpForwardEntry2: {route}");
        match operations.create_route(&route) {
            Ok(AddOutcome::Created) => {
                log::info!("Installed Windows route owned by this TUN session: {route}");
                record.owned_routes.push(route);
            }
            Ok(AddOutcome::Preexisting) => {
                // Never claim an existing row: teardown must not delete routes
                // that this process did not create.
                log::warn!("Required Windows route already existed and will not be removed on teardown: {route}");
            }
            Err(error) => {
                let setup_error = contextual_error(&format!("create Windows route {route}"), error);
                return Err(rollback_after_setup_failure(operations, &mut record, setup_error));
            }
        }
    }

    record.dns_changed = true;
    // Point Windows at the DNS endpoint inside the TUN.  The userspace stack
    // then applies the selected direct/over-TCP/virtual DNS strategy.  Setting
    // a public resolver here would let Windows route DNS independently of that
    // strategy and is especially fragile with Fake-IP mode.
    if let Err(error) = operations.set_dns(tun_luid, Some(&args.tun_gateway.to_string())) {
        let setup_error = contextual_error(
            &format!("set DNS server {} on TUN adapter {:?}", args.tun_gateway, args.tun_name),
            error,
        );
        return Err(rollback_after_setup_failure(operations, &mut record, setup_error));
    }
    log::info!(
        "Windows TUN setup committed: {} owned route(s), DNS {}; original default routes remain untouched",
        record.owned_routes.len(),
        args.tun_gateway
    );
    Ok(record)
}

fn rollback_after_setup_failure<O: NetworkOperations>(operations: &mut O, record: &mut InstallRecord, setup_error: io::Error) -> io::Error {
    log::error!("Windows TUN setup failed; rolling back every change made by this transaction: {setup_error}");
    match cleanup_transaction(operations, record) {
        Ok(()) => setup_error,
        Err(first_rollback_error) => {
            // Failed rows and DNS state remain in `record`, so a transient IP
            // Helper failure can be retried without touching anything that the
            // first attempt already removed successfully.
            log::warn!("Initial Windows TUN rollback was incomplete; retrying the remaining owned changes once: {first_rollback_error}");
            match cleanup_transaction(operations, record) {
                Ok(()) => {
                    log::info!("Windows TUN rollback retry removed all remaining owned changes");
                    setup_error
                }
                Err(second_rollback_error) => io::Error::other(format!(
                    "{setup_error}; first rollback attempt reported: {first_rollback_error}; retry reported: {second_rollback_error}"
                )),
            }
        }
    }
}

fn cleanup_transaction<O: NetworkOperations>(operations: &mut O, record: &mut InstallRecord) -> io::Result<()> {
    if record.removed {
        log::debug!("Windows TUN network configuration was already removed; skipping duplicate teardown");
        return Ok(());
    }

    let mut failures = Vec::new();
    let mut failed_routes = Vec::new();
    for route in std::mem::take(&mut record.owned_routes).into_iter().rev() {
        log::debug!("Deleting exact Windows route owned by this TUN session: {route}");
        if let Err(error) = operations.delete_route(&route) {
            log::error!("Could not delete owned Windows route {route}: {error}");
            failures.push(format!("delete route {route}: {error}"));
            failed_routes.push(route);
        } else {
            log::info!("Removed owned Windows route: {route}");
        }
    }
    // Preserve installation order so a later retry still tears down in exact
    // reverse order.  Crucially, failed rows remain owned instead of being
    // forgotten and left on the machine until reboot.
    failed_routes.reverse();
    record.owned_routes = failed_routes;

    if record.dns_changed {
        log::debug!("Restoring previous DNS settings on TUN interface LUID {:#x}", record.tun_luid);
        if let Err(error) = operations.set_dns(record.tun_luid, record.dns_before.name_servers.as_deref()) {
            log::error!("Could not restore TUN adapter DNS settings: {error}");
            failures.push(format!("restore TUN DNS: {error}"));
        } else {
            log::info!("Restored previous TUN adapter DNS settings");
        }
        if failures.last().is_none_or(|failure| !failure.starts_with("restore TUN DNS:")) {
            record.dns_changed = false;
        }
    }

    if failures.is_empty() {
        record.removed = true;
        log::info!("Windows TUN network teardown completed without modifying any foreign default route");
        Ok(())
    } else {
        record.removed = false;
        Err(io::Error::other(failures.join("; ")))
    }
}

fn contextual_error(context: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("Failed to {context}: {error}"))
}

struct IpHelperOperations;

impl NetworkOperations for IpHelperOperations {
    fn interface_luid(&mut self, alias: &str) -> io::Result<u64> {
        let alias = wide_string(alias);
        let mut luid = NET_LUID_LH::default();
        let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) };
        win32_result(status)?;
        Ok(unsafe { luid.Value })
    }

    fn best_route(&mut self, destination: IpAddr) -> io::Result<(u64, RouteAddress)> {
        let destination = sockaddr(destination, 0);
        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        let status = unsafe { GetBestRoute2(std::ptr::null(), 0, std::ptr::null(), &destination, 0, &mut route, &mut source) };
        win32_result(status)?;
        let luid = unsafe { route.InterfaceLuid.Value };
        let next_hop = route_address(&route.NextHop)?;
        log::debug!(
            "GetBestRoute2 selected physical interface LUID {luid:#x}, next hop {} for {}",
            next_hop.ip,
            route_address(&destination)?.ip
        );
        Ok((luid, next_hop))
    }

    fn create_route(&mut self, route: &RouteSpec) -> io::Result<AddOutcome> {
        let row = route_row(route);
        let status = unsafe { CreateIpForwardEntry2(&row) };
        if status == ERROR_OBJECT_ALREADY_EXISTS {
            return Ok(AddOutcome::Preexisting);
        }
        win32_result(status)?;
        Ok(AddOutcome::Created)
    }

    fn delete_route(&mut self, route: &RouteSpec) -> io::Result<()> {
        let row = route_row(route);
        let status = unsafe { DeleteIpForwardEntry2(&row) };
        if status == ERROR_NOT_FOUND {
            log::debug!("Owned route was already absent during idempotent teardown: {route}");
            return Ok(());
        }
        win32_result(status)
    }

    fn snapshot_dns(&mut self, interface_luid: u64) -> io::Result<DnsSnapshot> {
        let api = InterfaceDnsApi::load()?;
        let guid = luid_to_guid(interface_luid)?;
        let mut settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            ..Default::default()
        };
        let status = unsafe { (api.get)(guid, &mut settings) };
        win32_result(status)?;
        let snapshot = DnsSnapshot {
            name_servers: unsafe { optional_wide_string(settings.NameServer) },
        };
        unsafe { (api.free)(&mut settings) };
        log::debug!("Snapshotted TUN DNS name servers: {:?}", snapshot.name_servers);
        Ok(snapshot)
    }

    fn set_dns(&mut self, interface_luid: u64, name_servers: Option<&str>) -> io::Result<()> {
        let api = InterfaceDnsApi::load()?;
        let guid = luid_to_guid(interface_luid)?;
        let mut encoded = name_servers.map(wide_string);
        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            NameServer: encoded.as_mut().map_or(std::ptr::null_mut(), |value| value.as_mut_ptr()),
            ..Default::default()
        };
        let status = unsafe { (api.set)(guid, &settings) };
        win32_result(status)
    }
}

fn route_row(route: &RouteSpec) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH {
        Value: route.interface_luid,
    };
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr(route.destination, 0),
        PrefixLength: route.prefix_len,
    };
    row.NextHop = sockaddr(route.next_hop.ip, route.next_hop.scope_id);
    row.Metric = route.metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Origin = NlroManual;
    row
}

fn sockaddr(ip: IpAddr, scope_id: u32) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(ip) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(ip) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: windows_sys::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: ip.octets() },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: scope_id },
            },
        },
    }
}

fn route_address(address: &SOCKADDR_INET) -> io::Result<RouteAddress> {
    let family = unsafe { address.si_family };
    match family {
        AF_INET => {
            let address = unsafe { address.Ipv4 };
            let raw = unsafe { address.sin_addr.S_un.S_addr };
            Ok(RouteAddress::new(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))))
        }
        AF_INET6 => {
            let address = unsafe { address.Ipv6 };
            let octets = unsafe { address.sin6_addr.u.Byte };
            Ok(RouteAddress {
                ip: IpAddr::V6(Ipv6Addr::from(octets)),
                scope_id: unsafe { address.Anonymous.sin6_scope_id },
            })
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("IP Helper returned unsupported address family {other}"),
        )),
    }
}

fn luid_to_guid(luid: u64) -> io::Result<GUID> {
    let luid = NET_LUID_LH { Value: luid };
    let mut guid = GUID::default();
    let status = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    win32_result(status)?;
    Ok(guid)
}

fn win32_result(status: u32) -> io::Result<()> {
    if status == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn wide_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn optional_wide_string(value: *const u16) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let mut len = 0;
    while unsafe { *value.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(value, len) };
    Some(String::from_utf16_lossy(slice))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, str::FromStr};

    #[derive(Default)]
    struct MockOperations {
        events: Vec<String>,
        add_results: VecDeque<io::Result<AddOutcome>>,
        delete_failures_remaining: usize,
        dns_failure: bool,
        best_route_luid: Option<u64>,
    }

    impl NetworkOperations for MockOperations {
        fn interface_luid(&mut self, alias: &str) -> io::Result<u64> {
            self.events.push(format!("luid:{alias}"));
            Ok(0x55)
        }

        fn best_route(&mut self, destination: IpAddr) -> io::Result<(u64, RouteAddress)> {
            self.events.push(format!("best:{destination}"));
            Ok((
                self.best_route_luid.unwrap_or(0x77),
                RouteAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            ))
        }

        fn create_route(&mut self, route: &RouteSpec) -> io::Result<AddOutcome> {
            self.events.push(format!("add:{}/{}", route.destination, route.prefix_len));
            self.add_results.pop_front().unwrap_or(Ok(AddOutcome::Created))
        }

        fn delete_route(&mut self, route: &RouteSpec) -> io::Result<()> {
            self.events.push(format!("delete:{}/{}", route.destination, route.prefix_len));
            if self.delete_failures_remaining > 0 {
                self.delete_failures_remaining -= 1;
                Err(io::Error::other("injected delete failure"))
            } else {
                Ok(())
            }
        }

        fn snapshot_dns(&mut self, _: u64) -> io::Result<DnsSnapshot> {
            self.events.push("dns:snapshot".into());
            Ok(DnsSnapshot {
                name_servers: Some("9.9.9.9".into()),
            })
        }

        fn set_dns(&mut self, _: u64, name_servers: Option<&str>) -> io::Result<()> {
            self.events.push(format!("dns:set:{name_servers:?}"));
            if self.dns_failure && name_servers != Some("9.9.9.9") {
                Err(io::Error::other("injected DNS failure"))
            } else {
                Ok(())
            }
        }
    }

    fn test_args() -> TproxyArgs {
        TproxyArgs::new()
            .tun_name("test-tun")
            .proxy_addr("203.0.113.8:1080".parse().unwrap())
            .bypass_ips(&[IpCidr::from_str("192.0.2.0/24").unwrap()])
    }

    #[test]
    fn adds_owned_default_for_forwarding_consumers_and_preserves_physical_route() {
        let mut operations = MockOperations::default();
        let mut record = install_transaction(&mut operations, &test_args()).unwrap();

        assert!(operations.events.contains(&"add:0.0.0.0/0".into()));
        assert!(operations.events.contains(&"add:0.0.0.0/1".into()));
        assert!(operations.events.contains(&"add:128.0.0.0/1".into()));
        assert_eq!(record.owned_routes.len(), 5); // explicit bypass, proxy host, compatibility 0/0, and two /1 capture rows

        cleanup_transaction(&mut operations, &mut record).unwrap();
        let deletes: Vec<_> = operations
            .events
            .iter()
            .filter(|event| event.starts_with("delete:"))
            .cloned()
            .collect();
        assert_eq!(
            deletes,
            [
                "delete:128.0.0.0/1",
                "delete:0.0.0.0/1",
                "delete:0.0.0.0/0",
                "delete:203.0.113.8/32",
                "delete:192.0.2.0/24"
            ]
        );
        assert_eq!(operations.events.last().unwrap(), "dns:set:Some(\"9.9.9.9\")");
    }

    #[test]
    fn rollback_deletes_only_routes_created_by_this_transaction() {
        let mut operations = MockOperations {
            add_results: VecDeque::from([
                Ok(AddOutcome::Preexisting),
                Ok(AddOutcome::Created),
                Err(io::Error::other("injected create failure")),
            ]),
            ..Default::default()
        };

        let error = install_transaction(&mut operations, &test_args()).unwrap_err();
        assert!(error.to_string().contains("injected create failure"));
        let deletes: Vec<_> = operations
            .events
            .iter()
            .filter(|event| event.starts_with("delete:"))
            .cloned()
            .collect();
        assert_eq!(deletes, ["delete:203.0.113.8/32"]);
        assert!(!operations.events.iter().any(|event| event == "delete:192.0.2.0/24"));
    }

    #[test]
    fn dns_failure_restores_dns_and_rolls_routes_back_in_reverse_order() {
        let mut operations = MockOperations {
            dns_failure: true,
            ..Default::default()
        };

        let error = install_transaction(&mut operations, &test_args()).unwrap_err();
        assert!(error.to_string().contains("injected DNS failure"));
        let deletes: Vec<_> = operations
            .events
            .iter()
            .filter(|event| event.starts_with("delete:"))
            .cloned()
            .collect();
        assert_eq!(
            deletes,
            [
                "delete:128.0.0.0/1",
                "delete:0.0.0.0/1",
                "delete:0.0.0.0/0",
                "delete:203.0.113.8/32",
                "delete:192.0.2.0/24"
            ]
        );
        assert_eq!(operations.events.last().unwrap(), "dns:set:Some(\"9.9.9.9\")");
    }

    #[test]
    fn setup_rollback_retries_only_the_owned_route_that_failed_to_delete() {
        let mut operations = MockOperations {
            add_results: VecDeque::from([
                Ok(AddOutcome::Created),
                Ok(AddOutcome::Created),
                Err(io::Error::other("injected create failure")),
            ]),
            delete_failures_remaining: 1,
            ..Default::default()
        };

        let error = install_transaction(&mut operations, &test_args()).unwrap_err();
        assert!(error.to_string().contains("injected create failure"));
        let deletes: Vec<_> = operations
            .events
            .iter()
            .filter(|event| event.starts_with("delete:"))
            .cloned()
            .collect();
        assert_eq!(deletes, ["delete:203.0.113.8/32", "delete:192.0.2.0/24", "delete:203.0.113.8/32"]);
    }

    #[test]
    fn teardown_attempts_dns_restore_even_when_route_deletion_fails() {
        let mut operations = MockOperations::default();
        let mut record = install_transaction(&mut operations, &test_args()).unwrap();
        operations.delete_failures_remaining = record.owned_routes.len();

        let error = cleanup_transaction(&mut operations, &mut record).unwrap_err();
        assert!(error.to_string().contains("injected delete failure"));
        assert_eq!(operations.events.last().unwrap(), "dns:set:Some(\"9.9.9.9\")");
        assert!(!record.removed);
        assert_eq!(record.owned_routes.len(), 5);
    }

    #[test]
    fn rejects_bypass_that_routes_back_into_the_tun() {
        let mut operations = MockOperations {
            best_route_luid: Some(0x55),
            ..Default::default()
        };

        let error = install_transaction(&mut operations, &test_args()).unwrap_err();

        assert!(error.to_string().contains("resolves back to TUN adapter"));
        assert!(!operations.events.iter().any(|event| event.starts_with("add:")));
    }

    #[test]
    fn rejects_bypass_prefixes_that_cannot_outrank_capture_routes() {
        for cidr in ["0.0.0.0/0", "128.0.0.0/1"] {
            let args = TproxyArgs::new()
                .tun_name("test-tun")
                .proxy_addr("127.0.0.1:1080".parse().unwrap())
                .bypass_ips(&[IpCidr::from_str(cidr).unwrap()]);
            let mut operations = MockOperations::default();

            let error = install_transaction(&mut operations, &args).unwrap_err();

            assert!(error.to_string().contains("too broad"));
            assert!(!operations.events.iter().any(|event| event.starts_with("add:")));
        }
    }
}
