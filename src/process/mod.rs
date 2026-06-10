//! Source-process lookup used by the `--bypass-process` feature.
//!
//! Given a session whose source address was observed on the TUN device, we map
//! the `(protocol, local addr, local port)` tuple back to the owning OS process
//! and compare its executable name against a user-supplied bypass list. This is
//! the tun2proxy equivalent of clash/mihomo's `PROCESS-NAME` rule and is used to
//! relay a local loopback proxy's own outbound traffic directly, breaking the
//! routing loop it would otherwise create.
//!
//! Only implemented on Windows and Linux; the module is not compiled elsewhere.

use crate::session_info::IpProtocol;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
mod imp;

/// How long a socket-table snapshot is proactively reused before it is
/// refreshed. The OS table walk costs a few milliseconds, so we avoid doing it
/// on every session while still reacting quickly to newly-spawned connections.
const SNAPSHOT_TTL: Duration = Duration::from_millis(1_000);

/// On a lookup *miss*, the cached snapshot may simply predate a just-created
/// socket (the kernel registers the socket at `connect()` time, before the
/// packet ever reaches the TUN). We then force one extra refresh-and-retry,
/// but no more often than this, so a flood of genuinely non-matching sessions
/// cannot turn every lookup into a table walk.
const MISS_REFRESH_MIN_AGE: Duration = Duration::from_millis(50);

/// One row of the OS socket table relevant to bypass matching.
#[derive(Debug, Clone)]
struct SocketEntry {
    protocol: IpProtocol,
    local: SocketAddr,
    pids: Vec<u32>,
}

#[derive(Default)]
struct Cache {
    fetched_at: Option<Instant>,
    entries: Vec<SocketEntry>,
    /// Resolved `pid -> executable basename`, memoized within one snapshot and
    /// cleared on every refresh. Note the name is resolved live (against the
    /// running process) the first time a PID is consulted, so there is a small,
    /// self-healing window in which a PID recycled since the snapshot was taken
    /// could resolve to a different executable. The bypass decision still cannot
    /// create a loop in that case, because a bypassed relay is always pinned to
    /// the physical interface regardless.
    pid_names: HashMap<u32, Option<String>>,
}

/// Matches sessions against a set of process names to be relayed directly.
pub(crate) struct ProcessMatcher {
    /// Normalized (lower-cased, `.exe` stripped) names to match against.
    names: Vec<String>,
    cache: Mutex<Cache>,
}

impl ProcessMatcher {
    /// Build a matcher from the raw `--bypass-process` values. Returns `None`
    /// when the list is empty (feature disabled, zero overhead).
    pub(crate) fn new(names: &[String]) -> Option<Self> {
        let names: Vec<String> = names.iter().map(|n| normalize_name(n)).filter(|n| !n.is_empty()).collect();
        if names.is_empty() {
            return None;
        }
        Some(Self {
            names,
            cache: Mutex::new(Cache::default()),
        })
    }

    /// Returns true if the session originating at `src` belongs to a process in
    /// the bypass list. Runs the (briefly blocking) OS table walk on the
    /// blocking pool so it never stalls the async accept loop.
    pub(crate) async fn matches(self: &std::sync::Arc<Self>, protocol: IpProtocol, src: SocketAddr) -> bool {
        let this = self.clone();
        match tokio::task::spawn_blocking(move || this.matches_blocking(protocol, src)).await {
            Ok(result) => result,
            Err(err) => {
                log::warn!("process bypass lookup task failed: {err}");
                false
            }
        }
    }

    fn matches_blocking(&self, protocol: IpProtocol, src: SocketAddr) -> bool {
        let mut cache = match self.cache.lock() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.refresh_if_stale(&mut cache);
        if self.match_in_cache(&mut cache, protocol, src) {
            return true;
        }
        // A miss may just mean our cached table predates this freshly-created
        // socket. Since misrouting the proxy's own connection re-creates the very
        // loop this feature prevents, force one bounded refresh and retry.
        let stale_enough = cache.fetched_at.map(|at| at.elapsed() >= MISS_REFRESH_MIN_AGE).unwrap_or(true);
        if stale_enough {
            self.refresh(&mut cache);
            return self.match_in_cache(&mut cache, protocol, src);
        }
        false
    }

    /// Look the session up against the current snapshot, resolving and memoizing
    /// candidate process names. Does not refresh the snapshot.
    fn match_in_cache(&self, cache: &mut Cache, protocol: IpProtocol, src: SocketAddr) -> bool {
        // Collect candidate PIDs first to avoid borrowing `cache.entries` and
        // `cache.pid_names` simultaneously.
        let pids = candidate_pids(&cache.entries, protocol, src);
        for pid in pids {
            let name = cache
                .pid_names
                .entry(pid)
                .or_insert_with(|| imp::process_name(pid).map(|n| normalize_name(&n)));
            if let Some(name) = name {
                if self.names.iter().any(|wanted| wanted == name) {
                    log::debug!("bypassing {protocol} session from {src} owned by process `{name}` (pid {pid})");
                    return true;
                }
            }
        }
        false
    }

    fn refresh_if_stale(&self, cache: &mut Cache) {
        let fresh = cache.fetched_at.map(|at| at.elapsed() < SNAPSHOT_TTL).unwrap_or(false);
        if !fresh {
            self.refresh(cache);
        }
    }

    fn refresh(&self, cache: &mut Cache) {
        match snapshot() {
            Ok(entries) => {
                cache.entries = entries;
                cache.pid_names.clear();
                cache.fetched_at = Some(Instant::now());
            }
            Err(err) => {
                // Keep the previous snapshot (if any) rather than failing the
                // session; log once per refresh attempt.
                log::warn!("failed to read OS socket table for process bypass: {err}");
                cache.fetched_at = Some(Instant::now());
            }
        }
    }
}

/// Take a fresh snapshot of the host TCP/UDP socket tables (IPv4 + IPv6) via
/// `netstat2`, keeping only the fields needed for bypass matching.
fn snapshot() -> crate::Result<Vec<SocketEntry>> {
    use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};

    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets = get_sockets_info(af_flags, proto_flags).map_err(|e| crate::Error::from(e.to_string()))?;

    let entries = sockets
        .into_iter()
        .map(|si| {
            let pids = si.associated_pids;
            let (protocol, local) = match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => (IpProtocol::Tcp, SocketAddr::new(tcp.local_addr, tcp.local_port)),
                ProtocolSocketInfo::Udp(udp) => (IpProtocol::Udp, SocketAddr::new(udp.local_addr, udp.local_port)),
            };
            SocketEntry { protocol, local, pids }
        })
        .collect();
    Ok(entries)
}

/// Lower-case and drop a trailing `.exe` so `curl` matches `curl.exe` and vice
/// versa across platforms.
fn normalize_name(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// PIDs of the socket(s) that plausibly originated `src`.
///
/// A TCP outbound socket always carries a concrete local IP, so we require an
/// exact IP+port match and never fall back to a wildcard (`0.0.0.0`/`::`) row —
/// that avoids matching an unrelated listener that merely shares the port. UDP
/// table rows often lack a concrete local IP (Windows reports `0.0.0.0` for
/// connected client sockets), so for UDP we prefer a concrete-IP match but fall
/// back to unspecified-IP rows on the same port when none is found.
fn candidate_pids(entries: &[SocketEntry], protocol: IpProtocol, src: SocketAddr) -> Vec<u32> {
    let concrete: Vec<u32> = entries
        .iter()
        .filter(|e| e.protocol == protocol && e.local.port() == src.port() && e.local.ip() == src.ip())
        .flat_map(|e| e.pids.iter().copied())
        .collect();
    if !concrete.is_empty() || protocol != IpProtocol::Udp {
        return concrete;
    }
    entries
        .iter()
        .filter(|e| e.protocol == protocol && e.local.port() == src.port() && e.local.ip().is_unspecified())
        .flat_map(|e| e.pids.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn normalize_name_is_case_and_extension_insensitive() {
        assert_eq!(normalize_name("Curl.EXE"), "curl");
        assert_eq!(normalize_name("curl"), "curl");
        assert_eq!(normalize_name("  My-Proxy.exe "), "my-proxy");
        assert_eq!(normalize_name(".exe"), "");
    }

    #[test]
    fn matcher_rejects_empty_and_normalizes() {
        assert!(ProcessMatcher::new(&[]).is_none());
        assert!(ProcessMatcher::new(&["   ".to_string()]).is_none());
        let matcher = ProcessMatcher::new(&["Curl.exe".to_string(), "wget".to_string()]).unwrap();
        assert_eq!(matcher.names, vec!["curl".to_string(), "wget".to_string()]);
    }

    fn entry(protocol: IpProtocol, ip: std::net::IpAddr, port: u16, pid: u32) -> SocketEntry {
        SocketEntry {
            protocol,
            local: SocketAddr::new(ip, port),
            pids: vec![pid],
        }
    }

    #[test]
    fn tcp_candidate_requires_exact_ip_and_port() {
        let src = SocketAddr::new(Ipv4Addr::new(198, 18, 0, 1).into(), 5000);
        let entries = vec![
            // Exact match -> selected.
            entry(IpProtocol::Tcp, src.ip(), 5000, 11),
            // Wildcard listener on the same port -> must NOT be selected for TCP.
            entry(IpProtocol::Tcp, Ipv4Addr::UNSPECIFIED.into(), 5000, 22),
            // Same port, different concrete ip -> not selected.
            entry(IpProtocol::Tcp, Ipv4Addr::new(10, 0, 0, 1).into(), 5000, 33),
            // Right ip+port but UDP -> protocol mismatch.
            entry(IpProtocol::Udp, src.ip(), 5000, 44),
        ];
        assert_eq!(candidate_pids(&entries, IpProtocol::Tcp, src), vec![11]);
        // A pure wildcard listener never matches a TCP session.
        let wildcard_only = vec![entry(IpProtocol::Tcp, Ipv4Addr::UNSPECIFIED.into(), 5000, 22)];
        assert!(candidate_pids(&wildcard_only, IpProtocol::Tcp, src).is_empty());
    }

    #[test]
    fn udp_candidate_prefers_concrete_then_falls_back_to_wildcard() {
        let src = SocketAddr::new(Ipv4Addr::new(198, 18, 0, 1).into(), 5300);
        // Concrete-IP row is preferred and the wildcard row is ignored when present.
        let with_concrete = vec![
            entry(IpProtocol::Udp, src.ip(), 5300, 11),
            entry(IpProtocol::Udp, Ipv4Addr::UNSPECIFIED.into(), 5300, 22),
        ];
        assert_eq!(candidate_pids(&with_concrete, IpProtocol::Udp, src), vec![11]);
        // Windows-style: only a 0.0.0.0/[::] row exists for a connected UDP client.
        let wildcard_only = vec![
            entry(IpProtocol::Udp, Ipv4Addr::UNSPECIFIED.into(), 5300, 22),
            entry(IpProtocol::Udp, Ipv6Addr::UNSPECIFIED.into(), 5300, 23),
        ];
        let pids = candidate_pids(&wildcard_only, IpProtocol::Udp, src);
        assert!(pids.contains(&22) && pids.contains(&23));
        // Different port never matches.
        assert!(candidate_pids(&wildcard_only, IpProtocol::Udp, SocketAddr::new(src.ip(), 5301)).is_empty());
    }
}
