//! Source-process lookup used by the `--bypass-process` feature.
//!
//! Given a session observed on the TUN device, we map its socket endpoints back
//! to the owning OS process and compare its executable name against a
//! user-supplied bypass list. This is
//! the tun2proxy equivalent of clash/mihomo's `PROCESS-NAME` rule and is used to
//! relay a local loopback proxy's own outbound traffic directly, breaking the
//! routing loop it would otherwise create.
//!
//! Only implemented on Windows and Linux; the module is not compiled elsewhere.

use crate::session_info::IpProtocol;
use std::{collections::HashMap, net::SocketAddr, sync::Mutex, time::Instant};

#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "windows", path = "windows.rs")]
mod imp;

/// One row of the OS socket table relevant to bypass matching.
#[derive(Debug, Clone)]
struct SocketEntry {
    protocol: IpProtocol,
    local: SocketAddr,
    /// TCP needs the complete tuple to distinguish sockets that reuse a local
    /// port. `netstat2` does not expose a remote endpoint for UDP.
    remote: Option<SocketAddr>,
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
    /// Whether the supplied list contains at least one usable process name.
    pub(crate) fn is_configured(names: &[String]) -> bool {
        names.iter().any(|name| !normalize_name(name).is_empty())
    }

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
    pub(crate) async fn matches(self: &std::sync::Arc<Self>, protocol: IpProtocol, src: SocketAddr, dst: SocketAddr) -> bool {
        // Any snapshot taken after this instant necessarily includes this
        // socket: the packet has already reached the TUN before lookup starts.
        // Concurrent lookups can therefore share one refresh without allowing
        // a time-based stale-cache window.
        let requested_at = Instant::now();
        let this = self.clone();
        match tokio::task::spawn_blocking(move || this.matches_blocking(protocol, src, dst, requested_at)).await {
            Ok(result) => result,
            Err(err) => {
                log::warn!("process bypass lookup task failed: {err}");
                false
            }
        }
    }

    fn matches_blocking(&self, protocol: IpProtocol, src: SocketAddr, dst: SocketAddr, requested_at: Instant) -> bool {
        let mut cache = match self.cache.lock() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !snapshot_covers_request(cache.fetched_at, requested_at) {
            self.refresh(&mut cache);
        }
        self.match_in_cache(&mut cache, protocol, src, dst)
    }

    /// Look the session up against the current snapshot, resolving and memoizing
    /// candidate process names. Does not refresh the snapshot.
    fn match_in_cache(&self, cache: &mut Cache, protocol: IpProtocol, src: SocketAddr, dst: SocketAddr) -> bool {
        // Collect candidate PIDs first to avoid borrowing `cache.entries` and
        // `cache.pid_names` simultaneously.
        let pids = candidate_pids(&cache.entries, protocol, src, dst);
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

    fn refresh(&self, cache: &mut Cache) {
        // Timestamp the beginning, not the end, of the table walk. A socket
        // lookup that starts while the snapshot is being collected may not be
        // represented in it and must trigger the next refresh.
        let snapshot_started_at = Instant::now();
        match snapshot() {
            Ok(entries) => {
                cache.entries = entries;
                cache.pid_names.clear();
                cache.fetched_at = Some(snapshot_started_at);
            }
            Err(err) => {
                log::warn!("failed to read OS socket table for process bypass: {err}");
                // Never reuse an older positive match after a refresh failure;
                // that could leak an unrelated, port-reusing connection direct.
                cache.entries.clear();
                cache.pid_names.clear();
                cache.fetched_at = Some(snapshot_started_at);
            }
        }
    }
}

fn snapshot_covers_request(fetched_at: Option<Instant>, requested_at: Instant) -> bool {
    fetched_at.is_some_and(|fetched_at| fetched_at >= requested_at)
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
            let (protocol, local, remote) = match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => (
                    IpProtocol::Tcp,
                    SocketAddr::new(tcp.local_addr, tcp.local_port),
                    Some(SocketAddr::new(tcp.remote_addr, tcp.remote_port)),
                ),
                ProtocolSocketInfo::Udp(udp) => (IpProtocol::Udp, SocketAddr::new(udp.local_addr, udp.local_port), None),
            };
            SocketEntry {
                protocol,
                local,
                remote,
                pids,
            }
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
/// TCP requires the complete local+remote tuple and never falls back to a
/// wildcard (`0.0.0.0`/`::`) row. UDP table rows often lack a concrete local IP
/// (Windows reports `0.0.0.0` for connected client sockets), so for UDP we
/// prefer a concrete-IP match but fall back to unspecified-IP rows on the same
/// port when none is found.
fn candidate_pids(entries: &[SocketEntry], protocol: IpProtocol, src: SocketAddr, dst: SocketAddr) -> Vec<u32> {
    let concrete: Vec<u32> = entries
        .iter()
        .filter(|e| {
            e.protocol == protocol
                && e.local.port() == src.port()
                && e.local.ip() == src.ip()
                && (protocol == IpProtocol::Udp || e.remote == Some(dst))
        })
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
    use std::time::Duration;

    #[test]
    fn snapshot_must_start_after_the_lookup_request() {
        let requested_at = Instant::now();
        assert!(!snapshot_covers_request(None, requested_at));
        assert!(!snapshot_covers_request(
            Some(requested_at - Duration::from_millis(1)),
            requested_at
        ));
        assert!(snapshot_covers_request(
            requested_at.checked_add(Duration::from_millis(1)),
            requested_at
        ));
    }

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

    #[tokio::test(flavor = "multi_thread")]
    async fn matcher_resolves_a_live_tcp_socket_owner() {
        let process_name = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned();
        let matcher = std::sync::Arc::new(ProcessMatcher::new(&[process_name]).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(destination).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();

        assert!(
            matcher
                .matches(IpProtocol::Tcp, client.local_addr().unwrap(), client.peer_addr().unwrap())
                .await
        );
    }

    fn entry(protocol: IpProtocol, ip: std::net::IpAddr, port: u16, remote: Option<SocketAddr>, pid: u32) -> SocketEntry {
        SocketEntry {
            protocol,
            local: SocketAddr::new(ip, port),
            remote,
            pids: vec![pid],
        }
    }

    #[test]
    fn tcp_candidate_requires_exact_ip_and_port() {
        let src = SocketAddr::new(Ipv4Addr::new(198, 18, 0, 1).into(), 5000);
        let dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);
        let entries = vec![
            // Exact match -> selected.
            entry(IpProtocol::Tcp, src.ip(), 5000, Some(dst), 11),
            // Wildcard listener on the same port -> must NOT be selected for TCP.
            entry(IpProtocol::Tcp, Ipv4Addr::UNSPECIFIED.into(), 5000, None, 22),
            // Same port, different concrete ip -> not selected.
            entry(IpProtocol::Tcp, Ipv4Addr::new(10, 0, 0, 1).into(), 5000, Some(dst), 33),
            // Same local endpoint, different remote -> not selected.
            entry(
                IpProtocol::Tcp,
                src.ip(),
                5000,
                Some(SocketAddr::new(Ipv4Addr::new(203, 0, 113, 20).into(), 443)),
                34,
            ),
            // Right ip+port but UDP -> protocol mismatch.
            entry(IpProtocol::Udp, src.ip(), 5000, None, 44),
        ];
        assert_eq!(candidate_pids(&entries, IpProtocol::Tcp, src, dst), vec![11]);
        // A pure wildcard listener never matches a TCP session.
        let wildcard_only = vec![entry(IpProtocol::Tcp, Ipv4Addr::UNSPECIFIED.into(), 5000, None, 22)];
        assert!(candidate_pids(&wildcard_only, IpProtocol::Tcp, src, dst).is_empty());
    }

    #[test]
    fn udp_candidate_prefers_concrete_then_falls_back_to_wildcard() {
        let src = SocketAddr::new(Ipv4Addr::new(198, 18, 0, 1).into(), 5300);
        let dst = SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53);
        // Concrete-IP row is preferred and the wildcard row is ignored when present.
        let with_concrete = vec![
            entry(IpProtocol::Udp, src.ip(), 5300, None, 11),
            entry(IpProtocol::Udp, Ipv4Addr::UNSPECIFIED.into(), 5300, None, 22),
        ];
        assert_eq!(candidate_pids(&with_concrete, IpProtocol::Udp, src, dst), vec![11]);
        // Windows-style: only a 0.0.0.0/[::] row exists for a connected UDP client.
        let wildcard_only = vec![
            entry(IpProtocol::Udp, Ipv4Addr::UNSPECIFIED.into(), 5300, None, 22),
            entry(IpProtocol::Udp, Ipv6Addr::UNSPECIFIED.into(), 5300, None, 23),
        ];
        let pids = candidate_pids(&wildcard_only, IpProtocol::Udp, src, dst);
        assert!(pids.contains(&22) && pids.contains(&23));
        // Different port never matches.
        assert!(candidate_pids(&wildcard_only, IpProtocol::Udp, SocketAddr::new(src.ip(), 5301), dst).is_empty());
    }
}
