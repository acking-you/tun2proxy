//! Source-process lookup used by the `--bypass-process` feature.
//!
//! Given a session observed on the TUN device, we map its socket endpoints back
//! to the owning OS process and compare its executable name against a
//! user-supplied bypass list. This is
//! the tun2proxy equivalent of clash/mihomo's `PROCESS-NAME` rule and is used to
//! relay a local loopback proxy's own outbound traffic directly, breaking the
//! routing loop it would otherwise create.
//!
//! Only implemented on Windows, Linux, and macOS; the module is not compiled
//! elsewhere. iOS and Android leave the interface to the platform VPN API, which
//! owns per-application routing itself.

use crate::{ProcessBypass, process_bypass::normalize_process_name, session_info::IpProtocol};
use std::{collections::HashMap, net::SocketAddr, sync::Mutex, time::Instant};

#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(target_os = "macos", path = "macos.rs")]
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
    /// Resolved `pid -> executable identity chain`, memoized within one socket
    /// snapshot and cleared on every refresh. Windows includes live ancestors so
    /// a launcher/application selection covers protected game child processes.
    pid_names: HashMap<u32, Vec<String>>,
}

/// Matches sessions against a set of process names to be relayed directly.
pub(crate) struct ProcessMatcher {
    names: ProcessBypass,
    cache: Mutex<Cache>,
}

/// The socket owner's identity is pinned for the lifetime of one relay. An OS
/// table refresh can lose an owner, recycle a UDP port, or see a different
/// ancestor chain; none of those events is a change to this session's policy.
pub(crate) struct SessionPolicy {
    names: ProcessBypass,
    identities: Vec<String>,
    changes: tokio::sync::watch::Receiver<u64>,
    bypass: bool,
}

impl SessionPolicy {
    pub(crate) fn bypass(&self) -> bool {
        self.bypass
    }

    pub(crate) async fn wait_for_routing_change(mut self) {
        loop {
            if self.changes.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
            if matches_policy(&self.names, &self.identities) != self.bypass {
                return;
            }
        }
    }
}

fn matches_policy(names: &ProcessBypass, identities: &[String]) -> bool {
    // Read a single policy snapshot, even if an update races this decision.
    let names = names.names();
    identities.iter().any(|name| names.contains(name))
}

impl ProcessMatcher {
    /// Whether the supplied list contains at least one usable process name.
    /// Build a matcher around a runtime-updatable list. Returns `None` when the
    /// initial list is empty, avoiding socket-table work when bypass is unused.
    pub(crate) fn new(names: ProcessBypass) -> Option<Self> {
        if !names.is_configured() {
            return None;
        }
        Some(Self {
            names,
            cache: Mutex::new(Cache::default()),
        })
    }

    /// Resolve a new session once, including identities that do not currently
    /// bypass. Policy updates then only compare names; they never launch an OS
    /// socket/process-table walk for every established relay at once.
    pub(crate) async fn match_session(
        self: &std::sync::Arc<Self>,
        protocol: IpProtocol,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> SessionPolicy {
        // Subscribe before lookup so an update racing it cannot be missed.
        let changes = self.names.subscribe();
        // Any snapshot taken after this instant necessarily includes this
        // socket: the packet has already reached the TUN before lookup starts.
        // Concurrent lookups can therefore share one refresh without allowing
        // a time-based stale-cache window.
        let requested_at = Instant::now();
        let this = self.clone();
        let identities = match tokio::task::spawn_blocking(move || this.identities_blocking(protocol, src, dst, requested_at)).await {
            Ok(result) => result,
            Err(err) => {
                log::warn!("process bypass lookup task failed: {err}");
                Vec::new()
            }
        };
        let bypass = matches_policy(&self.names, &identities);
        if bypass {
            log::info!("bypassing {protocol} session {src} -> {dst}: process identities {identities:?}");
        }
        SessionPolicy {
            names: self.names.clone(),
            identities,
            changes,
            bypass,
        }
    }

    fn identities_blocking(&self, protocol: IpProtocol, src: SocketAddr, dst: SocketAddr, requested_at: Instant) -> Vec<String> {
        let mut cache = match self.cache.lock() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !snapshot_covers_request(cache.fetched_at, requested_at) {
            self.refresh(&mut cache);
        }
        self.identities_in_cache(&mut cache, protocol, src, dst)
    }

    /// Look the session up against the current snapshot, resolving and memoizing
    /// candidate process names. Does not refresh the snapshot.
    fn identities_in_cache(&self, cache: &mut Cache, protocol: IpProtocol, src: SocketAddr, dst: SocketAddr) -> Vec<String> {
        // Collect candidate PIDs first to avoid borrowing `cache.entries` and
        // `cache.pid_names` simultaneously.
        let pids = candidate_pids(&cache.entries, protocol, src, dst);
        if pids.is_empty() {
            log::debug!("process bypass found no socket owner for {protocol} session {src} -> {dst}");
            return Vec::new();
        }
        let mut identities = Vec::new();
        for pid in pids {
            let names = cache.pid_names.entry(pid).or_insert_with(|| {
                imp::process_names(pid)
                    .into_iter()
                    .map(|name| normalize_process_name(&name))
                    .filter(|name| !name.is_empty())
                    .collect()
            });
            if names.is_empty() {
                log::debug!("process bypass could not resolve executable identity for {protocol} session {src} -> {dst} owner pid {pid}");
                continue;
            }
            identities.extend(names.iter().cloned());
            log::debug!("process bypass resolved socket pid {pid} to identity chain {names:?}");
        }
        identities.sort_unstable();
        identities.dedup();
        identities
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

/// PIDs of the socket(s) that plausibly originated `src`.
///
/// TCP prefers the complete local+remote tuple, then tolerates a different
/// concrete local IP while still requiring the same port and remote endpoint.
/// Windows can expose the physical-interface address in the socket table while
/// the packet observed by TUN carries its translated virtual address. UDP table
/// rows do not expose a remote endpoint, so matching falls back from the exact
/// IP to an unspecified address and finally to another same-family local IP.
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
    if !concrete.is_empty() {
        return concrete;
    }

    if protocol == IpProtocol::Tcp {
        return entries
            .iter()
            .filter(|e| {
                e.protocol == protocol && e.local.port() == src.port() && e.local.is_ipv4() == src.is_ipv4() && e.remote == Some(dst)
            })
            .flat_map(|e| e.pids.iter().copied())
            .collect();
    }

    let unspecified: Vec<u32> = entries
        .iter()
        .filter(|e| e.protocol == protocol && e.local.port() == src.port() && e.local.ip().is_unspecified())
        .flat_map(|e| e.pids.iter().copied())
        .collect();
    if !unspecified.is_empty() {
        return unspecified;
    }

    entries
        .iter()
        .filter(|e| e.protocol == protocol && e.local.port() == src.port() && e.local.is_ipv4() == src.is_ipv4())
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
        assert_eq!(normalize_process_name("Curl.EXE"), "curl");
        assert_eq!(normalize_process_name("curl"), "curl");
        assert_eq!(normalize_process_name("  My-Proxy.exe "), "my-proxy");
        assert_eq!(normalize_process_name(".exe"), "");
    }

    #[test]
    fn matcher_rejects_empty_and_normalizes() {
        assert!(ProcessMatcher::new(ProcessBypass::default()).is_none());
        assert!(ProcessMatcher::new(ProcessBypass::new(["   ".to_string()])).is_none());
        let matcher = ProcessMatcher::new(ProcessBypass::new(["Curl.exe".to_string(), "wget".to_string()])).unwrap();
        assert_eq!(matcher.names.names(), vec!["curl".to_string(), "wget".to_string()]);
    }

    #[test]
    fn process_identity_includes_current_executable() {
        let current = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned();
        let current = normalize_process_name(&current);
        let names = imp::process_names(std::process::id())
            .into_iter()
            .map(|name| normalize_process_name(&name))
            .collect::<Vec<_>>();
        assert!(names.contains(&current), "current process `{current}` missing from {names:?}");
    }

    /// The macOS backend walks ancestors through `proc_pidinfo`, so verify the
    /// chain really reaches this process's parent instead of stopping at itself.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_identity_chain_reaches_a_real_ancestor() {
        let names = imp::process_names(std::process::id());
        assert!(names.len() >= 2, "expected an ancestor beyond the current process, got {names:?}");

        let parent = imp::process_names(std::os::unix::process::parent_id());
        assert_eq!(names[1], parent[0], "the second identity must be the real parent executable");

        // A pid that cannot exist must resolve to nothing rather than panicking
        // or inventing a chain.
        assert!(imp::process_names(0).is_empty());
    }

    #[test]
    fn matcher_accepts_a_selected_process_ancestor() {
        let names = ProcessBypass::new(["game-launcher.exe".to_string()]);
        let matcher = ProcessMatcher::new(names).unwrap();
        let src = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 5000);
        let dst = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 10).into(), 443);
        let mut cache = Cache {
            fetched_at: Some(Instant::now()),
            entries: vec![entry(IpProtocol::Tcp, src.ip(), src.port(), Some(dst), 42)],
            pid_names: HashMap::from([(42, vec!["protected-game".to_string(), "game-launcher".to_string()])]),
        };

        assert!(matches_policy(
            &matcher.names,
            &matcher.identities_in_cache(&mut cache, IpProtocol::Tcp, src, dst)
        ));
    }

    #[tokio::test]
    async fn adding_bypass_preserves_an_existing_direct_session_when_the_socket_snapshot_loses_its_owner() {
        let names = ProcessBypass::new(["proxy_ui".to_string()]);
        let matcher = std::sync::Arc::new(ProcessMatcher::new(names.clone()).unwrap());
        let src: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let dst: SocketAddr = "198.51.100.1:443".parse().unwrap();
        // Synthetic snapshots only: no sockets, adapters, or OS routes are used.
        *matcher.cache.lock().unwrap() = Cache {
            fetched_at: Some(Instant::now() + Duration::from_secs(3600)),
            entries: vec![entry(IpProtocol::Tcp, src.ip(), src.port(), Some(dst), 42)],
            pid_names: HashMap::from([(42, vec!["proxy_ui".to_string()])]),
        };
        let policy = matcher.match_session(IpProtocol::Tcp, src, dst).await;
        assert!(policy.bypass());
        matcher.cache.lock().unwrap().entries.clear();
        names.set_names(["proxy_ui".to_string(), "browser".to_string()]);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), policy.wait_for_routing_change(),)
                .await
                .is_err(),
            "adding another app must not disconnect the proxy's existing direct connection"
        );
    }

    fn synthetic_matcher(
        names: ProcessBypass,
        identities: &[&str],
        protocol: IpProtocol,
    ) -> (std::sync::Arc<ProcessMatcher>, SocketAddr, SocketAddr) {
        let src: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let dst: SocketAddr = "198.18.0.1:443".parse().unwrap();
        let matcher = std::sync::Arc::new(ProcessMatcher::new(names).unwrap());
        *matcher.cache.lock().unwrap() = Cache {
            fetched_at: Some(Instant::now() + Duration::from_secs(3600)),
            entries: vec![entry(protocol, src.ip(), src.port(), Some(dst), 42)],
            pid_names: HashMap::from([(42, identities.iter().map(|name| (*name).to_string()).collect())]),
        };
        (matcher, src, dst)
    }

    #[tokio::test]
    async fn selecting_an_ancestor_reroutes_existing_tcp_and_udp_even_if_the_socket_owner_disappears() {
        for protocol in [IpProtocol::Tcp, IpProtocol::Udp] {
            let names = ProcessBypass::new(["proxy_ui".to_string()]);
            let (matcher, src, dst) = synthetic_matcher(names.clone(), &["browser-helper", "browser"], protocol);
            let policy = matcher.match_session(protocol, src, dst).await;
            assert!(!policy.bypass());
            matcher.cache.lock().unwrap().entries.clear();
            // Update before the waiter is first polled, as can happen during
            // fake-IP resolution or an upstream connection handshake.
            names.set_names(["proxy_ui".to_string(), "browser".to_string()]);
            tokio::time::timeout(Duration::from_secs(1), policy.wait_for_routing_change())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn repeated_apply_only_interrupts_the_app_whose_route_changes() {
        let names = ProcessBypass::new(["proxy_ui".to_string(), "browser".to_string()]);
        let (proxy, src, dst) = synthetic_matcher(names.clone(), &["proxy_ui"], IpProtocol::Tcp);
        let (browser, _, _) = synthetic_matcher(names.clone(), &["browser"], IpProtocol::Tcp);
        let proxy = proxy.match_session(IpProtocol::Tcp, src, dst).await;
        let browser = browser.match_session(IpProtocol::Tcp, src, dst).await;
        let mut proxy_wait = Box::pin(proxy.wait_for_routing_change());
        let mut browser_wait = Box::pin(browser.wait_for_routing_change());
        for app in ["curl", "game", "music"] {
            names.set_names(["proxy_ui".to_string(), "browser".to_string(), app.to_string()]);
            assert!(tokio::time::timeout(Duration::from_millis(10), &mut proxy_wait).await.is_err());
            assert!(tokio::time::timeout(Duration::from_millis(10), &mut browser_wait).await.is_err());
        }
        names.set_names(["proxy_ui".to_string()]);
        tokio::time::timeout(Duration::from_secs(1), &mut browser_wait).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(10), &mut proxy_wait).await.is_err());
    }

    #[tokio::test]
    async fn a_reused_udp_port_does_not_reassign_an_established_session_to_another_process() {
        let names = ProcessBypass::new(["proxy_ui".to_string()]);
        let (matcher, src, dst) = synthetic_matcher(names.clone(), &["ordinary-app"], IpProtocol::Udp);
        let policy = matcher.match_session(IpProtocol::Udp, src, dst).await;
        assert!(!policy.bypass());
        matcher.cache.lock().unwrap().pid_names.insert(42, vec!["proxy_ui".to_string()]);
        names.set_names(["proxy_ui".to_string(), "other-app".to_string()]);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), policy.wait_for_routing_change())
                .await
                .is_err()
        );
        // A new relay still does a fresh ownership lookup.
        assert!(matcher.match_session(IpProtocol::Udp, src, dst).await.bypass());
    }

    #[tokio::test]
    async fn an_unresolved_owner_cannot_be_promoted_to_direct_by_a_later_snapshot() {
        let names = ProcessBypass::new(["proxy_ui".to_string()]);
        let (matcher, src, dst) = synthetic_matcher(names.clone(), &[], IpProtocol::Tcp);
        let policy = matcher.match_session(IpProtocol::Tcp, src, dst).await;
        assert!(!policy.bypass());
        matcher.cache.lock().unwrap().pid_names.insert(42, vec!["proxy_ui".to_string()]);
        names.set_names(["proxy_ui".to_string(), "browser".to_string()]);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), policy.wait_for_routing_change())
                .await
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn matcher_resolves_a_live_tcp_socket_owner() {
        let process_name = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned();
        let matcher = std::sync::Arc::new(ProcessMatcher::new(ProcessBypass::new([process_name])).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(destination).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();

        assert!(
            matcher
                .match_session(IpProtocol::Tcp, client.local_addr().unwrap(), client.peer_addr().unwrap())
                .await
                .bypass()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn matcher_uses_process_names_replaced_at_runtime() {
        let process_name = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned();
        let names = ProcessBypass::new(["definitely-not-this-process".to_string()]);
        let matcher = std::sync::Arc::new(ProcessMatcher::new(names.clone()).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(destination).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();
        let source = client.local_addr().unwrap();

        assert!(!matcher.match_session(IpProtocol::Tcp, source, destination).await.bypass());
        names.set_names([process_name]);
        assert!(matcher.match_session(IpProtocol::Tcp, source, destination).await.bypass());
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
    fn tcp_candidate_prefers_exact_ip_then_accepts_tun_address_translation() {
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
        // A pure wildcard listener never matches a TCP session because it has
        // no remote endpoint.
        let wildcard_only = vec![entry(IpProtocol::Tcp, Ipv4Addr::UNSPECIFIED.into(), 5000, None, 22)];
        assert!(candidate_pids(&wildcard_only, IpProtocol::Tcp, src, dst).is_empty());

        let physical_ip_only = vec![entry(IpProtocol::Tcp, Ipv4Addr::new(192, 168, 1, 20).into(), 5000, Some(dst), 55)];
        assert_eq!(candidate_pids(&physical_ip_only, IpProtocol::Tcp, src, dst), vec![55]);
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

        let physical_ip_only = vec![entry(IpProtocol::Udp, Ipv4Addr::new(192, 168, 1, 20).into(), 5300, None, 24)];
        assert_eq!(candidate_pids(&physical_ip_only, IpProtocol::Udp, src, dst), vec![24]);
    }
}
