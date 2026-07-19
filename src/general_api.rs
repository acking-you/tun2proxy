use crate::{Args, ProcessBypass, VirtualDnsState};
use std::os::raw::{c_char, c_int, c_ushort};

/// # Safety
/// Run the tun2proxy component with command line arguments
/// Parameters:
/// - cli_args: The command line arguments,
///   e.g. `tun2proxy-bin --setup --proxy socks5://127.0.0.1:1080 --bypass 98.76.54.0/24 --dns over-tcp --verbosity trace`
/// - tun_mtu: The MTU of the TUN device, e.g. 1500
/// - packet_information: Whether exists packet information in packet from TUN device
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tun2proxy_run_with_cli_args(cli_args: *const c_char, tun_mtu: c_ushort, packet_information: bool) -> c_int {
    let Ok(cli_args) = unsafe { std::ffi::CStr::from_ptr(cli_args) }.to_str() else {
        log::error!("Failed to convert CLI arguments to string");
        return -5;
    };
    let Some(args) = shlex::split(cli_args) else {
        log::error!("Failed to split CLI arguments");
        return -6;
    };
    let args = <Args as ::clap::Parser>::parse_from(args);
    general_run_for_api(args, tun_mtu, packet_information)
}

static TUN_QUIT: std::sync::Mutex<Option<tokio_util::sync::CancellationToken>> = std::sync::Mutex::new(None);

pub(crate) fn tun2proxy_stop_internal() -> c_int {
    if let Ok(mut lock) = TUN_QUIT.lock() {
        if let Some(shutdown_token) = lock.take() {
            shutdown_token.cancel();
            return 0;
        }
    }
    -1
}

pub fn general_run_for_api(args: Args, tun_mtu: u16, packet_information: bool) -> c_int {
    log::set_max_level(args.verbosity.into());
    if let Err(err) = log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()) {
        log::debug!("set logger error: {err}");
    }

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    if let Ok(mut lock) = TUN_QUIT.lock() {
        if lock.is_some() {
            log::error!("tun2proxy already started");
            return -1;
        }
        *lock = Some(shutdown_token.clone());
    } else {
        log::error!("failed to lock tun2proxy quit token");
        return -2;
    }

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread().enable_all().build() else {
        log::error!("failed to create tokio runtime with");
        return -3;
    };
    let args_clone = args.clone();
    let res = rt.block_on(async move {
        let ret = general_run_async(args_clone, tun_mtu, packet_information, shutdown_token).await;
        // Spawn a std thread to force exit after timeout so it isn't cancelled
        // when the tokio runtime is dropped.
        let _h = std::thread::spawn(move || {
            // Delay some seconds then try to exit current process if not exited yet, normally this case should not happen
            std::thread::sleep(crate::FORCE_EXIT_TIMEOUT);
            log::info!("Forcing exit now.");
            std::process::exit(-1);
        });
        tokio::time::sleep(std::time::Duration::from_micros(100)).await;
        ret
    });

    let res = match res {
        Ok(sessions) => {
            log::debug!("tun2proxy exited normally, current session count: {sessions}");
            0
        }
        Err(e) => {
            log::error!("failed to run tun2proxy with error: {e:?}");
            -4
        }
    };

    if let Ok(mut lock) = TUN_QUIT.lock() {
        lock.take();
    }

    res
}

/// Run the tun2proxy component with some arguments.
pub async fn general_run_async(
    args: Args,
    tun_mtu: u16,
    _packet_information: bool,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> std::io::Result<usize> {
    let process_bypass = ProcessBypass::new(args.bypass_process.clone());
    general_run_async_with_process_bypass(args, tun_mtu, _packet_information, shutdown_token, process_bypass).await
}

/// Run tun2proxy with a process bypass list that an embedding application may
/// update while the TUN device remains active.
pub async fn general_run_async_with_process_bypass(
    args: Args,
    tun_mtu: u16,
    _packet_information: bool,
    shutdown_token: tokio_util::sync::CancellationToken,
    process_bypass: ProcessBypass,
) -> std::io::Result<usize> {
    general_run_async_with_process_bypass_inner(args, tun_mtu, _packet_information, shutdown_token, process_bypass, None, None).await
}

/// Run tun2proxy and report when the adapter and operating-system routes are
/// ready.
///
/// Long-running embedders should not treat task creation as proof that TUN
/// capture is active. The readiness channel resolves only after device creation
/// and route setup have both succeeded. Setup failures are returned through the
/// channel as well as from the task, so a UI can keep its state synchronized
/// without waiting for the complete TUN session to exit.
pub async fn general_run_async_with_process_bypass_and_ready(
    args: Args,
    tun_mtu: u16,
    packet_information: bool,
    shutdown_token: tokio_util::sync::CancellationToken,
    process_bypass: ProcessBypass,
    ready: tokio::sync::oneshot::Sender<Result<(), String>>,
) -> std::io::Result<usize> {
    general_run_async_with_process_bypass_inner(args, tun_mtu, packet_information, shutdown_token, process_bypass, Some(ready), None).await
}

/// Run an embedded TUN session with readiness reporting and reusable fake-DNS
/// mappings. Reusing the state keeps cached fake IPs valid across route-only
/// restarts such as an upstream node hot switch.
pub async fn general_run_async_with_process_bypass_and_ready_and_virtual_dns(
    args: Args,
    tun_mtu: u16,
    packet_information: bool,
    shutdown_token: tokio_util::sync::CancellationToken,
    process_bypass: ProcessBypass,
    ready: tokio::sync::oneshot::Sender<Result<(), String>>,
    virtual_dns_state: VirtualDnsState,
) -> std::io::Result<usize> {
    general_run_async_with_process_bypass_inner(
        args,
        tun_mtu,
        packet_information,
        shutdown_token,
        process_bypass,
        Some(ready),
        Some(virtual_dns_state),
    )
    .await
}

async fn general_run_async_with_process_bypass_inner(
    args: Args,
    tun_mtu: u16,
    _packet_information: bool,
    shutdown_token: tokio_util::sync::CancellationToken,
    process_bypass: ProcessBypass,
    mut ready: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    virtual_dns_state: Option<VirtualDnsState>,
) -> std::io::Result<usize> {
    let result = general_run_async_with_process_bypass_setup(
        args,
        tun_mtu,
        _packet_information,
        shutdown_token,
        process_bypass,
        virtual_dns_state,
        &mut ready,
    )
    .await;
    if let Err(error) = &result {
        if let Some(ready) = ready.take() {
            let _ = ready.send(Err(error.to_string()));
        }
    }
    result
}

async fn general_run_async_with_process_bypass_setup(
    args: Args,
    tun_mtu: u16,
    _packet_information: bool,
    shutdown_token: tokio_util::sync::CancellationToken,
    process_bypass: ProcessBypass,
    virtual_dns_state: Option<VirtualDnsState>,
    ready: &mut Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
) -> std::io::Result<usize> {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    let mut args = args;

    // Capture this before creating our adapter. If setup later fails, the
    // diagnostic can identify tunnel software that was already active rather
    // than mistakenly reporting the adapter created by this invocation.
    #[cfg(target_os = "windows")]
    let preexisting_tunnels = active_windows_tunnel_adapters();
    #[cfg(target_os = "windows")]
    if args.setup && !preexisting_tunnels.is_empty() {
        return Err(preexisting_windows_tunnel_error(&preexisting_tunnels));
    }

    // Resolve the physical egress before `tproxy_setup` installs the TUN
    // catch-all routes. Re-resolving the default interface afterwards would
    // select the TUN itself and send direct relays back into the tunnel.
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    if process_bypass.is_configured() {
        let iface = crate::direct::detect(args.bind_interface.as_deref()).map_err(std::io::Error::from)?;
        log::info!("Process-bypass physical interface selected before route setup: {iface}");
        args.bind_interface = Some(iface.name);
    }

    let mut tun_config = tun::Configuration::default();

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        use tproxy_config::{TUN_IPV4, TUN_NETMASK};
        tun_config.address(TUN_IPV4).netmask(TUN_NETMASK).mtu(tun_mtu).up();
    }

    // On Windows, tun::Configuration::destination creates an unmanaged 0/0
    // route inside the tun crate. The transactional setup below must be the
    // sole owner of capture routes so teardown can remove exactly what it
    // created. Unix platforms still use destination for their native point-
    // to-point/interface setup.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use tproxy_config::TUN_GATEWAY;
        tun_config.destination(TUN_GATEWAY);
    }

    // Keep ownership outside `tun::Device` until construction succeeds. This
    // closes an embedding application's duplicated descriptor on every setup
    // error without risking a double-close inside the tun crate.
    #[cfg(unix)]
    let owned_tun_fd = if args.tun_fd.is_some() && args.close_fd_on_drop.unwrap_or(true) {
        use std::os::fd::FromRawFd;
        args.tun_fd.map(|fd| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    } else {
        None
    };
    #[cfg(unix)]
    if let Some(fd) = owned_tun_fd.as_ref() {
        use std::os::fd::AsRawFd;
        tun_config.raw_fd(fd.as_raw_fd()).close_fd_on_drop(false);
    } else if let Some(fd) = args.tun_fd {
        tun_config.raw_fd(fd).close_fd_on_drop(false);
    } else if let Some(ref tun) = args.tun {
        tun_config.tun_name(tun);
    }
    #[cfg(windows)]
    if let Some(ref tun) = args.tun {
        tun_config.tun_name(tun);
    }

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|cfg| {
        #[allow(deprecated)]
        cfg.packet_information(true);
        cfg.ensure_root_privileges(args.setup);
    });

    #[cfg(target_os = "windows")]
    tun_config.platform_config(|cfg| {
        cfg.device_guid(12324323423423434234_u128);
    });

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    tun_config.platform_config(|cfg| {
        cfg.packet_information(_packet_information);
    });

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[allow(unused_variables)]
    let mut tproxy_args = tproxy_config::TproxyArgs::new()
        .tun_dns(args.dns_addr)
        .proxy_addr(args.proxy.addr)
        .bypass_ips(&args.bypass)
        .ipv6_default_route(args.ipv6_enabled);

    #[cfg(target_os = "windows")]
    let device = tun::create_as_async(&tun_config)
        .map_err(|error| windows_tun_setup_error("create or open the Wintun adapter", error.into(), &preexisting_tunnels))?;
    #[cfg(not(target_os = "windows"))]
    let device = tun::create_as_async(&tun_config)?;

    match tun::AbstractDevice::mtu(&*device) {
        Ok(device_mtu) if device_mtu == tun_mtu => {
            log::info!("TUN adapter effective MTU is {device_mtu} bytes");
        }
        Ok(device_mtu) => {
            log::warn!(
                "TUN adapter reported MTU {device_mtu}, but tun2proxy requested {tun_mtu}; oversized packets may be dropped by downstream virtual interfaces"
            );
        }
        Err(error) => {
            log::warn!("Could not read the effective TUN adapter MTU after requesting {tun_mtu}: {error}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if let Ok(tun_name) = tun::AbstractDevice::tun_name(&*device) {
        // Above line is equivalent to: `use tun::AbstractDevice; if let Ok(tun_name) = device.tun_name() {`
        tproxy_args = tproxy_args.tun_name(&tun_name);
    }

    // Keep the platform setup guard alive for the forwarding lifetime. On
    // Windows its Drop implementation synchronously retries owned-route and
    // DNS cleanup if explicit teardown cannot complete.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    let mut restore: Option<crate::network_config::NetworkConfigState> = None;

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if args.setup {
        #[cfg(target_os = "windows")]
        {
            restore = Some(crate::network_config::setup(&tproxy_args).await.map_err(|error| {
                windows_tun_setup_error(
                    "install the transactional Windows routes and DNS settings",
                    error,
                    &preexisting_tunnels,
                )
            })?);
        }
        #[cfg(not(target_os = "windows"))]
        {
            restore = Some(crate::network_config::setup(&tproxy_args).await?);
        }
    }

    log::info!("TUN adapter and system routes are ready");
    if let Some(ready) = ready.take() {
        let _ = ready.send(Ok(()));
    }

    #[cfg(target_os = "linux")]
    {
        let mut admin_command_args = args.admin_command.iter();
        if let Some(command) = admin_command_args.next() {
            let child = tokio::process::Command::new(command)
                .args(admin_command_args)
                .kill_on_drop(true)
                .spawn();

            match child {
                Err(err) => {
                    log::warn!("Failed to start admin process: {err}");
                }
                Ok(mut child) => {
                    tokio::spawn(async move {
                        if let Err(err) = child.wait().await {
                            log::warn!("Admin process terminated: {err}");
                        }
                    });
                }
            };
        }
    }

    // A plain JoinHandle permanently detaches its task when this outer future
    // is dropped. AbortOnDropHandle propagates cancellation instead; the
    // forwarding loop's JoinSet then owns and aborts all of its session tasks.
    // Tokio abort is cooperative, so this prevents leaked background work but
    // does not claim an instantaneous ordering against synchronous Drop.
    let join_handle = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(crate::run_with_process_bypass_and_virtual_dns(
        device,
        tun_mtu,
        args.clone(),
        shutdown_token.clone(),
        process_bypass,
        virtual_dns_state,
    )));

    // Preserve JoinError instead of returning through `?`: route/DNS cleanup
    // must also run when the forwarding task panics or is aborted.
    let forwarding_task_result = join_handle.await;

    // Restore routes and DNS on every normal task completion, including
    // forwarding errors. Relying only on Drop would hide teardown failures
    // behind the original forwarding error and could leave owned routes in
    // place until the next reboot.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    let cleanup_result = crate::network_config::remove(restore).await;
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    let cleanup_result: std::io::Result<()> = Ok(());

    let forwarding_result = match forwarding_task_result {
        Ok(result) => result,
        Err(join_error) => {
            return match cleanup_result {
                Ok(()) => Err(std::io::Error::other(format!("TUN forwarding task failed: {join_error}"))),
                Err(cleanup_error) => Err(std::io::Error::other(format!(
                    "TUN forwarding task failed: {join_error}; network teardown also failed: {cleanup_error}"
                ))),
            };
        }
    };

    if let Err(cleanup_error) = cleanup_result {
        return match forwarding_result {
            Ok(_) => Err(cleanup_error),
            Err(forwarding_error) => Err(std::io::Error::other(format!(
                "TUN forwarding failed: {forwarding_error}; network teardown also failed: {cleanup_error}"
            ))),
        };
    }

    match forwarding_result {
        Ok(sessions) => {
            let max_sessions = args.max_sessions;
            if args.exit_on_fatal_error && sessions >= max_sessions {
                let info = format!("Forced exit due to max sessions reached ({sessions}/{max_sessions})");
                return Err(std::io::Error::other(info));
            }
            Ok(sessions)
        }
        Err(err) => Err(std::io::Error::from(err)),
    }
}

#[cfg(target_os = "windows")]
fn active_windows_tunnel_adapters() -> Vec<String> {
    const TUNNEL_MARKERS: &[&str] = &["tun", "tap", "vpn", "wireguard", "wintun", "tailscale", "zerotier", "openvpn"];

    let mut adapters = netdev::get_interfaces()
        .into_iter()
        .filter(|interface| interface.is_up() || interface.is_oper_up())
        .filter_map(|interface| {
            let friendly = interface.friendly_name.as_deref().unwrap_or(&interface.name);
            let description = interface.description.as_deref().unwrap_or_default();
            let searchable = format!("{friendly} {description}").to_ascii_lowercase();
            // Do not use the generic point-to-point heuristic on Windows: its
            // always-present WAN Miniport adapters satisfy it and would block
            // TUN mode on otherwise normal systems. Product/driver markers are
            // narrower and still cover Wintun, WireGuard, OpenVPN, and common
            // third-party tunnel adapters.
            let looks_like_tunnel = TUNNEL_MARKERS.iter().any(|marker| searchable.contains(marker));
            looks_like_tunnel.then(|| {
                if description.is_empty() || description.eq_ignore_ascii_case(friendly) {
                    friendly.to_string()
                } else {
                    format!("{friendly} ({description})")
                }
            })
        })
        .collect::<Vec<_>>();
    adapters.sort();
    adapters.dedup();
    adapters
}

#[cfg(target_os = "windows")]
fn windows_tun_setup_error(operation: &str, error: std::io::Error, preexisting_tunnels: &[String]) -> std::io::Error {
    let conflict = if preexisting_tunnels.is_empty() {
        "No pre-existing tunnel adapter was detected; inspect the Windows detail below.".to_string()
    } else {
        format!(
            "Active tunnel/VPN adapters were already present: {}. Stop the other VPN/TUN application (or another proxy-everything instance) and retry.",
            preexisting_tunnels.join(", ")
        )
    };
    std::io::Error::new(error.kind(), format!("Failed to {operation}. {conflict} Windows detail: {error}"))
}

#[cfg(target_os = "windows")]
fn preexisting_windows_tunnel_error(adapters: &[String]) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        format!(
            "TUN startup was stopped before changing routes because another active tunnel/VPN adapter was detected: {}. Stop the owning VPN/TUN application (or another proxy-everything instance), then retry.",
            adapters.join(", ")
        ),
    )
}

/// # Safety
///
/// Shutdown the tun2proxy component.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tun2proxy_stop() -> c_int {
    tun2proxy_stop_internal()
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn setup_error_names_preexisting_tunnel_and_recovery_action() {
        let error = windows_tun_setup_error(
            "install routes",
            std::io::Error::other("route already exists"),
            &["Other VPN (Example Tunnel)".to_string()],
        );
        let message = error.to_string();
        assert!(message.contains("Other VPN (Example Tunnel)"));
        assert!(message.contains("Stop the other VPN/TUN application"));
        assert!(message.contains("route already exists"));
    }

    #[test]
    fn preflight_conflict_error_is_actionable() {
        let error = preexisting_windows_tunnel_error(&["wintun (wintun Tunnel)".to_string()]);
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains("before changing routes"));
        assert!(error.to_string().contains("wintun (wintun Tunnel)"));
    }
}
