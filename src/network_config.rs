//! Platform network configuration used by `--setup`.
//!
//! Windows deliberately does not delegate setup to `tproxy-config`: its
//! Windows teardown invokes `route delete 0.0.0.0 mask 0.0.0.0`, which can
//! delete default routes owned by Windows, VPN clients, and other software.
//! The Windows implementation records and removes only rows it created.

#[cfg(windows)]
pub(crate) type NetworkConfigState = crate::windows_network_config::WindowsNetworkConfig;

#[cfg(not(windows))]
pub(crate) type NetworkConfigState = tproxy_config::TproxyState;

pub(crate) async fn setup(args: &tproxy_config::TproxyArgs) -> std::io::Result<NetworkConfigState> {
    #[cfg(windows)]
    {
        crate::windows_network_config::WindowsNetworkConfig::install(args)
    }

    #[cfg(not(windows))]
    {
        tproxy_config::tproxy_setup(args).await
    }
}

pub(crate) async fn remove(state: Option<NetworkConfigState>) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        match state {
            Some(state) => state.remove(),
            None => Ok(()),
        }
    }

    #[cfg(not(windows))]
    {
        tproxy_config::tproxy_remove(state).await
    }
}
