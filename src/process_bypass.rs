//! Runtime-updatable process names that bypass the proxy.
//!
//! The list is shared with the active TUN session so embedders can change
//! process routing without recreating the device or replacing system routes.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use tokio::sync::watch;

/// Thread-safe process bypass list shared by TUN session matchers.
#[derive(Clone, Debug)]
pub struct ProcessBypass {
    names: Arc<RwLock<Vec<String>>>,
    changes: watch::Sender<u64>,
}

impl Default for ProcessBypass {
    fn default() -> Self {
        let (changes, _) = watch::channel(0);
        Self {
            names: Arc::new(RwLock::new(Vec::new())),
            changes,
        }
    }
}

impl ProcessBypass {
    /// Create a list from executable file names.
    pub fn new(names: impl IntoIterator<Item = String>) -> Self {
        let bypass = Self::default();
        bypass.set_names(names);
        bypass
    }

    /// Atomically replace the names used for new and established sessions.
    ///
    /// Established sessions are notified through [`Self::subscribe`]. Their
    /// relay is closed only when the updated policy changes that session's
    /// decision, allowing the originating application to reconnect on the new
    /// route without recreating the TUN adapter.
    pub fn set_names(&self, names: impl IntoIterator<Item = String>) {
        let names = names
            .into_iter()
            .map(|name| normalize_process_name(&name))
            .filter(|name| !name.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let changed = match self.names.write() {
            Ok(mut current) if *current != names => {
                *current = names;
                true
            }
            Err(poisoned) => {
                let mut current = poisoned.into_inner();
                if *current == names {
                    false
                } else {
                    *current = names;
                    true
                }
            }
            Ok(_) => false,
        };
        if changed {
            self.changes.send_modify(|revision| *revision = revision.wrapping_add(1));
        }
    }

    /// Return the normalized, sorted names currently in effect.
    pub fn names(&self) -> Vec<String> {
        match self.names.read() {
            Ok(names) => names.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Whether at least one process currently bypasses the proxy.
    pub fn is_configured(&self) -> bool {
        match self.names.read() {
            Ok(names) => !names.is_empty(),
            Err(poisoned) => !poisoned.into_inner().is_empty(),
        }
    }

    #[cfg(test)]
    pub(crate) fn contains_normalized(&self, name: &str) -> bool {
        match self.names.read() {
            Ok(names) => names.iter().any(|candidate| candidate == name),
            Err(poisoned) => poisoned.into_inner().iter().any(|candidate| candidate == name),
        }
    }

    /// Subscribe to effective policy changes. The revision itself is opaque;
    /// receivers only use it as an inexpensive wake-up signal.
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos", test))]
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

/// Lower-case and drop a trailing `.exe` so names behave consistently across
/// Windows and Linux.
pub fn normalize_process_name(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_normalized_deduplicated_and_replaceable() {
        let bypass = ProcessBypass::new([" Curl.EXE ".to_string(), "curl".to_string(), "proxy-ui.exe".to_string()]);
        assert_eq!(bypass.names(), vec!["curl", "proxy-ui"]);

        bypass.set_names(["other.exe".to_string()]);
        assert_eq!(bypass.names(), vec!["other"]);
        assert!(bypass.contains_normalized("other"));
        assert!(!bypass.contains_normalized("curl"));
    }

    #[tokio::test]
    async fn subscribers_are_notified_only_when_policy_changes() {
        let bypass = ProcessBypass::new(["curl.exe".to_string()]);
        let mut changes = bypass.subscribe();

        bypass.set_names(["CURL".to_string()]);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), changes.changed())
                .await
                .is_err()
        );

        bypass.set_names(["wget.exe".to_string()]);
        changes.changed().await.unwrap();
        assert_eq!(bypass.names(), vec!["wget"]);
    }
}
