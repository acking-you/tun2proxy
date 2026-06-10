//! Linux source-process name resolution.

use std::path::Path;

/// Resolve a PID to its executable basename.
///
/// Prefers the `/proc/<pid>/exe` symlink (full, untruncated name; readable when
/// running with the privileges `--setup` already requires) and falls back to
/// `/proc/<pid>/comm` (which the kernel truncates to 15 bytes) when the symlink
/// cannot be read.
pub(super) fn process_name(pid: u32) -> Option<String> {
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        if let Some(name) = exe.file_name().and_then(|n| n.to_str()) {
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }

    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = comm.trim();
    if name.is_empty() {
        return None;
    }
    // `comm` may itself contain a path component in unusual cases; keep only the
    // basename to stay consistent with the `exe` branch.
    Some(Path::new(name).file_name().and_then(|n| n.to_str()).unwrap_or(name).to_string())
}
