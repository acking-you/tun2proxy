//! macOS source-process identity resolution.

// `libc` is not a direct dependency; it is reached through `nix`, matching how
// `direct.rs` already uses `nix::libc`.
use nix::libc;

/// Resolve a PID to its executable basename via `proc_pidpath`.
///
/// `proc_pidpath` returns the full executable path and, unlike Linux's
/// `/proc/<pid>/comm`, is not truncated. The TUN session runs as root on macOS,
/// so it can query processes belonging to any user; an unprivileged caller still
/// resolves its own processes, which is all the picker list needs.
fn process_name(pid: u32) -> Option<String> {
    // PROC_PIDPATHINFO_MAXSIZE is 4 * PATH_MAX; sizing the buffer to it means a
    // real path can never be rejected for being too long.
    let mut buffer = vec![0u8; 4 * libc::PATH_MAX as usize];
    // SAFETY: the buffer is valid for `buffer.len()` bytes and `proc_pidpath`
    // writes at most that many, returning the byte count it used.
    let length = unsafe { libc::proc_pidpath(pid as libc::c_int, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if length <= 0 {
        return None;
    }
    let path = String::from_utf8_lossy(&buffer[..length as usize]).into_owned();
    std::path::Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
        .filter(|name| !name.is_empty())
}

/// Resolve a PID's parent through `proc_pidinfo(PROC_PIDTBSDINFO)`.
fn parent_pid(pid: u32) -> Option<u32> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the destination is a correctly sized, writable `proc_bsdinfo`, and
    // the flavor matches that struct. A partial write is rejected below by
    // requiring the exact byte count back.
    let written = unsafe { libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
    if written != size {
        return None;
    }
    // SAFETY: `proc_pidinfo` reported a complete write of the struct.
    let info = unsafe { info.assume_init() };
    // launchd is pid 1 and reports itself as its own parent's child chain root;
    // a zero ppid means the chain ends here.
    if info.pbi_ppid == 0 || info.pbi_ppid == pid {
        return None;
    }
    Some(info.pbi_ppid)
}

/// Resolve the executable names of a PID and its live ancestor chain.
///
/// Ancestors participate in matching for the same reason they do on Windows:
/// selecting an application root should also cover the child processes that own
/// its sockets. The walk stops at the first PID that cannot be resolved and is
/// bounded by a seen-set so a recycled or cyclic ppid cannot loop.
pub(super) fn process_names(pid: u32) -> Vec<String> {
    if pid == 0 {
        return Vec::new();
    }

    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = pid;
    while seen.insert(current) {
        if let Some(name) = process_name(current) {
            names.push(name);
        }
        match parent_pid(current) {
            Some(parent) => current = parent,
            None => break,
        }
    }
    names
}
