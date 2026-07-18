//! Windows source-process identity resolution.

use std::collections::{HashMap, HashSet};
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS},
        Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW},
    },
};

#[derive(Debug)]
struct SnapshotProcess {
    name: String,
    parent_pid: u32,
}

/// Resolve the executable names of a PID and its live ancestor chain.
///
/// `PROCESSENTRY32W::szExeFile` comes from the system-wide ToolHelp snapshot and
/// does not require opening the target process. This matters for games guarded
/// by anti-cheat software: even an elevated caller can be denied an
/// `OpenProcess` handle while the process and its sockets remain visible in the
/// system tables. Ancestors are returned as well so selecting a launcher or a
/// Task Manager-style application root also covers the child processes that
/// actually own the game's TCP/UDP sockets.
pub(super) fn process_names(pid: u32) -> Vec<String> {
    if pid == 0 {
        return Vec::new();
    }

    let processes = toolhelp_processes();
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    let mut current = pid;
    while current != 0 && seen.insert(current) {
        let Some(process) = processes.get(&current) else {
            break;
        };
        if !process.name.is_empty() {
            names.push(process.name.clone());
        }
        current = process.parent_pid;
    }

    // A process can start or exit while ToolHelp is taking its snapshot. Keep
    // the path query as a narrow fallback for that race and older environments
    // where snapshot creation fails.
    if names.is_empty() {
        if let Some(name) = process_name_from_handle(pid) {
            names.push(name);
        }
    }
    names
}

fn toolhelp_processes() -> HashMap<u32, SnapshotProcess> {
    // SAFETY: the returned snapshot handle is validated, used only by the
    // ToolHelp iteration functions, and closed exactly once before returning.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return HashMap::new();
    }

    let mut processes = HashMap::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: `entry.dwSize` identifies the exact structure version and `entry`
    // remains writable for the complete iteration.
    let mut available = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while available {
        let end = entry
            .szExeFile
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
        processes.insert(
            entry.th32ProcessID,
            SnapshotProcess {
                name,
                parent_pid: entry.th32ParentProcessID,
            },
        );
        // SAFETY: same valid snapshot and writable entry as Process32FirstW.
        available = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    // SAFETY: `snapshot` is a valid owned handle and is not used afterwards.
    unsafe { CloseHandle(snapshot) };
    processes
}

/// Resolve a PID through a process handle when ToolHelp missed it.
///
/// Uses `PROCESS_QUERY_LIMITED_INFORMATION`, which the elevated context that TUN
/// setup already requires can normally open for other processes. Protected
/// processes may still reject it, which is why ToolHelp is the primary source.
fn process_name_from_handle(pid: u32) -> Option<String> {
    // Heap buffer large enough for the Windows extended path limit so we never
    // fail a real path with ERROR_INSUFFICIENT_BUFFER.
    let mut buf = vec![0u16; 32_768];
    let mut size = buf.len() as u32;

    // SAFETY: `handle` is checked for null before use and always closed; the
    // buffer/size pair passed to QueryFullProcessImageNameW is valid for `size`
    // u16s and the function writes at most `size` code units, updating `size`.
    let name = unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut size);
        CloseHandle(handle);
        if ok == 0 || size == 0 {
            return None;
        }
        String::from_utf16_lossy(&buf[..size as usize])
    };

    std::path::Path::new(&name)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}
