//! Windows source-process name resolution via Win32 `iphlpapi`/`kernel32`.

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW},
};

/// Resolve a PID to its executable basename using `QueryFullProcessImageNameW`.
///
/// Uses `PROCESS_QUERY_LIMITED_INFORMATION`, which the elevated context that TUN
/// setup already requires can open for other processes. Returns `None` on any
/// failure (process gone, access denied, oversized path) so the caller simply
/// treats the session as non-matching.
pub(super) fn process_name(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
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
