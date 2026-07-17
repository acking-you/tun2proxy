use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::Console::{
    AttachConsole, FreeConsole, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCtrlHandler, SetStdHandle,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NO_CONSOLE, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

const ELEVATED_CONSOLE_PID_ARG: &str = "--elevated-console-pid";

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct IgnoreCtrlC;

impl IgnoreCtrlC {
    fn install() -> io::Result<Self> {
        if unsafe { SetConsoleCtrlHandler(Some(ignore_ctrl_c), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self)
    }
}

impl Drop for IgnoreCtrlC {
    fn drop(&mut self) {
        unsafe {
            SetConsoleCtrlHandler(Some(ignore_ctrl_c), 0);
        }
    }
}

unsafe extern "system" fn ignore_ctrl_c(_: u32) -> i32 {
    1
}

/// Detach the elevated child from any console created by the UAC broker and
/// reconnect it to the terminal that launched the original process.
pub fn attach_to_parent_console(parent_pid: u32) -> io::Result<()> {
    unsafe {
        // FreeConsole may report that no console is attached. Either way,
        // attaching to the original process is the next required operation.
        FreeConsole();
        if AttachConsole(parent_pid) == 0 {
            return Err(io::Error::last_os_error());
        }
    }

    reconnect_standard_handles()
}

/// Relaunch the current executable through UAC when its token is not elevated.
/// The original process stays attached to its terminal and waits for the child,
/// returning the child's exit code to the caller.
pub fn relaunch_if_needed() -> io::Result<Option<u32>> {
    if is_elevated()? {
        return Ok(None);
    }

    let executable = std::env::current_exe()?;
    let mut arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    arguments.push(ELEVATED_CONSOLE_PID_ARG.into());
    arguments.push(unsafe { GetCurrentProcessId() }.to_string().into());
    let parameters = build_command_line(arguments);
    let executable = null_terminated(executable.as_os_str());
    let working_directory = std::env::current_dir().ok().map(|path| null_terminated(path.as_os_str()));
    let verb = null_terminated(OsStr::new("runas"));

    eprintln!("Administrator privileges are required; requesting elevation through UAC...");

    let mut execute_info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        // Some UAC broker paths ignore NO_CONSOLE. SW_HIDE suppresses their
        // bootstrap console, then the child attaches to this process explicitly.
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_NO_CONSOLE,
        hwnd: null_mut(),
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: working_directory.as_ref().map_or(null(), |path| path.as_ptr()),
        nShow: SW_HIDE,
        ..Default::default()
    };

    let _ctrl_c = IgnoreCtrlC::install()?;
    if unsafe { ShellExecuteExW(&raw mut execute_info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if execute_info.hProcess.is_null() {
        return Err(io::Error::other("the elevated process did not return a process handle"));
    }
    let process = OwnedHandle(execute_info.hProcess);

    let wait_result = unsafe { WaitForSingleObject(process.0, INFINITE) };
    if wait_result == WAIT_FAILED {
        return Err(io::Error::last_os_error());
    }
    if wait_result != WAIT_OBJECT_0 {
        return Err(io::Error::other(format!("unexpected elevated process wait result: {wait_result}")));
    }

    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(process.0, &raw mut exit_code) } == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(Some(exit_code))
}

fn reconnect_standard_handles() -> io::Result<()> {
    let input_name = null_terminated(OsStr::new("CONIN$"));
    let output_name = null_terminated(OsStr::new("CONOUT$"));
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;

    let input = unsafe {
        CreateFileW(
            input_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            share,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if input == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }

    let output = unsafe {
        CreateFileW(
            output_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            share,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if output == INVALID_HANDLE_VALUE {
        unsafe {
            CloseHandle(input);
        }
        return Err(io::Error::last_os_error());
    }

    let handles_set = unsafe {
        SetStdHandle(STD_INPUT_HANDLE, input) != 0
            && SetStdHandle(STD_OUTPUT_HANDLE, output) != 0
            && SetStdHandle(STD_ERROR_HANDLE, output) != 0
    };
    if !handles_set {
        unsafe {
            CloseHandle(input);
            CloseHandle(output);
        }
        return Err(io::Error::last_os_error());
    }

    // These are now the process standard handles and must remain open. Windows
    // closes them when the elevated child exits.
    Ok(())
}

fn is_elevated() -> io::Result<bool> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned_size = 0;
    let success = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&raw mut elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned_size,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(elevation.TokenIsElevated != 0)
}

fn null_terminated(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn build_command_line(args: impl IntoIterator<Item = OsString>) -> Vec<u16> {
    let mut command_line = Vec::new();
    for argument in args {
        if !command_line.is_empty() {
            command_line.push(b' ' as u16);
        }
        append_quoted_argument(&mut command_line, argument.as_os_str());
    }
    command_line.push(0);
    command_line
}

// Quote one argument according to the CommandLineToArgvW/MSVC parsing rules.
// In particular, backslashes immediately before a quote or the closing quote
// must be doubled so paths and credentials survive the elevated relaunch.
fn append_quoted_argument(command_line: &mut Vec<u16>, argument: &OsStr) {
    let argument: Vec<u16> = argument.encode_wide().collect();
    let needs_quotes = argument.is_empty()
        || argument
            .iter()
            .any(|value| *value == b' ' as u16 || *value == b'\t' as u16 || *value == b'"' as u16);

    if !needs_quotes {
        command_line.extend(argument);
        return;
    }

    command_line.push(b'"' as u16);
    let mut backslashes = 0;
    for value in argument {
        if value == b'\\' as u16 {
            backslashes += 1;
            continue;
        }

        if value == b'"' as u16 {
            command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
        } else {
            command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
        }
        backslashes = 0;
        command_line.push(value);
    }

    command_line.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    command_line.push(b'"' as u16);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_line(args: &[&str]) -> String {
        let wide = build_command_line(args.iter().map(OsString::from));
        String::from_utf16(&wide[..wide.len() - 1]).unwrap()
    }

    #[test]
    fn quotes_empty_and_whitespace_arguments() {
        assert_eq!(
            command_line(&["--proxy", "http://127.0.0.1:8080", "", "two words"]),
            "--proxy http://127.0.0.1:8080 \"\" \"two words\""
        );
    }

    #[test]
    fn escapes_quotes_and_trailing_backslashes() {
        assert_eq!(
            command_line(&["a\"b", r"C:\path with spaces\"]),
            r#""a\"b" "C:\path with spaces\\""#
        );
    }

    #[test]
    fn leaves_simple_backslashes_unquoted() {
        assert_eq!(command_line(&[r"C:\proxy\config.toml"]), r"C:\proxy\config.toml");
    }
}
