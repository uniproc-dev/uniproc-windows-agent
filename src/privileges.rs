use anyhow::{Result, bail};
use windows::Win32::Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

/// Turns on a privilege the process token already holds.
///
/// Fails when the token does not hold it at all: `AdjustTokenPrivileges`
/// reports that through the last error while still returning success.
pub fn enable(name: PCWSTR) -> Result<()> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?
    };

    let adjusted = adjust(token, name);
    let _ = unsafe { CloseHandle(token) };
    adjusted
}

fn adjust(token: HANDLE, name: PCWSTR) -> Result<()> {
    let mut luid = Default::default();
    unsafe { LookupPrivilegeValueW(None, name, &mut luid)? };

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe { AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None)? };

    if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
        bail!(
            "the process token does not hold {}",
            unsafe { name.to_string() }.unwrap_or_default()
        );
    }
    Ok(())
}
