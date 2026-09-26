use anyhow::{Result, bail};
use windows::Win32::{
    AdjustTokenPrivileges, CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetCurrentProcess, GetLastError,
    HANDLE, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, OpenProcessToken, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
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
            (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) as u32,
            &mut token,
        )
        .ok()?
    };

    let adjusted = adjust(token, name);
    let _ = unsafe { CloseHandle(token) };
    adjusted
}

fn adjust(token: HANDLE, name: PCWSTR) -> Result<()> {
    let mut luid = Default::default();
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid).ok()? };

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED as u32,
        }],
    };

    unsafe { AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None).ok()? };

    if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED as u32 {
        bail!(
            "the process token does not hold {}",
            unsafe { name.to_string() }.unwrap_or_default()
        );
    }
    Ok(())
}
