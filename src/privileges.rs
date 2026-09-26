use anyhow::Result;
use windows::Win32::{
    CloseHandle, GetCurrentProcess, GetTokenInformation, HANDLE, OpenProcessToken,
    TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};

/// Whether this process runs with the full, elevated token.
pub fn is_elevated() -> Result<bool> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY as u32, &mut token).ok()? };

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut _),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    let _ = unsafe { CloseHandle(token) };
    queried.ok()?;
    Ok(elevation.TokenIsElevated != 0)
}
