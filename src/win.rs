use windows::Win32::{HANDLE, OpenProcess};
use windows::core::{Error, Result};

pub fn open_process(access: i32, pid: u32) -> Result<HANDLE> {
    let handle = unsafe { OpenProcess(access as u32, false, pid) };
    if handle.0.is_null() {
        Err(Error::from_thread())
    } else {
        Ok(handle)
    }
}

/// The Win32 code behind an error: the low half of a FACILITY_WIN32 HRESULT, any other as it is.
pub fn win32_code(e: &Error) -> u32 {
    let hresult = e.code().0 as u32;
    if hresult & 0xFFFF_0000 == 0x8007_0000 {
        hresult & 0xFFFF
    } else {
        hresult
    }
}
