use windows::Win32::{HANDLE, OpenProcess};
use windows::core::{Error, GUID, Result};

pub const PROCESS_NAME_WIN32: u32 = 0;

pub const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID =
    GUID::from_u128(0x00aac56b_cd44_11d0_8cc2_00c04fc295ee);

pub fn open_process(access: i32, pid: u32) -> Result<HANDLE> {
    let handle = unsafe { OpenProcess(access as u32, false, pid) };
    if handle.0.is_null() {
        Err(Error::from_thread())
    } else {
        Ok(handle)
    }
}
