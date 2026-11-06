#[inline]
pub unsafe fn SetStdHandle(nstdhandle: u32, hhandle: HANDLE) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn SetStdHandle(nstdhandle : u32, hhandle : HANDLE) -> windows_core::BOOL);
    unsafe { SetStdHandle(nstdhandle, hhandle) }
}
pub const CREATE_NO_WINDOW: i32 = 134217728;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HANDLE(pub *mut core::ffi::c_void);
pub const STD_ERROR_HANDLE: u32 = 4294967284;
