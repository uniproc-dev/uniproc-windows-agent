#[inline]
pub unsafe fn CloseHandle(hobject: HANDLE) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn CloseHandle(hobject : HANDLE) -> windows_core::BOOL);
    unsafe { CloseHandle(hobject) }
}
#[inline]
pub unsafe fn CloseServiceHandle(hscobject: SC_HANDLE) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn CloseServiceHandle(hscobject : SC_HANDLE) -> windows_core::BOOL);
    unsafe { CloseServiceHandle(hscobject) }
}
#[inline]
pub unsafe fn ControlService(
    hservice: SC_HANDLE,
    dwcontrol: u32,
    lpservicestatus: *mut SERVICE_STATUS,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn ControlService(hservice : SC_HANDLE, dwcontrol : u32, lpservicestatus : *mut SERVICE_STATUS) -> windows_core::BOOL);
    unsafe { ControlService(hservice, dwcontrol, lpservicestatus as _) }
}
#[inline]
pub unsafe fn ConvertStringSecurityDescriptorToSecurityDescriptorW<P0>(
    stringsecuritydescriptor: P0,
    stringsdrevision: u32,
    securitydescriptor: *mut PSECURITY_DESCRIPTOR,
    securitydescriptorsize: Option<*mut u32>,
) -> windows_core::BOOL
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("advapi32.dll" "system" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(stringsecuritydescriptor : windows_core::PCWSTR, stringsdrevision : u32, securitydescriptor : *mut PSECURITY_DESCRIPTOR, securitydescriptorsize : *mut u32) -> windows_core::BOOL);
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            stringsecuritydescriptor.param().abi(),
            stringsdrevision,
            securitydescriptor as _,
            securitydescriptorsize.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn CreateEventW<P3>(
    lpeventattributes: Option<*const SECURITY_ATTRIBUTES>,
    bmanualreset: bool,
    binitialstate: bool,
    lpname: P3,
) -> HANDLE
where
    P3: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn CreateEventW(lpeventattributes : *const SECURITY_ATTRIBUTES, bmanualreset : windows_core::BOOL, binitialstate : windows_core::BOOL, lpname : windows_core::PCWSTR) -> HANDLE);
    unsafe {
        CreateEventW(
            lpeventattributes.unwrap_or(core::mem::zeroed()) as _,
            bmanualreset.into(),
            binitialstate.into(),
            lpname.param().abi(),
        )
    }
}
#[inline]
pub unsafe fn EnumServicesStatusExW<P9>(
    hscmanager: SC_HANDLE,
    infolevel: SC_ENUM_TYPE,
    dwservicetype: u32,
    dwservicestate: u32,
    lpservices: Option<*mut u8>,
    cbbufsize: u32,
    pcbbytesneeded: *mut u32,
    lpservicesreturned: *mut u32,
    lpresumehandle: Option<*mut u32>,
    pszgroupname: P9,
) -> windows_core::BOOL
where
    P9: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("advapi32.dll" "system" fn EnumServicesStatusExW(hscmanager : SC_HANDLE, infolevel : SC_ENUM_TYPE, dwservicetype : u32, dwservicestate : u32, lpservices : *mut u8, cbbufsize : u32, pcbbytesneeded : *mut u32, lpservicesreturned : *mut u32, lpresumehandle : *mut u32, pszgroupname : windows_core::PCWSTR) -> windows_core::BOOL);
    unsafe {
        EnumServicesStatusExW(
            hscmanager,
            infolevel,
            dwservicetype,
            dwservicestate,
            lpservices.unwrap_or(core::mem::zeroed()) as _,
            cbbufsize,
            pcbbytesneeded as _,
            lpservicesreturned as _,
            lpresumehandle.unwrap_or(core::mem::zeroed()) as _,
            pszgroupname.param().abi(),
        )
    }
}
#[inline]
pub unsafe fn GetCurrentProcess() -> HANDLE {
    windows_core::link!("kernel32.dll" "system" fn GetCurrentProcess() -> HANDLE);
    unsafe { GetCurrentProcess() }
}
#[inline]
pub unsafe fn GetLastError() -> u32 {
    windows_core::link!("kernel32.dll" "system" fn GetLastError() -> u32);
    unsafe { GetLastError() }
}
#[inline]
pub unsafe fn GetTokenInformation(
    tokenhandle: HANDLE,
    tokeninformationclass: TOKEN_INFORMATION_CLASS,
    tokeninformation: Option<*mut core::ffi::c_void>,
    tokeninformationlength: u32,
    returnlength: *mut u32,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn GetTokenInformation(tokenhandle : HANDLE, tokeninformationclass : TOKEN_INFORMATION_CLASS, tokeninformation : *mut core::ffi::c_void, tokeninformationlength : u32, returnlength : *mut u32) -> windows_core::BOOL);
    unsafe {
        GetTokenInformation(
            tokenhandle,
            tokeninformationclass,
            tokeninformation.unwrap_or(core::mem::zeroed()) as _,
            tokeninformationlength,
            returnlength as _,
        )
    }
}
#[inline]
pub unsafe fn LocalFree(hmem: HLOCAL) -> HLOCAL {
    windows_core::link!("kernel32.dll" "system" fn LocalFree(hmem : HLOCAL) -> HLOCAL);
    unsafe { LocalFree(hmem) }
}
#[inline]
pub unsafe fn NotifyServiceStatusChangeW(
    hservice: SC_HANDLE,
    dwnotifymask: u32,
    pnotifybuffer: *const SERVICE_NOTIFY_2W,
) -> u32 {
    windows_core::link!("advapi32.dll" "system" fn NotifyServiceStatusChangeW(hservice : SC_HANDLE, dwnotifymask : u32, pnotifybuffer : *const SERVICE_NOTIFY_2W) -> u32);
    unsafe { NotifyServiceStatusChangeW(hservice, dwnotifymask, pnotifybuffer) }
}
#[inline]
pub unsafe fn OpenProcess(dwdesiredaccess: u32, binherithandle: bool, dwprocessid: u32) -> HANDLE {
    windows_core::link!("kernel32.dll" "system" fn OpenProcess(dwdesiredaccess : u32, binherithandle : windows_core::BOOL, dwprocessid : u32) -> HANDLE);
    unsafe { OpenProcess(dwdesiredaccess, binherithandle.into(), dwprocessid) }
}
#[inline]
pub unsafe fn OpenProcessToken(
    processhandle: HANDLE,
    desiredaccess: u32,
    tokenhandle: *mut HANDLE,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn OpenProcessToken(processhandle : HANDLE, desiredaccess : u32, tokenhandle : *mut HANDLE) -> windows_core::BOOL);
    unsafe { OpenProcessToken(processhandle, desiredaccess, tokenhandle as _) }
}
#[inline]
pub unsafe fn OpenSCManagerW<P0, P1>(
    lpmachinename: P0,
    lpdatabasename: P1,
    dwdesiredaccess: u32,
) -> SC_HANDLE
where
    P0: windows_core::Param<windows_core::PCWSTR>,
    P1: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("advapi32.dll" "system" fn OpenSCManagerW(lpmachinename : windows_core::PCWSTR, lpdatabasename : windows_core::PCWSTR, dwdesiredaccess : u32) -> SC_HANDLE);
    unsafe {
        OpenSCManagerW(
            lpmachinename.param().abi(),
            lpdatabasename.param().abi(),
            dwdesiredaccess,
        )
    }
}
#[inline]
pub unsafe fn OpenServiceW<P1>(
    hscmanager: SC_HANDLE,
    lpservicename: P1,
    dwdesiredaccess: u32,
) -> SC_HANDLE
where
    P1: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("advapi32.dll" "system" fn OpenServiceW(hscmanager : SC_HANDLE, lpservicename : windows_core::PCWSTR, dwdesiredaccess : u32) -> SC_HANDLE);
    unsafe { OpenServiceW(hscmanager, lpservicename.param().abi(), dwdesiredaccess) }
}
#[inline]
pub unsafe fn QueryServiceConfig2W(
    hservice: SC_HANDLE,
    dwinfolevel: u32,
    lpbuffer: Option<*mut u8>,
    cbbufsize: u32,
    pcbbytesneeded: *mut u32,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn QueryServiceConfig2W(hservice : SC_HANDLE, dwinfolevel : u32, lpbuffer : *mut u8, cbbufsize : u32, pcbbytesneeded : *mut u32) -> windows_core::BOOL);
    unsafe {
        QueryServiceConfig2W(
            hservice,
            dwinfolevel,
            lpbuffer.unwrap_or(core::mem::zeroed()) as _,
            cbbufsize,
            pcbbytesneeded as _,
        )
    }
}
#[inline]
pub unsafe fn QueryServiceConfigW(
    hservice: SC_HANDLE,
    lpserviceconfig: Option<*mut QUERY_SERVICE_CONFIGW>,
    cbbufsize: u32,
    pcbbytesneeded: *mut u32,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn QueryServiceConfigW(hservice : SC_HANDLE, lpserviceconfig : *mut QUERY_SERVICE_CONFIGW, cbbufsize : u32, pcbbytesneeded : *mut u32) -> windows_core::BOOL);
    unsafe {
        QueryServiceConfigW(
            hservice,
            lpserviceconfig.unwrap_or(core::mem::zeroed()) as _,
            cbbufsize,
            pcbbytesneeded as _,
        )
    }
}
#[inline]
pub unsafe fn QueryServiceStatusEx(
    hservice: SC_HANDLE,
    infolevel: SC_STATUS_TYPE,
    lpbuffer: Option<*mut u8>,
    cbbufsize: u32,
    pcbbytesneeded: *mut u32,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn QueryServiceStatusEx(hservice : SC_HANDLE, infolevel : SC_STATUS_TYPE, lpbuffer : *mut u8, cbbufsize : u32, pcbbytesneeded : *mut u32) -> windows_core::BOOL);
    unsafe {
        QueryServiceStatusEx(
            hservice,
            infolevel,
            lpbuffer.unwrap_or(core::mem::zeroed()) as _,
            cbbufsize,
            pcbbytesneeded as _,
        )
    }
}
#[inline]
pub unsafe fn SetEvent(hevent: HANDLE) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn SetEvent(hevent : HANDLE) -> windows_core::BOOL);
    unsafe { SetEvent(hevent) }
}
#[inline]
pub unsafe fn SetPriorityClass(hprocess: HANDLE, dwpriorityclass: u32) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn SetPriorityClass(hprocess : HANDLE, dwpriorityclass : u32) -> windows_core::BOOL);
    unsafe { SetPriorityClass(hprocess, dwpriorityclass) }
}
#[inline]
pub unsafe fn SetProcessAffinityMask(
    hprocess: HANDLE,
    dwprocessaffinitymask: usize,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn SetProcessAffinityMask(hprocess : HANDLE, dwprocessaffinitymask : usize) -> windows_core::BOOL);
    unsafe { SetProcessAffinityMask(hprocess, dwprocessaffinitymask) }
}
#[inline]
pub unsafe fn SetServiceObjectSecurity(
    hservice: SC_HANDLE,
    dwsecurityinformation: SECURITY_INFORMATION,
    lpsecuritydescriptor: PSECURITY_DESCRIPTOR,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn SetServiceObjectSecurity(hservice : SC_HANDLE, dwsecurityinformation : SECURITY_INFORMATION, lpsecuritydescriptor : PSECURITY_DESCRIPTOR) -> windows_core::BOOL);
    unsafe { SetServiceObjectSecurity(hservice, dwsecurityinformation, lpsecuritydescriptor) }
}
#[inline]
pub unsafe fn SleepEx(dwmilliseconds: u32, balertable: bool) -> u32 {
    windows_core::link!("kernel32.dll" "system" fn SleepEx(dwmilliseconds : u32, balertable : windows_core::BOOL) -> u32);
    unsafe { SleepEx(dwmilliseconds, balertable.into()) }
}
#[inline]
pub unsafe fn StartServiceW(
    hservice: SC_HANDLE,
    lpserviceargvectors: Option<&[windows_core::PCWSTR]>,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn StartServiceW(hservice : SC_HANDLE, dwnumserviceargs : u32, lpserviceargvectors : *const windows_core::PCWSTR) -> windows_core::BOOL);
    unsafe {
        StartServiceW(
            hservice,
            lpserviceargvectors.map_or(0, |slice| slice.len().try_into().unwrap()),
            lpserviceargvectors.map_or(core::ptr::null(), |slice| slice.as_ptr()),
        )
    }
}
#[inline]
pub unsafe fn TerminateProcess(hprocess: HANDLE, uexitcode: u32) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn TerminateProcess(hprocess : HANDLE, uexitcode : u32) -> windows_core::BOOL);
    unsafe { TerminateProcess(hprocess, uexitcode) }
}
#[inline]
pub unsafe fn WaitForSingleObjectEx(hhandle: HANDLE, dwmilliseconds: u32, balertable: bool) -> u32 {
    windows_core::link!("kernel32.dll" "system" fn WaitForSingleObjectEx(hhandle : HANDLE, dwmilliseconds : u32, balertable : windows_core::BOOL) -> u32);
    unsafe { WaitForSingleObjectEx(hhandle, dwmilliseconds, balertable.into()) }
}
pub const ABOVE_NORMAL_PRIORITY_CLASS: i32 = 32768;
pub const BELOW_NORMAL_PRIORITY_CLASS: i32 = 16384;
pub const DACL_SECURITY_INFORMATION: i32 = 4;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ENUM_SERVICE_STATUS_PROCESSW {
    pub lpServiceName: windows_core::PWSTR,
    pub lpDisplayName: windows_core::PWSTR,
    pub ServiceStatusProcess: SERVICE_STATUS_PROCESS,
}
pub const ERROR_SERVICE_NOTIFY_CLIENT_LAGGING: i32 = 1294;
pub const ERROR_SUCCESS: i32 = 0;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HANDLE(pub *mut core::ffi::c_void);
pub const HIGH_PRIORITY_CLASS: i32 = 128;
pub type HLOCAL = HANDLE;
pub const IDLE_PRIORITY_CLASS: i32 = 64;
pub const INFINITE: u32 = 4294967295;
pub const NORMAL_PRIORITY_CLASS: i32 = 32;
pub type PFN_SC_NOTIFY_CALLBACK =
    Option<unsafe extern "system" fn(pparameter: *const core::ffi::c_void)>;
pub const PROCESS_SET_INFORMATION: i32 = 512;
pub const PROCESS_SUSPEND_RESUME: i32 = 2048;
pub const PROCESS_TERMINATE: i32 = 1;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PSECURITY_DESCRIPTOR(pub *mut core::ffi::c_void);
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QUERY_SERVICE_CONFIGW {
    pub dwServiceType: u32,
    pub dwStartType: u32,
    pub dwErrorControl: u32,
    pub lpBinaryPathName: windows_core::PWSTR,
    pub lpLoadOrderGroup: windows_core::PWSTR,
    pub dwTagId: u32,
    pub lpDependencies: windows_core::PWSTR,
    pub lpServiceStartName: windows_core::PWSTR,
    pub lpDisplayName: windows_core::PWSTR,
}
pub const READ_CONTROL: i32 = 131072;
pub const REALTIME_PRIORITY_CLASS: i32 = 256;
pub const SC_ENUM_PROCESS_INFO: SC_ENUM_TYPE = 0;
pub type SC_ENUM_TYPE = i32;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SC_HANDLE(pub *mut core::ffi::c_void);
pub const SC_MANAGER_CONNECT: i32 = 1;
pub const SC_MANAGER_ENUMERATE_SERVICE: i32 = 4;
pub const SC_STATUS_PROCESS_INFO: SC_STATUS_TYPE = 0;
pub type SC_STATUS_TYPE = i32;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: u32,
    pub lpSecurityDescriptor: *mut core::ffi::c_void,
    pub bInheritHandle: windows_core::BOOL,
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SECURITY_INFORMATION(pub u32);
pub const SERVICE_CONFIG_DESCRIPTION: i32 = 1;
pub const SERVICE_CONTINUE_PENDING: i32 = 5;
pub const SERVICE_CONTROL_CONTINUE: i32 = 3;
pub const SERVICE_CONTROL_PAUSE: i32 = 2;
pub const SERVICE_CONTROL_STOP: i32 = 1;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SERVICE_DESCRIPTIONW {
    pub lpDescription: windows_core::PWSTR,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SERVICE_NOTIFY_2W {
    pub dwVersion: u32,
    pub pfnNotifyCallback: PFN_SC_NOTIFY_CALLBACK,
    pub pContext: *mut core::ffi::c_void,
    pub dwNotificationStatus: u32,
    pub ServiceStatus: SERVICE_STATUS_PROCESS,
    pub dwNotificationTriggered: u32,
    pub pszServiceNames: windows_core::PWSTR,
}
pub const SERVICE_NOTIFY_CONTINUE_PENDING: i32 = 16;
pub const SERVICE_NOTIFY_DELETE_PENDING: i32 = 512;
pub const SERVICE_NOTIFY_PAUSED: i32 = 64;
pub const SERVICE_NOTIFY_PAUSE_PENDING: i32 = 32;
pub const SERVICE_NOTIFY_RUNNING: i32 = 8;
pub const SERVICE_NOTIFY_START_PENDING: i32 = 2;
pub const SERVICE_NOTIFY_STATUS_CHANGE: i32 = 2;
pub const SERVICE_NOTIFY_STOPPED: i32 = 1;
pub const SERVICE_NOTIFY_STOP_PENDING: i32 = 4;
pub const SERVICE_PAUSED: i32 = 7;
pub const SERVICE_PAUSE_CONTINUE: i32 = 64;
pub const SERVICE_PAUSE_PENDING: i32 = 6;
pub const SERVICE_QUERY_CONFIG: i32 = 1;
pub const SERVICE_QUERY_STATUS: i32 = 4;
pub const SERVICE_RUNNING: i32 = 4;
pub const SERVICE_START: i32 = 16;
pub const SERVICE_START_PENDING: i32 = 2;
pub const SERVICE_STATE_ALL: i32 = 3;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SERVICE_STATUS {
    pub dwServiceType: u32,
    pub dwCurrentState: u32,
    pub dwControlsAccepted: u32,
    pub dwWin32ExitCode: u32,
    pub dwServiceSpecificExitCode: u32,
    pub dwCheckPoint: u32,
    pub dwWaitHint: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SERVICE_STATUS_PROCESS {
    pub dwServiceType: u32,
    pub dwCurrentState: u32,
    pub dwControlsAccepted: u32,
    pub dwWin32ExitCode: u32,
    pub dwServiceSpecificExitCode: u32,
    pub dwCheckPoint: u32,
    pub dwWaitHint: u32,
    pub dwProcessId: u32,
    pub dwServiceFlags: u32,
}
pub const SERVICE_STOP: i32 = 32;
pub const SERVICE_STOPPED: i32 = 1;
pub const SERVICE_STOP_PENDING: i32 = 3;
pub const SERVICE_WIN32: i32 = 48;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TOKEN_ELEVATION {
    pub TokenIsElevated: u32,
}
pub type TOKEN_INFORMATION_CLASS = i32;
pub const TOKEN_QUERY: i32 = 8;
pub const TokenElevation: TOKEN_INFORMATION_CLASS = 20;
pub const WRITE_DAC: i32 = 262144;
