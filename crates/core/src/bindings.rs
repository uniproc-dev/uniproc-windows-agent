#[inline]
pub unsafe fn AdjustTokenPrivileges(
    tokenhandle: HANDLE,
    disableallprivileges: bool,
    newstate: Option<*const TOKEN_PRIVILEGES>,
    bufferlength: u32,
    previousstate: Option<*mut TOKEN_PRIVILEGES>,
    returnlength: Option<*mut u32>,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn AdjustTokenPrivileges(tokenhandle : HANDLE, disableallprivileges : windows_core::BOOL, newstate : *const TOKEN_PRIVILEGES, bufferlength : u32, previousstate : *mut TOKEN_PRIVILEGES, returnlength : *mut u32) -> windows_core::BOOL);
    unsafe {
        AdjustTokenPrivileges(
            tokenhandle,
            disableallprivileges.into(),
            newstate.unwrap_or(core::mem::zeroed()) as _,
            bufferlength,
            previousstate.unwrap_or(core::mem::zeroed()) as _,
            returnlength.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn AreDpiAwarenessContextsEqual(
    dpicontexta: DPI_AWARENESS_CONTEXT,
    dpicontextb: DPI_AWARENESS_CONTEXT,
) -> windows_core::BOOL {
    windows_core::link!("user32.dll" "system" fn AreDpiAwarenessContextsEqual(dpicontexta : DPI_AWARENESS_CONTEXT, dpicontextb : DPI_AWARENESS_CONTEXT) -> windows_core::BOOL);
    unsafe { AreDpiAwarenessContextsEqual(dpicontexta, dpicontextb) }
}
#[inline]
pub unsafe fn CallNtPowerInformation(
    informationlevel: POWER_INFORMATION_LEVEL,
    inputbuffer: Option<*const core::ffi::c_void>,
    inputbufferlength: u32,
    outputbuffer: Option<*mut core::ffi::c_void>,
    outputbufferlength: u32,
) -> i32 {
    windows_core::link!("powrprof.dll" "system" fn CallNtPowerInformation(informationlevel : POWER_INFORMATION_LEVEL, inputbuffer : *const core::ffi::c_void, inputbufferlength : u32, outputbuffer : *mut core::ffi::c_void, outputbufferlength : u32) -> i32);
    unsafe {
        CallNtPowerInformation(
            informationlevel,
            inputbuffer.unwrap_or(core::mem::zeroed()) as _,
            inputbufferlength,
            outputbuffer.unwrap_or(core::mem::zeroed()) as _,
            outputbufferlength,
        )
    }
}
#[inline]
pub unsafe fn CertGetNameStringW(
    pcertcontext: *const CERT_CONTEXT,
    dwtype: u32,
    dwflags: u32,
    pvtypepara: Option<*const core::ffi::c_void>,
    psznamestring: Option<windows_core::PWSTR>,
    cchnamestring: u32,
) -> u32 {
    windows_core::link!("crypt32.dll" "system" fn CertGetNameStringW(pcertcontext : *const CERT_CONTEXT, dwtype : u32, dwflags : u32, pvtypepara : *const core::ffi::c_void, psznamestring : windows_core::PWSTR, cchnamestring : u32) -> u32);
    unsafe {
        CertGetNameStringW(
            pcertcontext,
            dwtype,
            dwflags,
            pvtypepara.unwrap_or(core::mem::zeroed()) as _,
            psznamestring.unwrap_or(core::mem::zeroed()) as _,
            cchnamestring,
        )
    }
}
#[inline]
pub unsafe fn CertVerifyCertificateChainPolicy<P0>(
    pszpolicyoid: P0,
    pchaincontext: *const CERT_CHAIN_CONTEXT,
    ppolicypara: *const CERT_CHAIN_POLICY_PARA,
    ppolicystatus: *mut CERT_CHAIN_POLICY_STATUS,
) -> windows_core::BOOL
where
    P0: windows_core::Param<windows_core::PCSTR>,
{
    windows_core::link!("crypt32.dll" "system" fn CertVerifyCertificateChainPolicy(pszpolicyoid : windows_core::PCSTR, pchaincontext : *const CERT_CHAIN_CONTEXT, ppolicypara : *const CERT_CHAIN_POLICY_PARA, ppolicystatus : *mut CERT_CHAIN_POLICY_STATUS) -> windows_core::BOOL);
    unsafe {
        CertVerifyCertificateChainPolicy(
            pszpolicyoid.param().abi(),
            pchaincontext,
            ppolicypara,
            ppolicystatus as _,
        )
    }
}
#[inline]
pub unsafe fn CloseHandle(hobject: HANDLE) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn CloseHandle(hobject : HANDLE) -> windows_core::BOOL);
    unsafe { CloseHandle(hobject) }
}
#[inline]
pub unsafe fn CommandLineToArgvW<P0>(lpcmdline: P0, pnumargs: *mut i32) -> *mut windows_core::PWSTR
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("shell32.dll" "system" fn CommandLineToArgvW(lpcmdline : windows_core::PCWSTR, pnumargs : *mut i32) -> *mut windows_core::PWSTR);
    unsafe { CommandLineToArgvW(lpcmdline.param().abi(), pnumargs as _) }
}
#[inline]
pub unsafe fn ConvertSidToStringSidW(
    sid: PSID,
    stringsid: *mut windows_core::PWSTR,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn ConvertSidToStringSidW(sid : PSID, stringsid : *mut windows_core::PWSTR) -> windows_core::BOOL);
    unsafe { ConvertSidToStringSidW(sid, stringsid as _) }
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
pub unsafe fn CreateDirectoryW<P0>(
    lppathname: P0,
    lpsecurityattributes: Option<*const SECURITY_ATTRIBUTES>,
) -> windows_core::BOOL
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn CreateDirectoryW(lppathname : windows_core::PCWSTR, lpsecurityattributes : *const SECURITY_ATTRIBUTES) -> windows_core::BOOL);
    unsafe {
        CreateDirectoryW(
            lppathname.param().abi(),
            lpsecurityattributes.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn CreateFileMappingW<P5>(
    hfile: HANDLE,
    lpfilemappingattributes: Option<*const SECURITY_ATTRIBUTES>,
    flprotect: u32,
    dwmaximumsizehigh: u32,
    dwmaximumsizelow: u32,
    lpname: P5,
) -> HANDLE
where
    P5: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn CreateFileMappingW(hfile : HANDLE, lpfilemappingattributes : *const SECURITY_ATTRIBUTES, flprotect : u32, dwmaximumsizehigh : u32, dwmaximumsizelow : u32, lpname : windows_core::PCWSTR) -> HANDLE);
    unsafe {
        CreateFileMappingW(
            hfile,
            lpfilemappingattributes.unwrap_or(core::mem::zeroed()) as _,
            flprotect,
            dwmaximumsizehigh,
            dwmaximumsizelow,
            lpname.param().abi(),
        )
    }
}
#[inline]
pub unsafe fn CreateFileW<P0>(
    lpfilename: P0,
    dwdesiredaccess: u32,
    dwsharemode: u32,
    lpsecurityattributes: Option<*const SECURITY_ATTRIBUTES>,
    dwcreationdisposition: u32,
    dwflagsandattributes: u32,
    htemplatefile: Option<HANDLE>,
) -> HANDLE
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn CreateFileW(lpfilename : windows_core::PCWSTR, dwdesiredaccess : u32, dwsharemode : u32, lpsecurityattributes : *const SECURITY_ATTRIBUTES, dwcreationdisposition : u32, dwflagsandattributes : u32, htemplatefile : HANDLE) -> HANDLE);
    unsafe {
        CreateFileW(
            lpfilename.param().abi(),
            dwdesiredaccess,
            dwsharemode,
            lpsecurityattributes.unwrap_or(core::mem::zeroed()) as _,
            dwcreationdisposition,
            dwflagsandattributes,
            htemplatefile.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn CryptCATAdminAcquireContext2<P2>(
    phcatadmin: *mut HCATADMIN,
    pgsubsystem: Option<*const windows_core::GUID>,
    pwszhashalgorithm: P2,
    pstronghashpolicy: Option<*const CERT_STRONG_SIGN_PARA>,
    dwflags: Option<u32>,
) -> windows_core::BOOL
where
    P2: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("wintrust.dll" "system" fn CryptCATAdminAcquireContext2(phcatadmin : *mut HCATADMIN, pgsubsystem : *const windows_core::GUID, pwszhashalgorithm : windows_core::PCWSTR, pstronghashpolicy : *const CERT_STRONG_SIGN_PARA, dwflags : u32) -> windows_core::BOOL);
    unsafe {
        CryptCATAdminAcquireContext2(
            phcatadmin as _,
            pgsubsystem.unwrap_or(core::mem::zeroed()) as _,
            pwszhashalgorithm.param().abi(),
            pstronghashpolicy.unwrap_or(core::mem::zeroed()) as _,
            dwflags.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn CryptCATAdminCalcHashFromFileHandle2(
    hcatadmin: HCATADMIN,
    hfile: HANDLE,
    pcbhash: *mut u32,
    pbhash: Option<*mut u8>,
    dwflags: Option<u32>,
) -> windows_core::BOOL {
    windows_core::link!("wintrust.dll" "system" fn CryptCATAdminCalcHashFromFileHandle2(hcatadmin : HCATADMIN, hfile : HANDLE, pcbhash : *mut u32, pbhash : *mut u8, dwflags : u32) -> windows_core::BOOL);
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            hcatadmin,
            hfile,
            pcbhash as _,
            pbhash.unwrap_or(core::mem::zeroed()) as _,
            dwflags.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn CryptCATAdminEnumCatalogFromHash(
    hcatadmin: HCATADMIN,
    pbhash: &[u8],
    dwflags: Option<u32>,
    phprevcatinfo: Option<*mut HCATINFO>,
) -> HCATINFO {
    windows_core::link!("wintrust.dll" "system" fn CryptCATAdminEnumCatalogFromHash(hcatadmin : HCATADMIN, pbhash : *const u8, cbhash : u32, dwflags : u32, phprevcatinfo : *mut HCATINFO) -> HCATINFO);
    unsafe {
        CryptCATAdminEnumCatalogFromHash(
            hcatadmin,
            pbhash.as_ptr(),
            pbhash.len().try_into().unwrap(),
            dwflags.unwrap_or(core::mem::zeroed()) as _,
            phprevcatinfo.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn CryptCATAdminReleaseCatalogContext(
    hcatadmin: HCATADMIN,
    hcatinfo: HCATINFO,
    dwflags: u32,
) -> windows_core::BOOL {
    windows_core::link!("wintrust.dll" "system" fn CryptCATAdminReleaseCatalogContext(hcatadmin : HCATADMIN, hcatinfo : HCATINFO, dwflags : u32) -> windows_core::BOOL);
    unsafe { CryptCATAdminReleaseCatalogContext(hcatadmin, hcatinfo, dwflags) }
}
#[inline]
pub unsafe fn CryptCATAdminReleaseContext(
    hcatadmin: HCATADMIN,
    dwflags: u32,
) -> windows_core::BOOL {
    windows_core::link!("wintrust.dll" "system" fn CryptCATAdminReleaseContext(hcatadmin : HCATADMIN, dwflags : u32) -> windows_core::BOOL);
    unsafe { CryptCATAdminReleaseContext(hcatadmin, dwflags) }
}
#[inline]
pub unsafe fn CryptCATCatalogInfoFromContext(
    hcatinfo: HCATINFO,
    pscatinfo: *mut CATALOG_INFO,
    dwflags: u32,
) -> windows_core::BOOL {
    windows_core::link!("wintrust.dll" "system" fn CryptCATCatalogInfoFromContext(hcatinfo : HCATINFO, pscatinfo : *mut CATALOG_INFO, dwflags : u32) -> windows_core::BOOL);
    unsafe { CryptCATCatalogInfoFromContext(hcatinfo, pscatinfo as _, dwflags) }
}
#[inline]
pub unsafe fn D3DKMTCloseAdapter(param0: *const D3DKMT_CLOSEADAPTER) -> windows_core::NTSTATUS {
    windows_core::link!("gdi32.dll" "system" fn D3DKMTCloseAdapter(param0 : *const D3DKMT_CLOSEADAPTER) -> windows_core::NTSTATUS);
    unsafe { D3DKMTCloseAdapter(param0) }
}
#[inline]
pub unsafe fn D3DKMTEnumAdapters2(param0: *mut D3DKMT_ENUMADAPTERS2) -> windows_core::NTSTATUS {
    windows_core::link!("gdi32.dll" "system" fn D3DKMTEnumAdapters2(param0 : *mut D3DKMT_ENUMADAPTERS2) -> windows_core::NTSTATUS);
    unsafe { D3DKMTEnumAdapters2(param0 as _) }
}
#[inline]
pub unsafe fn D3DKMTQueryAdapterInfo(
    param0: *mut D3DKMT_QUERYADAPTERINFO,
) -> windows_core::NTSTATUS {
    windows_core::link!("gdi32.dll" "system" fn D3DKMTQueryAdapterInfo(param0 : *mut D3DKMT_QUERYADAPTERINFO) -> windows_core::NTSTATUS);
    unsafe { D3DKMTQueryAdapterInfo(param0 as _) }
}
#[inline]
pub unsafe fn D3DKMTQueryStatistics(
    param0: *const D3DKMT_QUERYSTATISTICS,
) -> windows_core::NTSTATUS {
    windows_core::link!("gdi32.dll" "system" fn D3DKMTQueryStatistics(param0 : *const D3DKMT_QUERYSTATISTICS) -> windows_core::NTSTATUS);
    unsafe { D3DKMTQueryStatistics(param0) }
}
#[inline]
pub unsafe fn DeviceIoControl(
    hdevice: HANDLE,
    dwiocontrolcode: u32,
    lpinbuffer: Option<*const core::ffi::c_void>,
    ninbuffersize: u32,
    lpoutbuffer: Option<*mut core::ffi::c_void>,
    noutbuffersize: u32,
    lpbytesreturned: Option<*mut u32>,
    lpoverlapped: Option<*mut OVERLAPPED>,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn DeviceIoControl(hdevice : HANDLE, dwiocontrolcode : u32, lpinbuffer : *const core::ffi::c_void, ninbuffersize : u32, lpoutbuffer : *mut core::ffi::c_void, noutbuffersize : u32, lpbytesreturned : *mut u32, lpoverlapped : *mut OVERLAPPED) -> windows_core::BOOL);
    unsafe {
        DeviceIoControl(
            hdevice,
            dwiocontrolcode,
            lpinbuffer.unwrap_or(core::mem::zeroed()) as _,
            ninbuffersize,
            lpoutbuffer.unwrap_or(core::mem::zeroed()) as _,
            noutbuffersize,
            lpbytesreturned.unwrap_or(core::mem::zeroed()) as _,
            lpoverlapped.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn DuplicateHandle(
    hsourceprocesshandle: HANDLE,
    hsourcehandle: HANDLE,
    htargetprocesshandle: HANDLE,
    lptargethandle: *mut HANDLE,
    dwdesiredaccess: u32,
    binherithandle: bool,
    dwoptions: u32,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn DuplicateHandle(hsourceprocesshandle : HANDLE, hsourcehandle : HANDLE, htargetprocesshandle : HANDLE, lptargethandle : *mut HANDLE, dwdesiredaccess : u32, binherithandle : windows_core::BOOL, dwoptions : u32) -> windows_core::BOOL);
    unsafe {
        DuplicateHandle(
            hsourceprocesshandle,
            hsourcehandle,
            htargetprocesshandle,
            lptargethandle as _,
            dwdesiredaccess,
            binherithandle.into(),
            dwoptions,
        )
    }
}
#[inline]
pub unsafe fn EnumProcessModulesEx(
    hprocess: HANDLE,
    lphmodule: *mut HMODULE,
    cb: u32,
    lpcbneeded: *mut u32,
    dwfilterflag: u32,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" "K32EnumProcessModulesEx" fn EnumProcessModulesEx(hprocess : HANDLE, lphmodule : *mut HMODULE, cb : u32, lpcbneeded : *mut u32, dwfilterflag : u32) -> windows_core::BOOL);
    unsafe { EnumProcessModulesEx(hprocess, lphmodule as _, cb, lpcbneeded as _, dwfilterflag) }
}
#[inline]
pub unsafe fn FreeLibrary(hlibmodule: HMODULE) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn FreeLibrary(hlibmodule : HMODULE) -> windows_core::BOOL);
    unsafe { FreeLibrary(hlibmodule) }
}
#[inline]
pub unsafe fn FreeMibTable(memory: *const core::ffi::c_void) {
    windows_core::link!("iphlpapi.dll" "system" fn FreeMibTable(memory : *const core::ffi::c_void));
    unsafe { FreeMibTable(memory) }
}
#[inline]
pub unsafe fn GetActiveProcessorCount(groupnumber: u16) -> u32 {
    windows_core::link!("kernel32.dll" "system" fn GetActiveProcessorCount(groupnumber : u16) -> u32);
    unsafe { GetActiveProcessorCount(groupnumber) }
}
#[inline]
pub unsafe fn GetActiveProcessorGroupCount() -> u16 {
    windows_core::link!("kernel32.dll" "system" fn GetActiveProcessorGroupCount() -> u16);
    unsafe { GetActiveProcessorGroupCount() }
}
#[inline]
pub unsafe fn GetApplicationUserModelId(
    hprocess: HANDLE,
    applicationusermodelidlength: *mut u32,
    applicationusermodelid: Option<windows_core::PWSTR>,
) -> i32 {
    windows_core::link!("kernel32.dll" "system" fn GetApplicationUserModelId(hprocess : HANDLE, applicationusermodelidlength : *mut u32, applicationusermodelid : windows_core::PWSTR) -> i32);
    unsafe {
        GetApplicationUserModelId(
            hprocess,
            applicationusermodelidlength as _,
            applicationusermodelid.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn GetCurrentProcess() -> HANDLE {
    windows_core::link!("kernel32.dll" "system" fn GetCurrentProcess() -> HANDLE);
    unsafe { GetCurrentProcess() }
}
#[inline]
pub unsafe fn GetCurrentProcessId() -> u32 {
    windows_core::link!("kernel32.dll" "system" fn GetCurrentProcessId() -> u32);
    unsafe { GetCurrentProcessId() }
}
#[inline]
pub unsafe fn GetDpiAwarenessContextForProcess(hprocess: HANDLE) -> DPI_AWARENESS_CONTEXT {
    windows_core::link!("user32.dll" "system" fn GetDpiAwarenessContextForProcess(hprocess : HANDLE) -> DPI_AWARENESS_CONTEXT);
    unsafe { GetDpiAwarenessContextForProcess(hprocess) }
}
#[inline]
pub unsafe fn GetDriveTypeW<P0>(lprootpathname: P0) -> u32
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn GetDriveTypeW(lprootpathname : windows_core::PCWSTR) -> u32);
    unsafe { GetDriveTypeW(lprootpathname.param().abi()) }
}
#[inline]
pub unsafe fn GetFileInformationByHandle(
    hfile: HANDLE,
    lpfileinformation: *mut BY_HANDLE_FILE_INFORMATION,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn GetFileInformationByHandle(hfile : HANDLE, lpfileinformation : *mut BY_HANDLE_FILE_INFORMATION) -> windows_core::BOOL);
    unsafe { GetFileInformationByHandle(hfile, lpfileinformation as _) }
}
#[inline]
pub unsafe fn GetFileInformationByHandleEx(
    hfile: HANDLE,
    fileinformationclass: FILE_INFO_BY_HANDLE_CLASS,
    lpfileinformation: *mut core::ffi::c_void,
    dwbuffersize: u32,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn GetFileInformationByHandleEx(hfile : HANDLE, fileinformationclass : FILE_INFO_BY_HANDLE_CLASS, lpfileinformation : *mut core::ffi::c_void, dwbuffersize : u32) -> windows_core::BOOL);
    unsafe {
        GetFileInformationByHandleEx(
            hfile,
            fileinformationclass,
            lpfileinformation as _,
            dwbuffersize,
        )
    }
}
#[inline]
pub unsafe fn GetFileVersionInfoSizeW<P0>(lptstrfilename: P0, lpdwhandle: Option<*mut u32>) -> u32
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("version.dll" "system" fn GetFileVersionInfoSizeW(lptstrfilename : windows_core::PCWSTR, lpdwhandle : *mut u32) -> u32);
    unsafe {
        GetFileVersionInfoSizeW(
            lptstrfilename.param().abi(),
            lpdwhandle.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn GetFileVersionInfoW<P0>(
    lptstrfilename: P0,
    dwhandle: Option<u32>,
    dwlen: u32,
    lpdata: *mut core::ffi::c_void,
) -> windows_core::BOOL
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("version.dll" "system" fn GetFileVersionInfoW(lptstrfilename : windows_core::PCWSTR, dwhandle : u32, dwlen : u32, lpdata : *mut core::ffi::c_void) -> windows_core::BOOL);
    unsafe {
        GetFileVersionInfoW(
            lptstrfilename.param().abi(),
            dwhandle.unwrap_or(core::mem::zeroed()) as _,
            dwlen,
            lpdata as _,
        )
    }
}
#[inline]
pub unsafe fn GetGuiResources(hprocess: HANDLE, uiflags: u32) -> u32 {
    windows_core::link!("user32.dll" "system" fn GetGuiResources(hprocess : HANDLE, uiflags : u32) -> u32);
    unsafe { GetGuiResources(hprocess, uiflags) }
}
#[inline]
pub unsafe fn GetIfEntry2(row: *mut MIB_IF_ROW2) -> windows_core::NTSTATUS {
    windows_core::link!("iphlpapi.dll" "system" fn GetIfEntry2(row : *mut MIB_IF_ROW2) -> windows_core::NTSTATUS);
    unsafe { GetIfEntry2(row as _) }
}
#[inline]
pub unsafe fn GetIfTable2Ex(
    level: MIB_IF_TABLE_LEVEL,
    table: *mut PMIB_IF_TABLE2,
) -> windows_core::NTSTATUS {
    windows_core::link!("iphlpapi.dll" "system" fn GetIfTable2Ex(level : MIB_IF_TABLE_LEVEL, table : *mut PMIB_IF_TABLE2) -> windows_core::NTSTATUS);
    unsafe { GetIfTable2Ex(level, table as _) }
}
#[inline]
pub unsafe fn GetLastError() -> u32 {
    windows_core::link!("kernel32.dll" "system" fn GetLastError() -> u32);
    unsafe { GetLastError() }
}
#[inline]
pub unsafe fn GetMappedFileNameW(
    hprocess: HANDLE,
    lpv: *const core::ffi::c_void,
    lpfilename: windows_core::PWSTR,
    nsize: u32,
) -> u32 {
    windows_core::link!("kernel32.dll" "system" "K32GetMappedFileNameW" fn GetMappedFileNameW(hprocess : HANDLE, lpv : *const core::ffi::c_void, lpfilename : windows_core::PWSTR, nsize : u32) -> u32);
    unsafe { GetMappedFileNameW(hprocess, lpv, lpfilename, nsize) }
}
#[inline]
pub unsafe fn GetNamedSecurityInfoW<P0>(
    pobjectname: P0,
    objecttype: SE_OBJECT_TYPE,
    securityinfo: SECURITY_INFORMATION,
    ppsidowner: Option<*mut PSID>,
    ppsidgroup: Option<*mut PSID>,
    ppdacl: Option<*mut PACL>,
    ppsacl: Option<*mut PACL>,
    ppsecuritydescriptor: *mut PSECURITY_DESCRIPTOR,
) -> u32
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("advapi32.dll" "system" fn GetNamedSecurityInfoW(pobjectname : windows_core::PCWSTR, objecttype : SE_OBJECT_TYPE, securityinfo : SECURITY_INFORMATION, ppsidowner : *mut PSID, ppsidgroup : *mut PSID, ppdacl : *mut PACL, ppsacl : *mut PACL, ppsecuritydescriptor : *mut PSECURITY_DESCRIPTOR) -> u32);
    unsafe {
        GetNamedSecurityInfoW(
            pobjectname.param().abi(),
            objecttype,
            securityinfo,
            ppsidowner.unwrap_or(core::mem::zeroed()) as _,
            ppsidgroup.unwrap_or(core::mem::zeroed()) as _,
            ppdacl.unwrap_or(core::mem::zeroed()) as _,
            ppsacl.unwrap_or(core::mem::zeroed()) as _,
            ppsecuritydescriptor as _,
        )
    }
}
#[inline]
pub unsafe fn GetPackageFullName(
    hprocess: HANDLE,
    packagefullnamelength: *mut u32,
    packagefullname: Option<windows_core::PWSTR>,
) -> i32 {
    windows_core::link!("kernel32.dll" "system" fn GetPackageFullName(hprocess : HANDLE, packagefullnamelength : *mut u32, packagefullname : windows_core::PWSTR) -> i32);
    unsafe {
        GetPackageFullName(
            hprocess,
            packagefullnamelength as _,
            packagefullname.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn GetPackagePathByFullName<P0>(
    packagefullname: P0,
    pathlength: *mut u32,
    path: Option<windows_core::PWSTR>,
) -> i32
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn GetPackagePathByFullName(packagefullname : windows_core::PCWSTR, pathlength : *mut u32, path : windows_core::PWSTR) -> i32);
    unsafe {
        GetPackagePathByFullName(
            packagefullname.param().abi(),
            pathlength as _,
            path.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn GetProcAddress<P1>(hmodule: HMODULE, lpprocname: P1) -> FARPROC
where
    P1: windows_core::Param<windows_core::PCSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn GetProcAddress(hmodule : HMODULE, lpprocname : windows_core::PCSTR) -> FARPROC);
    unsafe { GetProcAddress(hmodule, lpprocname.param().abi()) }
}
#[inline]
pub unsafe fn GetProcessInformation(
    hprocess: HANDLE,
    processinformationclass: PROCESS_INFORMATION_CLASS,
    processinformation: *mut core::ffi::c_void,
    processinformationsize: u32,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn GetProcessInformation(hprocess : HANDLE, processinformationclass : PROCESS_INFORMATION_CLASS, processinformation : *mut core::ffi::c_void, processinformationsize : u32) -> windows_core::BOOL);
    unsafe {
        GetProcessInformation(
            hprocess,
            processinformationclass,
            processinformation as _,
            processinformationsize,
        )
    }
}
#[inline]
pub unsafe fn GetProcessMitigationPolicy(
    hprocess: HANDLE,
    mitigationpolicy: PROCESS_MITIGATION_POLICY,
    lpbuffer: *mut core::ffi::c_void,
    dwlength: usize,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn GetProcessMitigationPolicy(hprocess : HANDLE, mitigationpolicy : PROCESS_MITIGATION_POLICY, lpbuffer : *mut core::ffi::c_void, dwlength : usize) -> windows_core::BOOL);
    unsafe { GetProcessMitigationPolicy(hprocess, mitigationpolicy, lpbuffer as _, dwlength) }
}
#[inline]
pub unsafe fn GetProcessTimes(
    hprocess: HANDLE,
    lpcreationtime: *mut FILETIME,
    lpexittime: *mut FILETIME,
    lpkerneltime: *mut FILETIME,
    lpusertime: *mut FILETIME,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn GetProcessTimes(hprocess : HANDLE, lpcreationtime : *mut FILETIME, lpexittime : *mut FILETIME, lpkerneltime : *mut FILETIME, lpusertime : *mut FILETIME) -> windows_core::BOOL);
    unsafe {
        GetProcessTimes(
            hprocess,
            lpcreationtime as _,
            lpexittime as _,
            lpkerneltime as _,
            lpusertime as _,
        )
    }
}
#[inline]
pub unsafe fn GetSecurityDescriptorDacl(
    psecuritydescriptor: PSECURITY_DESCRIPTOR,
    lpbdaclpresent: *mut windows_core::BOOL,
    pdacl: *mut PACL,
    lpbdacldefaulted: *mut windows_core::BOOL,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn GetSecurityDescriptorDacl(psecuritydescriptor : PSECURITY_DESCRIPTOR, lpbdaclpresent : *mut windows_core::BOOL, pdacl : *mut PACL, lpbdacldefaulted : *mut windows_core::BOOL) -> windows_core::BOOL);
    unsafe {
        GetSecurityDescriptorDacl(
            psecuritydescriptor,
            lpbdaclpresent as _,
            pdacl as _,
            lpbdacldefaulted as _,
        )
    }
}
#[inline]
pub unsafe fn GetStagedPackageOrigin<P0>(packagefullname: P0, origin: *mut PackageOrigin) -> i32
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("api-ms-win-appmodel-runtime-l1-1-1.dll" "system" fn GetStagedPackageOrigin(packagefullname : windows_core::PCWSTR, origin : *mut PackageOrigin) -> i32);
    unsafe { GetStagedPackageOrigin(packagefullname.param().abi(), origin as _) }
}
#[inline]
pub unsafe fn GetStagedPackagePathByFullName<P0>(
    packagefullname: P0,
    pathlength: *mut u32,
    path: Option<windows_core::PWSTR>,
) -> i32
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn GetStagedPackagePathByFullName(packagefullname : windows_core::PCWSTR, pathlength : *mut u32, path : windows_core::PWSTR) -> i32);
    unsafe {
        GetStagedPackagePathByFullName(
            packagefullname.param().abi(),
            pathlength as _,
            path.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn GetSystemInfo(lpsysteminfo: *mut SYSTEM_INFO) {
    windows_core::link!("kernel32.dll" "system" fn GetSystemInfo(lpsysteminfo : *mut SYSTEM_INFO));
    unsafe { GetSystemInfo(lpsysteminfo as _) }
}
#[inline]
pub unsafe fn GetSystemTimePreciseAsFileTime() -> FILETIME {
    windows_core::link!("kernel32.dll" "system" fn GetSystemTimePreciseAsFileTime(lpsystemtimeasfiletime : *mut FILETIME));
    unsafe {
        let mut result__ = core::mem::zeroed();
        GetSystemTimePreciseAsFileTime(&mut result__);
        result__
    }
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
pub unsafe fn GlobalMemoryStatusEx(lpbuffer: *mut MEMORYSTATUSEX) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn GlobalMemoryStatusEx(lpbuffer : *mut MEMORYSTATUSEX) -> windows_core::BOOL);
    unsafe { GlobalMemoryStatusEx(lpbuffer as _) }
}
#[inline]
pub unsafe fn IsWellKnownSid(
    psid: PSID,
    wellknownsidtype: WELL_KNOWN_SID_TYPE,
) -> windows_core::BOOL {
    windows_core::link!("advapi32.dll" "system" fn IsWellKnownSid(psid : PSID, wellknownsidtype : WELL_KNOWN_SID_TYPE) -> windows_core::BOOL);
    unsafe { IsWellKnownSid(psid, wellknownsidtype) }
}
#[inline]
pub unsafe fn IsWow64Process2(
    hprocess: HANDLE,
    pprocessmachine: *mut u16,
    pnativemachine: Option<*mut u16>,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn IsWow64Process2(hprocess : HANDLE, pprocessmachine : *mut u16, pnativemachine : *mut u16) -> windows_core::BOOL);
    unsafe {
        IsWow64Process2(
            hprocess,
            pprocessmachine as _,
            pnativemachine.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn LoadLibraryW<P0>(lplibfilename: P0) -> HMODULE
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn LoadLibraryW(lplibfilename : windows_core::PCWSTR) -> HMODULE);
    unsafe { LoadLibraryW(lplibfilename.param().abi()) }
}
#[inline]
pub unsafe fn LocalFree(hmem: HLOCAL) -> HLOCAL {
    windows_core::link!("kernel32.dll" "system" fn LocalFree(hmem : HLOCAL) -> HLOCAL);
    unsafe { LocalFree(hmem) }
}
#[inline]
pub unsafe fn LookupAccountSidW<P0>(
    lpsystemname: P0,
    sid: PSID,
    name: Option<windows_core::PWSTR>,
    cchname: *mut u32,
    referenceddomainname: Option<windows_core::PWSTR>,
    cchreferenceddomainname: *mut u32,
    peuse: *mut SID_NAME_USE,
) -> windows_core::BOOL
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("advapi32.dll" "system" fn LookupAccountSidW(lpsystemname : windows_core::PCWSTR, sid : PSID, name : windows_core::PWSTR, cchname : *mut u32, referenceddomainname : windows_core::PWSTR, cchreferenceddomainname : *mut u32, peuse : *mut SID_NAME_USE) -> windows_core::BOOL);
    unsafe {
        LookupAccountSidW(
            lpsystemname.param().abi(),
            sid,
            name.unwrap_or(core::mem::zeroed()) as _,
            cchname as _,
            referenceddomainname.unwrap_or(core::mem::zeroed()) as _,
            cchreferenceddomainname as _,
            peuse as _,
        )
    }
}
#[inline]
pub unsafe fn LookupPrivilegeValueW<P0, P1>(
    lpsystemname: P0,
    lpname: P1,
    lpluid: *mut LUID,
) -> windows_core::BOOL
where
    P0: windows_core::Param<windows_core::PCWSTR>,
    P1: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("advapi32.dll" "system" fn LookupPrivilegeValueW(lpsystemname : windows_core::PCWSTR, lpname : windows_core::PCWSTR, lpluid : *mut LUID) -> windows_core::BOOL);
    unsafe {
        LookupPrivilegeValueW(
            lpsystemname.param().abi(),
            lpname.param().abi(),
            lpluid as _,
        )
    }
}
#[inline]
pub unsafe fn MapViewOfFile(
    hfilemappingobject: HANDLE,
    dwdesiredaccess: u32,
    dwfileoffsethigh: u32,
    dwfileoffsetlow: u32,
    dwnumberofbytestomap: usize,
) -> *mut core::ffi::c_void {
    windows_core::link!("kernel32.dll" "system" fn MapViewOfFile(hfilemappingobject : HANDLE, dwdesiredaccess : u32, dwfileoffsethigh : u32, dwfileoffsetlow : u32, dwnumberofbytestomap : usize) -> *mut core::ffi::c_void);
    unsafe {
        MapViewOfFile(
            hfilemappingobject,
            dwdesiredaccess,
            dwfileoffsethigh,
            dwfileoffsetlow,
            dwnumberofbytestomap,
        )
    }
}
#[inline]
pub unsafe fn NtQueryInformationProcess(
    processhandle: HANDLE,
    processinformationclass: PROCESSINFOCLASS,
    processinformation: *mut core::ffi::c_void,
    processinformationlength: u32,
    returnlength: Option<*mut u32>,
) -> windows_core::NTSTATUS {
    windows_core::link!("ntdll.dll" "system" fn NtQueryInformationProcess(processhandle : HANDLE, processinformationclass : PROCESSINFOCLASS, processinformation : *mut core::ffi::c_void, processinformationlength : u32, returnlength : *mut u32) -> windows_core::NTSTATUS);
    unsafe {
        NtQueryInformationProcess(
            processhandle,
            processinformationclass,
            processinformation as _,
            processinformationlength,
            returnlength.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn NtQueryObject(
    handle: Option<HANDLE>,
    objectinformationclass: OBJECT_INFORMATION_CLASS,
    objectinformation: Option<*mut core::ffi::c_void>,
    objectinformationlength: u32,
    returnlength: Option<*mut u32>,
) -> windows_core::NTSTATUS {
    windows_core::link!("ntdll.dll" "system" fn NtQueryObject(handle : HANDLE, objectinformationclass : OBJECT_INFORMATION_CLASS, objectinformation : *mut core::ffi::c_void, objectinformationlength : u32, returnlength : *mut u32) -> windows_core::NTSTATUS);
    unsafe {
        NtQueryObject(
            handle.unwrap_or(core::mem::zeroed()) as _,
            objectinformationclass,
            objectinformation.unwrap_or(core::mem::zeroed()) as _,
            objectinformationlength,
            returnlength.unwrap_or(core::mem::zeroed()) as _,
        )
    }
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
pub unsafe fn PackageIdFromFullName<P0>(
    packagefullname: P0,
    flags: u32,
    bufferlength: *mut u32,
    buffer: Option<*mut u8>,
) -> i32
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn PackageIdFromFullName(packagefullname : windows_core::PCWSTR, flags : u32, bufferlength : *mut u32, buffer : *mut u8) -> i32);
    unsafe {
        PackageIdFromFullName(
            packagefullname.param().abi(),
            flags,
            bufferlength as _,
            buffer.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn PdhAddEnglishCounterW<P1>(
    hquery: PDH_HQUERY,
    szfullcounterpath: P1,
    dwuserdata: usize,
    phcounter: *mut PDH_HCOUNTER,
) -> PDH_STATUS
where
    P1: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("pdh.dll" "system" fn PdhAddEnglishCounterW(hquery : PDH_HQUERY, szfullcounterpath : windows_core::PCWSTR, dwuserdata : usize, phcounter : *mut PDH_HCOUNTER) -> PDH_STATUS);
    unsafe {
        PdhAddEnglishCounterW(
            hquery,
            szfullcounterpath.param().abi(),
            dwuserdata,
            phcounter as _,
        )
    }
}
#[inline]
pub unsafe fn PdhCloseQuery(hquery: PDH_HQUERY) -> PDH_STATUS {
    windows_core::link!("pdh.dll" "system" fn PdhCloseQuery(hquery : PDH_HQUERY) -> PDH_STATUS);
    unsafe { PdhCloseQuery(hquery as _) }
}
#[inline]
pub unsafe fn PdhCollectQueryData(hquery: PDH_HQUERY) -> PDH_STATUS {
    windows_core::link!("pdh.dll" "system" fn PdhCollectQueryData(hquery : PDH_HQUERY) -> PDH_STATUS);
    unsafe { PdhCollectQueryData(hquery as _) }
}
#[inline]
pub unsafe fn PdhGetFormattedCounterValue(
    hcounter: PDH_HCOUNTER,
    dwformat: u32,
    lpdwtype: Option<*mut u32>,
    pvalue: *mut PDH_FMT_COUNTERVALUE,
) -> PDH_STATUS {
    windows_core::link!("pdh.dll" "system" fn PdhGetFormattedCounterValue(hcounter : PDH_HCOUNTER, dwformat : u32, lpdwtype : *mut u32, pvalue : *mut PDH_FMT_COUNTERVALUE) -> PDH_STATUS);
    unsafe {
        PdhGetFormattedCounterValue(
            hcounter,
            dwformat,
            lpdwtype.unwrap_or(core::mem::zeroed()) as _,
            pvalue as _,
        )
    }
}
#[inline]
pub unsafe fn PdhOpenQueryW<P0>(
    szdatasource: P0,
    dwuserdata: usize,
    phquery: *mut PDH_HQUERY,
) -> PDH_STATUS
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("pdh.dll" "system" fn PdhOpenQueryW(szdatasource : windows_core::PCWSTR, dwuserdata : usize, phquery : *mut PDH_HQUERY) -> PDH_STATUS);
    unsafe { PdhOpenQueryW(szdatasource.param().abi(), dwuserdata, phquery as _) }
}
#[inline]
pub unsafe fn ProcessIdToSessionId(dwprocessid: u32, psessionid: *mut u32) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn ProcessIdToSessionId(dwprocessid : u32, psessionid : *mut u32) -> windows_core::BOOL);
    unsafe { ProcessIdToSessionId(dwprocessid, psessionid as _) }
}
#[inline]
pub unsafe fn QueryDosDeviceW<P0>(
    lpdevicename: P0,
    lptargetpath: Option<windows_core::PWSTR>,
    ucchmax: u32,
) -> u32
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("kernel32.dll" "system" fn QueryDosDeviceW(lpdevicename : windows_core::PCWSTR, lptargetpath : windows_core::PWSTR, ucchmax : u32) -> u32);
    unsafe {
        QueryDosDeviceW(
            lpdevicename.param().abi(),
            lptargetpath.unwrap_or(core::mem::zeroed()) as _,
            ucchmax,
        )
    }
}
#[inline]
pub unsafe fn QueryFullProcessImageNameW(
    hprocess: HANDLE,
    dwflags: u32,
    lpexename: windows_core::PWSTR,
    lpdwsize: *mut u32,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn QueryFullProcessImageNameW(hprocess : HANDLE, dwflags : u32, lpexename : windows_core::PWSTR, lpdwsize : *mut u32) -> windows_core::BOOL);
    unsafe { QueryFullProcessImageNameW(hprocess, dwflags, lpexename, lpdwsize as _) }
}
#[inline]
pub unsafe fn QueryPerformanceCounter(lpperformancecount: *mut i64) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn QueryPerformanceCounter(lpperformancecount : *mut i64) -> windows_core::BOOL);
    unsafe { QueryPerformanceCounter(lpperformancecount as _) }
}
#[inline]
pub unsafe fn QueryPerformanceFrequency(lpfrequency: *mut i64) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn QueryPerformanceFrequency(lpfrequency : *mut i64) -> windows_core::BOOL);
    unsafe { QueryPerformanceFrequency(lpfrequency as _) }
}
#[inline]
pub unsafe fn QueryWorkingSet(
    hprocess: HANDLE,
    pv: *mut core::ffi::c_void,
    cb: u32,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" "K32QueryWorkingSet" fn QueryWorkingSet(hprocess : HANDLE, pv : *mut core::ffi::c_void, cb : u32) -> windows_core::BOOL);
    unsafe { QueryWorkingSet(hprocess, pv as _, cb) }
}
#[inline]
pub unsafe fn ReadProcessMemory(
    hprocess: HANDLE,
    lpbaseaddress: *const core::ffi::c_void,
    lpbuffer: *mut core::ffi::c_void,
    nsize: usize,
    lpnumberofbytesread: Option<*mut usize>,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn ReadProcessMemory(hprocess : HANDLE, lpbaseaddress : *const core::ffi::c_void, lpbuffer : *mut core::ffi::c_void, nsize : usize, lpnumberofbytesread : *mut usize) -> windows_core::BOOL);
    unsafe {
        ReadProcessMemory(
            hprocess,
            lpbaseaddress,
            lpbuffer as _,
            nsize,
            lpnumberofbytesread.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn SHGetFileInfoW<P0>(
    pszpath: P0,
    dwfileattributes: u32,
    psfi: Option<*mut SHFILEINFOW>,
    cbfileinfo: u32,
    uflags: u32,
) -> usize
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("shell32.dll" "system" fn SHGetFileInfoW(pszpath : windows_core::PCWSTR, dwfileattributes : u32, psfi : *mut SHFILEINFOW, cbfileinfo : u32, uflags : u32) -> usize);
    unsafe {
        SHGetFileInfoW(
            pszpath.param().abi(),
            dwfileattributes,
            psfi.unwrap_or(core::mem::zeroed()) as _,
            cbfileinfo,
            uflags,
        )
    }
}
#[inline]
pub unsafe fn SHLoadIndirectString<P0>(
    pszsource: P0,
    pszoutbuf: windows_core::PWSTR,
    cchoutbuf: u32,
    ppvreserved: Option<*const *const core::ffi::c_void>,
) -> windows_core::HRESULT
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("shlwapi.dll" "system" fn SHLoadIndirectString(pszsource : windows_core::PCWSTR, pszoutbuf : windows_core::PWSTR, cchoutbuf : u32, ppvreserved : *const *const core::ffi::c_void) -> windows_core::HRESULT);
    unsafe {
        SHLoadIndirectString(
            pszsource.param().abi(),
            pszoutbuf,
            cchoutbuf,
            ppvreserved.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn SetNamedSecurityInfoW<P0>(
    pobjectname: P0,
    objecttype: SE_OBJECT_TYPE,
    securityinfo: SECURITY_INFORMATION,
    psidowner: Option<PSID>,
    psidgroup: Option<PSID>,
    pdacl: Option<*const ACL>,
    psacl: Option<*const ACL>,
) -> u32
where
    P0: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("advapi32.dll" "system" fn SetNamedSecurityInfoW(pobjectname : windows_core::PCWSTR, objecttype : SE_OBJECT_TYPE, securityinfo : SECURITY_INFORMATION, psidowner : PSID, psidgroup : PSID, pdacl : *const ACL, psacl : *const ACL) -> u32);
    unsafe {
        SetNamedSecurityInfoW(
            pobjectname.param().abi(),
            objecttype,
            securityinfo,
            psidowner.unwrap_or(core::mem::zeroed()) as _,
            psidgroup.unwrap_or(core::mem::zeroed()) as _,
            pdacl.unwrap_or(core::mem::zeroed()) as _,
            psacl.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[inline]
pub unsafe fn UnmapViewOfFile(lpbaseaddress: *const core::ffi::c_void) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn UnmapViewOfFile(lpbaseaddress : *const core::ffi::c_void) -> windows_core::BOOL);
    unsafe { UnmapViewOfFile(lpbaseaddress) }
}
#[inline]
pub unsafe fn VerQueryValueW<P1>(
    pblock: *const core::ffi::c_void,
    lpsubblock: P1,
    lplpbuffer: *mut *mut core::ffi::c_void,
    pulen: *mut u32,
) -> windows_core::BOOL
where
    P1: windows_core::Param<windows_core::PCWSTR>,
{
    windows_core::link!("version.dll" "system" fn VerQueryValueW(pblock : *const core::ffi::c_void, lpsubblock : windows_core::PCWSTR, lplpbuffer : *mut *mut core::ffi::c_void, pulen : *mut u32) -> windows_core::BOOL);
    unsafe {
        VerQueryValueW(
            pblock,
            lpsubblock.param().abi(),
            lplpbuffer as _,
            pulen as _,
        )
    }
}
#[inline]
pub unsafe fn WTHelperGetProvSignerFromChain(
    pprovdata: *mut CRYPT_PROVIDER_DATA,
    idxsigner: u32,
    fcountersigner: bool,
    idxcountersigner: u32,
) -> *mut CRYPT_PROVIDER_SGNR {
    windows_core::link!("wintrust.dll" "system" fn WTHelperGetProvSignerFromChain(pprovdata : *mut CRYPT_PROVIDER_DATA, idxsigner : u32, fcountersigner : windows_core::BOOL, idxcountersigner : u32) -> *mut CRYPT_PROVIDER_SGNR);
    unsafe {
        WTHelperGetProvSignerFromChain(
            pprovdata as _,
            idxsigner,
            fcountersigner.into(),
            idxcountersigner,
        )
    }
}
#[inline]
pub unsafe fn WTHelperProvDataFromStateData(hstatedata: HANDLE) -> *mut CRYPT_PROVIDER_DATA {
    windows_core::link!("wintrust.dll" "system" fn WTHelperProvDataFromStateData(hstatedata : HANDLE) -> *mut CRYPT_PROVIDER_DATA);
    unsafe { WTHelperProvDataFromStateData(hstatedata) }
}
#[inline]
pub unsafe fn WinVerifyTrust(
    hwnd: HWND,
    pgactionid: *mut windows_core::GUID,
    pwvtdata: *mut core::ffi::c_void,
) -> i32 {
    windows_core::link!("wintrust.dll" "system" fn WinVerifyTrust(hwnd : HWND, pgactionid : *mut windows_core::GUID, pwvtdata : *mut core::ffi::c_void) -> i32);
    unsafe { WinVerifyTrust(hwnd, pgactionid as _, pwvtdata as _) }
}
#[inline]
pub unsafe fn WriteProcessMemory(
    hprocess: HANDLE,
    lpbaseaddress: *const core::ffi::c_void,
    lpbuffer: *const core::ffi::c_void,
    nsize: usize,
    lpnumberofbyteswritten: Option<*mut usize>,
) -> windows_core::BOOL {
    windows_core::link!("kernel32.dll" "system" fn WriteProcessMemory(hprocess : HANDLE, lpbaseaddress : *const core::ffi::c_void, lpbuffer : *const core::ffi::c_void, nsize : usize, lpnumberofbyteswritten : *mut usize) -> windows_core::BOOL);
    unsafe {
        WriteProcessMemory(
            hprocess,
            lpbaseaddress,
            lpbuffer,
            nsize,
            lpnumberofbyteswritten.unwrap_or(core::mem::zeroed()) as _,
        )
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ACL {
    pub AclRevision: u8,
    pub Sbz1: u8,
    pub AclSize: u16,
    pub AceCount: u16,
    pub Sbz2: u16,
}
pub const ALL_PROCESSOR_GROUPS: i32 = 65535;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BY_HANDLE_FILE_INFORMATION {
    pub dwFileAttributes: u32,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub dwVolumeSerialNumber: u32,
    pub nFileSizeHigh: u32,
    pub nFileSizeLow: u32,
    pub nNumberOfLinks: u32,
    pub nFileIndexHigh: u32,
    pub nFileIndexLow: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CATALOG_INFO {
    pub cbStruct: u32,
    pub wszCatalogFile: [u16; 260],
}
impl Default for CATALOG_INFO {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_CHAIN_CONTEXT {
    pub cbSize: u32,
    pub TrustStatus: CERT_TRUST_STATUS,
    pub cChain: u32,
    pub rgpChain: *mut PCERT_SIMPLE_CHAIN,
    pub cLowerQualityChainContext: u32,
    pub rgpLowerQualityChainContext: *mut PCCERT_CHAIN_CONTEXT,
    pub fHasRevocationFreshnessTime: windows_core::BOOL,
    pub dwRevocationFreshnessTime: u32,
    pub dwCreateFlags: u32,
    pub ChainId: windows_core::GUID,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_CHAIN_ELEMENT {
    pub cbSize: u32,
    pub pCertContext: PCCERT_CONTEXT,
    pub TrustStatus: CERT_TRUST_STATUS,
    pub pRevocationInfo: PCERT_REVOCATION_INFO,
    pub pIssuanceUsage: PCERT_ENHKEY_USAGE,
    pub pApplicationUsage: PCERT_ENHKEY_USAGE,
    pub pwszExtendedErrorInfo: windows_core::PCWSTR,
}
pub const CERT_CHAIN_POLICY_MICROSOFT_ROOT: windows_core::PCSTR = windows_core::PCSTR(7 as _);
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_CHAIN_POLICY_PARA {
    pub cbSize: u32,
    pub dwFlags: u32,
    pub pvExtraPolicyPara: *mut core::ffi::c_void,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_CHAIN_POLICY_STATUS {
    pub cbSize: u32,
    pub dwError: u32,
    pub lChainIndex: i32,
    pub lElementIndex: i32,
    pub pvExtraPolicyStatus: *mut core::ffi::c_void,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_CONTEXT {
    pub dwCertEncodingType: u32,
    pub pbCertEncoded: *mut u8,
    pub cbCertEncoded: u32,
    pub pCertInfo: PCERT_INFO,
    pub hCertStore: HCERTSTORE,
}
pub type CERT_ENHKEY_USAGE = CTL_USAGE;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_EXTENSION {
    pub pszObjId: windows_core::PSTR,
    pub fCritical: windows_core::BOOL,
    pub Value: CRYPT_OBJID_BLOB,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_INFO {
    pub dwVersion: u32,
    pub SerialNumber: CRYPT_INTEGER_BLOB,
    pub SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub Issuer: CERT_NAME_BLOB,
    pub NotBefore: FILETIME,
    pub NotAfter: FILETIME,
    pub Subject: CERT_NAME_BLOB,
    pub SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO,
    pub IssuerUniqueId: CRYPT_BIT_BLOB,
    pub SubjectUniqueId: CRYPT_BIT_BLOB,
    pub cExtension: u32,
    pub rgExtension: PCERT_EXTENSION,
}
pub type CERT_NAME_BLOB = CRYPT_INTEGER_BLOB;
pub const CERT_NAME_SIMPLE_DISPLAY_TYPE: i32 = 4;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_PUBLIC_KEY_INFO {
    pub Algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub PublicKey: CRYPT_BIT_BLOB,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_REVOCATION_CRL_INFO {
    pub cbSize: u32,
    pub pBaseCrlContext: PCCRL_CONTEXT,
    pub pDeltaCrlContext: PCCRL_CONTEXT,
    pub pCrlEntry: PCRL_ENTRY,
    pub fDeltaCrlEntry: windows_core::BOOL,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_REVOCATION_INFO {
    pub cbSize: u32,
    pub dwRevocationResult: u32,
    pub pszRevocationOid: windows_core::PCSTR,
    pub pvOidSpecificInfo: *mut core::ffi::c_void,
    pub fHasFreshnessTime: windows_core::BOOL,
    pub dwFreshnessTime: u32,
    pub pCrlInfo: PCERT_REVOCATION_CRL_INFO,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_SIMPLE_CHAIN {
    pub cbSize: u32,
    pub TrustStatus: CERT_TRUST_STATUS,
    pub cElement: u32,
    pub rgpElement: *mut PCERT_CHAIN_ELEMENT,
    pub pTrustListInfo: PCERT_TRUST_LIST_INFO,
    pub fHasRevocationFreshnessTime: windows_core::BOOL,
    pub dwRevocationFreshnessTime: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CERT_STRONG_SIGN_PARA {
    pub cbSize: u32,
    pub dwInfoChoice: u32,
    pub Anonymous: CERT_STRONG_SIGN_PARA_0,
}
impl Default for CERT_STRONG_SIGN_PARA {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union CERT_STRONG_SIGN_PARA_0 {
    pub pvInfo: *mut core::ffi::c_void,
    pub pSerializedInfo: PCERT_STRONG_SIGN_SERIALIZED_INFO,
    pub pszOID: windows_core::PSTR,
}
impl Default for CERT_STRONG_SIGN_PARA_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_STRONG_SIGN_SERIALIZED_INFO {
    pub dwFlags: u32,
    pub pwszCNGSignHashAlgids: windows_core::PWSTR,
    pub pwszCNGPubKeyMinBitLengths: windows_core::PWSTR,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_TRUST_LIST_INFO {
    pub cbSize: u32,
    pub pCtlEntry: PCTL_ENTRY,
    pub pCtlContext: PCCTL_CONTEXT,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_TRUST_STATUS {
    pub dwErrorStatus: u32,
    pub dwInfoStatus: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CERT_USAGE_MATCH {
    pub dwType: u32,
    pub Usage: CERT_ENHKEY_USAGE,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CMSG_SIGNER_INFO {
    pub dwVersion: u32,
    pub Issuer: CERT_NAME_BLOB,
    pub SerialNumber: CRYPT_INTEGER_BLOB,
    pub HashAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub HashEncryptionAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub EncryptedHash: CRYPT_DATA_BLOB,
    pub AuthAttrs: CRYPT_ATTRIBUTES,
    pub UnauthAttrs: CRYPT_ATTRIBUTES,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRL_CONTEXT {
    pub dwCertEncodingType: u32,
    pub pbCrlEncoded: *mut u8,
    pub cbCrlEncoded: u32,
    pub pCrlInfo: PCRL_INFO,
    pub hCertStore: HCERTSTORE,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRL_ENTRY {
    pub SerialNumber: CRYPT_INTEGER_BLOB,
    pub RevocationDate: FILETIME,
    pub cExtension: u32,
    pub rgExtension: PCERT_EXTENSION,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRL_INFO {
    pub dwVersion: u32,
    pub SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub Issuer: CERT_NAME_BLOB,
    pub ThisUpdate: FILETIME,
    pub NextUpdate: FILETIME,
    pub cCRLEntry: u32,
    pub rgCRLEntry: PCRL_ENTRY,
    pub cExtension: u32,
    pub rgExtension: PCERT_EXTENSION,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPTCATMEMBER {
    pub cbStruct: u32,
    pub pwszReferenceTag: windows_core::PWSTR,
    pub pwszFileName: windows_core::PWSTR,
    pub gSubjectType: windows_core::GUID,
    pub fdwMemberFlags: u32,
    pub pIndirectData: *mut SIP_INDIRECT_DATA,
    pub dwCertVersion: u32,
    pub dwReserved: u32,
    pub hReserved: HANDLE,
    pub sEncodedIndirectData: CRYPT_ATTR_BLOB,
    pub sEncodedMemberInfo: CRYPT_ATTR_BLOB,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPTCATSTORE {
    pub cbStruct: u32,
    pub dwPublicVersion: u32,
    pub pwszP7File: windows_core::PWSTR,
    pub hProv: HCRYPTPROV,
    pub dwEncodingType: u32,
    pub fdwStoreFlags: u32,
    pub hReserved: HANDLE,
    pub hAttrs: HANDLE,
    pub hCryptMsg: HCRYPTMSG,
    pub hSorted: HANDLE,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_ALGORITHM_IDENTIFIER {
    pub pszObjId: windows_core::PSTR,
    pub Parameters: CRYPT_OBJID_BLOB,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_ATTRIBUTE {
    pub pszObjId: windows_core::PSTR,
    pub cValue: u32,
    pub rgValue: PCRYPT_ATTR_BLOB,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_ATTRIBUTES {
    pub cAttr: u32,
    pub rgAttr: PCRYPT_ATTRIBUTE,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_ATTRIBUTE_TYPE_VALUE {
    pub pszObjId: windows_core::PSTR,
    pub Value: CRYPT_OBJID_BLOB,
}
pub type CRYPT_ATTR_BLOB = CRYPT_INTEGER_BLOB;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_BIT_BLOB {
    pub cbData: u32,
    pub pbData: *mut u8,
    pub cUnusedBits: u32,
}
pub type CRYPT_DATA_BLOB = CRYPT_INTEGER_BLOB;
pub type CRYPT_DIGEST_BLOB = CRYPT_INTEGER_BLOB;
pub type CRYPT_HASH_BLOB = CRYPT_INTEGER_BLOB;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_INTEGER_BLOB {
    pub cbData: u32,
    pub pbData: *mut u8,
}
pub type CRYPT_OBJID_BLOB = CRYPT_INTEGER_BLOB;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_PROVIDER_CERT {
    pub cbStruct: u32,
    pub pCert: PCCERT_CONTEXT,
    pub fCommercial: windows_core::BOOL,
    pub fTrustedRoot: windows_core::BOOL,
    pub fSelfSigned: windows_core::BOOL,
    pub fTestCert: windows_core::BOOL,
    pub dwRevokedReason: u32,
    pub dwConfidence: u32,
    pub dwError: u32,
    pub pTrustListContext: *mut CTL_CONTEXT,
    pub fTrustListSignerCert: windows_core::BOOL,
    pub pCtlContext: PCCTL_CONTEXT,
    pub dwCtlError: u32,
    pub fIsCyclic: windows_core::BOOL,
    pub pChainElement: PCERT_CHAIN_ELEMENT,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CRYPT_PROVIDER_DATA {
    pub cbStruct: u32,
    pub pWintrustData: *mut WINTRUST_DATA,
    pub fOpenedFile: windows_core::BOOL,
    pub hWndParent: HWND,
    pub pgActionID: *mut windows_core::GUID,
    pub hProv: HCRYPTPROV,
    pub dwError: u32,
    pub dwRegSecuritySettings: u32,
    pub dwRegPolicySettings: u32,
    pub psPfns: *mut CRYPT_PROVIDER_FUNCTIONS,
    pub cdwTrustStepErrors: u32,
    pub padwTrustStepErrors: *mut u32,
    pub chStores: u32,
    pub pahStores: *mut HCERTSTORE,
    pub dwEncoding: u32,
    pub hMsg: HCRYPTMSG,
    pub csSigners: u32,
    pub pasSigners: *mut CRYPT_PROVIDER_SGNR,
    pub csProvPrivData: u32,
    pub pasProvPrivData: *mut CRYPT_PROVIDER_PRIVDATA,
    pub dwSubjectChoice: u32,
    pub Anonymous: CRYPT_PROVIDER_DATA_0,
    pub pszUsageOID: *mut i8,
    pub fRecallWithState: windows_core::BOOL,
    pub sftSystemTime: FILETIME,
    pub pszCTLSignerUsageOID: *mut i8,
    pub dwProvFlags: u32,
    pub dwFinalError: u32,
    pub pRequestUsage: PCERT_USAGE_MATCH,
    pub dwTrustPubSettings: u32,
    pub dwUIStateFlags: u32,
    pub pSigState: *mut CRYPT_PROVIDER_SIGSTATE,
    pub pSigSettings: *mut WINTRUST_SIGNATURE_SETTINGS,
}
impl Default for CRYPT_PROVIDER_DATA {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union CRYPT_PROVIDER_DATA_0 {
    pub pPDSip: *mut PROVDATA_SIP,
}
impl Default for CRYPT_PROVIDER_DATA_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CRYPT_PROVIDER_FUNCTIONS {
    pub cbStruct: u32,
    pub pfnAlloc: PFN_CPD_MEM_ALLOC,
    pub pfnFree: PFN_CPD_MEM_FREE,
    pub pfnAddStore2Chain: PFN_CPD_ADD_STORE,
    pub pfnAddSgnr2Chain: PFN_CPD_ADD_SGNR,
    pub pfnAddCert2Chain: PFN_CPD_ADD_CERT,
    pub pfnAddPrivData2Chain: PFN_CPD_ADD_PRIVDATA,
    pub pfnInitialize: PFN_PROVIDER_INIT_CALL,
    pub pfnObjectTrust: PFN_PROVIDER_OBJTRUST_CALL,
    pub pfnSignatureTrust: PFN_PROVIDER_SIGTRUST_CALL,
    pub pfnCertificateTrust: PFN_PROVIDER_CERTTRUST_CALL,
    pub pfnFinalPolicy: PFN_PROVIDER_FINALPOLICY_CALL,
    pub pfnCertCheckPolicy: PFN_PROVIDER_CERTCHKPOLICY_CALL,
    pub pfnTestFinalPolicy: PFN_PROVIDER_TESTFINALPOLICY_CALL,
    pub psUIpfns: *mut CRYPT_PROVUI_FUNCS,
    pub pfnCleanupPolicy: PFN_PROVIDER_CLEANUP_CALL,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_PROVIDER_PRIVDATA {
    pub cbStruct: u32,
    pub gProviderID: windows_core::GUID,
    pub cbProvData: u32,
    pub pvProvData: *mut core::ffi::c_void,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_PROVIDER_SGNR {
    pub cbStruct: u32,
    pub sftVerifyAsOf: FILETIME,
    pub csCertChain: u32,
    pub pasCertChain: *mut CRYPT_PROVIDER_CERT,
    pub dwSignerType: u32,
    pub psSigner: *mut CMSG_SIGNER_INFO,
    pub dwError: u32,
    pub csCounterSigners: u32,
    pub pasCounterSigners: *mut Self,
    pub pChainContext: PCCERT_CHAIN_CONTEXT,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_PROVIDER_SIGSTATE {
    pub cbStruct: u32,
    pub rhSecondarySigs: *mut HCRYPTMSG,
    pub hPrimarySig: HCRYPTMSG,
    pub fFirstAttemptMade: windows_core::BOOL,
    pub fNoMoreSigs: windows_core::BOOL,
    pub cSecondarySigs: u32,
    pub dwCurrentIndex: u32,
    pub fSupportMultiSig: windows_core::BOOL,
    pub dwCryptoPolicySupport: u32,
    pub iAttemptCount: u32,
    pub fCheckedSealing: windows_core::BOOL,
    pub pSealingSignature: *mut SEALING_SIGNATURE_ATTRIBUTE,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CRYPT_PROVUI_DATA {
    pub cbStruct: u32,
    pub dwFinalError: u32,
    pub pYesButtonText: *mut u16,
    pub pNoButtonText: *mut u16,
    pub pMoreInfoButtonText: *mut u16,
    pub pAdvancedLinkText: *mut u16,
    pub pCopyActionText: *mut u16,
    pub pCopyActionTextNoTS: *mut u16,
    pub pCopyActionTextNotSigned: *mut u16,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CRYPT_PROVUI_FUNCS {
    pub cbStruct: u32,
    pub psUIData: *mut CRYPT_PROVUI_DATA,
    pub pfnOnMoreInfoClick: PFN_PROVUI_CALL,
    pub pfnOnMoreInfoClickDefault: PFN_PROVUI_CALL,
    pub pfnOnAdvancedClick: PFN_PROVUI_CALL,
    pub pfnOnAdvancedClickDefault: PFN_PROVUI_CALL,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CTL_CONTEXT {
    pub dwMsgAndCertEncodingType: u32,
    pub pbCtlEncoded: *mut u8,
    pub cbCtlEncoded: u32,
    pub pCtlInfo: PCTL_INFO,
    pub hCertStore: HCERTSTORE,
    pub hCryptMsg: HCRYPTMSG,
    pub pbCtlContent: *mut u8,
    pub cbCtlContent: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CTL_ENTRY {
    pub SubjectIdentifier: CRYPT_DATA_BLOB,
    pub cAttribute: u32,
    pub rgAttribute: PCRYPT_ATTRIBUTE,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CTL_INFO {
    pub dwVersion: u32,
    pub SubjectUsage: CTL_USAGE,
    pub ListIdentifier: CRYPT_DATA_BLOB,
    pub SequenceNumber: CRYPT_INTEGER_BLOB,
    pub ThisUpdate: FILETIME,
    pub NextUpdate: FILETIME,
    pub SubjectAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub cCTLEntry: u32,
    pub rgCTLEntry: PCTL_ENTRY,
    pub cExtension: u32,
    pub rgExtension: PCERT_EXTENSION,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CTL_USAGE {
    pub cUsageIdentifier: u32,
    pub rgpszUsageIdentifier: *mut windows_core::PSTR,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_ADAPTERINFO {
    pub hAdapter: D3DKMT_HANDLE,
    pub AdapterLuid: LUID,
    pub NumOfSources: u32,
    pub bPrecisePresentRegionsPreferred: windows_core::BOOL,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_ADAPTERREGISTRYINFO {
    pub AdapterString: [u16; 260],
    pub BiosString: [u16; 260],
    pub DacType: [u16; 260],
    pub ChipType: [u16; 260],
}
impl Default for D3DKMT_ADAPTERREGISTRYINFO {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct D3DKMT_ADAPTERTYPE {
    pub Anonymous: D3DKMT_ADAPTERTYPE_0,
}
impl Default for D3DKMT_ADAPTERTYPE {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union D3DKMT_ADAPTERTYPE_0 {
    pub Anonymous: D3DKMT_ADAPTERTYPE_0_0,
    pub Value: u32,
}
impl Default for D3DKMT_ADAPTERTYPE_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_ADAPTERTYPE_0_0 {
    pub _bitfield: u32,
}
impl D3DKMT_ADAPTERTYPE_0_0 {
    pub fn RenderSupported(&self) -> bool {
        self._bitfield & 1 != 0
    }
    pub fn set_RenderSupported(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !1) | (value as u32);
    }
    pub fn DisplaySupported(&self) -> bool {
        (self._bitfield >> 1) & 1 != 0
    }
    pub fn set_DisplaySupported(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 1)) | ((value as u32) << 1);
    }
    pub fn SoftwareDevice(&self) -> bool {
        (self._bitfield >> 2) & 1 != 0
    }
    pub fn set_SoftwareDevice(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 2)) | ((value as u32) << 2);
    }
    pub fn PostDevice(&self) -> bool {
        (self._bitfield >> 3) & 1 != 0
    }
    pub fn set_PostDevice(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 3)) | ((value as u32) << 3);
    }
    pub fn HybridDiscrete(&self) -> bool {
        (self._bitfield >> 4) & 1 != 0
    }
    pub fn set_HybridDiscrete(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 4)) | ((value as u32) << 4);
    }
    pub fn HybridIntegrated(&self) -> bool {
        (self._bitfield >> 5) & 1 != 0
    }
    pub fn set_HybridIntegrated(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 5)) | ((value as u32) << 5);
    }
    pub fn IndirectDisplayDevice(&self) -> bool {
        (self._bitfield >> 6) & 1 != 0
    }
    pub fn set_IndirectDisplayDevice(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 6)) | ((value as u32) << 6);
    }
    pub fn Paravirtualized(&self) -> bool {
        (self._bitfield >> 7) & 1 != 0
    }
    pub fn set_Paravirtualized(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 7)) | ((value as u32) << 7);
    }
    pub fn ACGSupported(&self) -> bool {
        (self._bitfield >> 8) & 1 != 0
    }
    pub fn set_ACGSupported(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 8)) | ((value as u32) << 8);
    }
    pub fn SupportSetTimingsFromVidPn(&self) -> bool {
        (self._bitfield >> 9) & 1 != 0
    }
    pub fn set_SupportSetTimingsFromVidPn(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 9)) | ((value as u32) << 9);
    }
    pub fn Detachable(&self) -> bool {
        (self._bitfield >> 10) & 1 != 0
    }
    pub fn set_Detachable(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 10)) | ((value as u32) << 10);
    }
    pub fn ComputeOnly(&self) -> bool {
        (self._bitfield >> 11) & 1 != 0
    }
    pub fn set_ComputeOnly(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 11)) | ((value as u32) << 11);
    }
    pub fn Prototype(&self) -> bool {
        (self._bitfield >> 12) & 1 != 0
    }
    pub fn set_Prototype(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 12)) | ((value as u32) << 12);
    }
    pub fn RuntimePowerManagement(&self) -> bool {
        (self._bitfield >> 13) & 1 != 0
    }
    pub fn set_RuntimePowerManagement(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 13)) | ((value as u32) << 13);
    }
    pub fn TestOnly(&self) -> bool {
        (self._bitfield >> 14) & 1 != 0
    }
    pub fn set_TestOnly(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 14)) | ((value as u32) << 14);
    }
    pub fn SingleAdapterHybridMode(&self) -> bool {
        (self._bitfield >> 15) & 1 != 0
    }
    pub fn set_SingleAdapterHybridMode(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 15)) | ((value as u32) << 15);
    }
    pub fn Reserved(&self) -> u32 {
        self._bitfield >> 16
    }
    pub fn set_Reserved(&mut self, value: u32) {
        self._bitfield = (self._bitfield & !(65535 << 16)) | ((value & 65535) << 16);
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_ADAPTER_PERFDATA {
    pub PhysicalAdapterIndex: u32,
    pub MemoryFrequency: u64,
    pub MaxMemoryFrequency: u64,
    pub MaxMemoryFrequencyOC: u64,
    pub MemoryBandwidth: u64,
    pub PCIEBandwidth: u64,
    pub FanRPM: u32,
    pub Power: u32,
    pub Temperature: u32,
    pub PowerStateOverride: u8,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_ADAPTER_PERFDATACAPS {
    pub PhysicalAdapterIndex: u32,
    pub MaxMemoryBandwidth: u64,
    pub MaxPCIEBandwidth: u64,
    pub MaxFanRPM: u32,
    pub TemperatureMax: u32,
    pub TemperatureWarning: u32,
}
pub type D3DKMT_CLIENTHINT = i32;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_CLOSEADAPTER {
    pub hAdapter: D3DKMT_HANDLE,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_DRIVER_DESCRIPTION {
    pub DriverDescription: [u16; 4096],
}
impl Default for D3DKMT_DRIVER_DESCRIPTION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_ENUMADAPTERS2 {
    pub NumAdapters: u32,
    pub pAdapters: *mut D3DKMT_ADAPTERINFO,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_GPUVERSION {
    pub PhysicalAdapterIndex: u32,
    pub BiosVersion: [u16; 32],
    pub GpuArchitecture: [u16; 32],
}
impl Default for D3DKMT_GPUVERSION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct D3DKMT_HANDLE(pub u32);
pub type D3DKMT_MEMORY_SEGMENT_GROUP = i32;
#[repr(C, packed(1))]
#[derive(Clone, Copy)]
pub struct D3DKMT_NODEMETADATA {
    pub NodeOrdinalAndAdapterIndex: u32,
    pub NodeData: DXGK_NODEMETADATA,
}
impl Default for D3DKMT_NODEMETADATA {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_NODE_PERFDATA {
    pub NodeOrdinal: u32,
    pub PhysicalAdapterIndex: u32,
    pub Frequency: u64,
    pub MaxFrequency: u64,
    pub MaxFrequencyOC: u64,
    pub Voltage: u32,
    pub VoltageMax: u32,
    pub VoltageMaxOC: u32,
    pub MaxTransitionLatency: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYADAPTERINFO {
    pub hAdapter: D3DKMT_HANDLE,
    pub Type: KMTQUERYADAPTERINFOTYPE,
    pub pPrivateDriverData: *mut core::ffi::c_void,
    pub PrivateDriverDataSize: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct D3DKMT_QUERYSTATISTICS {
    pub Type: D3DKMT_QUERYSTATISTICS_TYPE,
    pub AdapterLuid: LUID,
    pub hProcess: HANDLE,
    pub QueryResult: D3DKMT_QUERYSTATISTICS_RESULT,
    pub Anonymous: D3DKMT_QUERYSTATISTICS_0,
}
impl Default for D3DKMT_QUERYSTATISTICS {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union D3DKMT_QUERYSTATISTICS_0 {
    pub QuerySegment: D3DKMT_QUERYSTATISTICS_QUERY_SEGMENT,
    pub QueryProcessSegment: D3DKMT_QUERYSTATISTICS_QUERY_SEGMENT,
    pub QueryProcessSegmentGroup: D3DKMT_MEMORY_SEGMENT_GROUP,
    pub QueryNode: D3DKMT_QUERYSTATISTICS_QUERY_NODE,
    pub QueryProcessNode: D3DKMT_QUERYSTATISTICS_QUERY_NODE,
    pub QueryVidPnSource: D3DKMT_QUERYSTATISTICS_QUERY_VIDPNSOURCE,
    pub QueryProcessVidPnSource: D3DKMT_QUERYSTATISTICS_QUERY_VIDPNSOURCE,
    pub QueryPhysAdapter: D3DKMT_QUERYSTATISTICS_QUERY_PHYSICAL_ADAPTER,
    pub QueryAdapter2: D3DKMT_QUERYSTATISTICS_QUERY_ADAPTER2,
    pub QuerySegment2: D3DKMT_QUERYSTATISTICS_QUERY_SEGMENT2,
    pub QueryProcessAdapter2: D3DKMT_QUERYSTATISTICS_QUERY_ADAPTER2,
    pub QueryProcessSegment2: D3DKMT_QUERYSTATISTICS_QUERY_SEGMENT2,
    pub QueryProcessSegmentGroup2: D3DKMT_QUERYSTATISTICS_QUERY_PROCESS_SEGMENT_GROUP2,
    pub QuerySegmentUsage: D3DKMT_QUERYSTATISTICS_QUERY_SEGMENT_USAGE,
    pub QuerySegmentGroupUsage: D3DKMT_QUERYSTATISTICS_QUERY_SEGMENT_GROUP_USAGE,
    pub QueryNode2: D3DKMT_QUERYSTATISTICS_QUERY_NODE2,
    pub QueryProcessNode2: D3DKMT_QUERYSTATISTICS_QUERY_NODE2,
}
impl Default for D3DKMT_QUERYSTATISTICS_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const D3DKMT_QUERYSTATISTICS_ADAPTER: D3DKMT_QUERYSTATISTICS_TYPE = 0;
pub const D3DKMT_QUERYSTATISTICS_ADAPTER2: D3DKMT_QUERYSTATISTICS_TYPE = 11;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION {
    pub NbSegments: u32,
    pub NodeCount: u32,
    pub VidPnSourceCount: u32,
    pub VSyncEnabled: u32,
    pub TdrDetectedCount: u32,
    pub ZeroLengthDmaBuffers: i64,
    pub RestartedPeriod: u64,
    pub ReferenceDmaBuffer: D3DKMT_QUERYSTATSTICS_REFERENCE_DMA_BUFFER,
    pub Renaming: D3DKMT_QUERYSTATSTICS_RENAMING,
    pub Preparation: D3DKMT_QUERYSTATSTICS_PREPRATION,
    pub PagingFault: D3DKMT_QUERYSTATSTICS_PAGING_FAULT,
    pub PagingTransfer: D3DKMT_QUERYSTATSTICS_PAGING_TRANSFER,
    pub SwizzlingRange: D3DKMT_QUERYSTATSTICS_SWIZZLING_RANGE,
    pub Locks: D3DKMT_QUERYSTATSTICS_LOCKS,
    pub Allocations: D3DKMT_QUERYSTATSTICS_ALLOCATIONS,
    pub Terminations: D3DKMT_QUERYSTATSTICS_TERMINATIONS,
    pub Flags: D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION_FLAGS,
    pub Reserved: [u64; 7],
}
impl Default for D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION_FLAGS {
    pub Anonymous: D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION_FLAGS_0,
}
impl Default for D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION_FLAGS {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION_FLAGS_0 {
    pub Anonymous: D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION_FLAGS_0_0,
    pub Value: u64,
}
impl Default for D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION_FLAGS_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION_FLAGS_0_0 {
    pub _bitfield: u64,
}
impl D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION_FLAGS_0_0 {
    pub fn NumberOfMemoryGroups(&self) -> u64 {
        (self._bitfield << 62) >> 62
    }
    pub fn set_NumberOfMemoryGroups(&mut self, value: u64) {
        self._bitfield = (self._bitfield & !3) | (value & 3);
    }
    pub fn SupportsDemotion(&self) -> bool {
        (self._bitfield >> 2) & 1 != 0
    }
    pub fn set_SupportsDemotion(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 2)) | ((value as u64) << 2);
    }
    pub fn Reserved(&self) -> u64 {
        self._bitfield >> 3
    }
    pub fn set_Reserved(&mut self, value: u64) {
        self._bitfield =
            (self._bitfield & !(2305843009213693951 << 3)) | ((value & 2305843009213693951) << 3);
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_COMMITMENT_DATA {
    pub TotalBytesEvictedFromProcess: u64,
    pub BytesBySegmentPreference: [u64; 5],
}
impl Default for D3DKMT_QUERYSTATISTICS_COMMITMENT_DATA {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_COUNTER {
    pub Count: u32,
    pub Bytes: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_DMA_BUFFER {
    pub Size: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub AllocationListBytes: u32,
    pub PatchLocationListBytes: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_DMA_PACKET_TYPE_INFORMATION {
    pub PacketSubmited: u32,
    pub PacketCompleted: u32,
    pub PacketPreempted: u32,
    pub PacketFaulted: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_MEMORY {
    pub TotalBytesEvicted: u64,
    pub AllocsCommitted: u32,
    pub AllocsResident: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_MEMORY_USAGE {
    pub AllocatedBytes: u64,
    pub FreeBytes: u64,
    pub ZeroBytes: u64,
    pub ModifiedBytes: u64,
    pub StandbyBytes: u64,
}
pub const D3DKMT_QUERYSTATISTICS_NODE: D3DKMT_QUERYSTATISTICS_TYPE = 5;
pub const D3DKMT_QUERYSTATISTICS_NODE2: D3DKMT_QUERYSTATISTICS_TYPE = 18;
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_NODE_INFORMATION {
    pub GlobalInformation: D3DKMT_QUERYSTATISTICS_PROCESS_NODE_INFORMATION,
    pub SystemInformation: D3DKMT_QUERYSTATISTICS_PROCESS_NODE_INFORMATION,
    pub NodePerfData: D3DKMT_NODE_PERFDATA,
    pub Reserved: [u32; 3],
}
impl Default for D3DKMT_QUERYSTATISTICS_NODE_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PACKET_INFORMATION {
    pub QueuePacket: [D3DKMT_QUERYSTATISTICS_QUEUE_PACKET_TYPE_INFORMATION; 8],
    pub DmaPacket: [D3DKMT_QUERYSTATISTICS_DMA_PACKET_TYPE_INFORMATION; 4],
}
impl Default for D3DKMT_QUERYSTATISTICS_PACKET_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const D3DKMT_QUERYSTATISTICS_PHYSICAL_ADAPTER: D3DKMT_QUERYSTATISTICS_TYPE = 10;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PHYSICAL_ADAPTER_INFORMATION {
    pub AdapterPerfData: D3DKMT_ADAPTER_PERFDATA,
    pub AdapterPerfDataCaps: D3DKMT_ADAPTER_PERFDATACAPS,
    pub GpuVersion: D3DKMT_GPUVERSION,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_POLICY {
    pub PreferApertureForRead: [u64; 5],
    pub PreferAperture: [u64; 5],
    pub MemResetOnPaging: u64,
    pub RemovePagesFromWorkingSetOnPaging: u64,
    pub MigrationEnabled: u64,
}
impl Default for D3DKMT_QUERYSTATISTICS_POLICY {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PREEMPTION_INFORMATION {
    pub PreemptionCounter: [u32; 16],
}
impl Default for D3DKMT_QUERYSTATISTICS_PREEMPTION_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const D3DKMT_QUERYSTATISTICS_PROCESS: D3DKMT_QUERYSTATISTICS_TYPE = 1;
pub const D3DKMT_QUERYSTATISTICS_PROCESS_ADAPTER: D3DKMT_QUERYSTATISTICS_TYPE = 2;
pub const D3DKMT_QUERYSTATISTICS_PROCESS_ADAPTER2: D3DKMT_QUERYSTATISTICS_TYPE = 13;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PROCESS_ADAPTER_INFORMATION {
    pub NbSegments: u32,
    pub NodeCount: u32,
    pub VidPnSourceCount: u32,
    pub VirtualMemoryUsage: u32,
    pub DmaBuffer: D3DKMT_QUERYSTATISTICS_DMA_BUFFER,
    pub CommitmentData: D3DKMT_QUERYSTATISTICS_COMMITMENT_DATA,
    pub _Policy: D3DKMT_QUERYSTATISTICS_POLICY,
    pub ProcessInterferenceCounters: D3DKMT_QUERYSTATISTICS_PROCESS_INTERFERENCE_COUNTERS,
    pub ClientHint: D3DKMT_CLIENTHINT,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PROCESS_INFORMATION {
    pub NodeCount: u32,
    pub VidPnSourceCount: u32,
    pub SystemMemory: D3DKMT_QUERYSTATISTICS_SYSTEM_MEMORY,
    pub Reserved: [u64; 7],
}
impl Default for D3DKMT_QUERYSTATISTICS_PROCESS_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PROCESS_INTERFERENCE_COUNTERS {
    pub InterferenceCount: [u64; 9],
}
impl Default for D3DKMT_QUERYSTATISTICS_PROCESS_INTERFERENCE_COUNTERS {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const D3DKMT_QUERYSTATISTICS_PROCESS_NODE: D3DKMT_QUERYSTATISTICS_TYPE = 6;
pub const D3DKMT_QUERYSTATISTICS_PROCESS_NODE2: D3DKMT_QUERYSTATISTICS_TYPE = 19;
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PROCESS_NODE_INFORMATION {
    pub RunningTime: i64,
    pub ContextSwitch: u32,
    pub PreemptionStatistics: D3DKMT_QUERYSTATISTICS_PREEMPTION_INFORMATION,
    pub PacketStatistics: D3DKMT_QUERYSTATISTICS_PACKET_INFORMATION,
    pub Reserved: [u64; 8],
}
impl Default for D3DKMT_QUERYSTATISTICS_PROCESS_NODE_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT: D3DKMT_QUERYSTATISTICS_TYPE = 4;
pub const D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT2: D3DKMT_QUERYSTATISTICS_TYPE = 14;
pub const D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP: D3DKMT_QUERYSTATISTICS_TYPE = 9;
pub const D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP2: D3DKMT_QUERYSTATISTICS_TYPE = 15;
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP_INFORMATION {
    pub Budget: u64,
    pub Requested: u64,
    pub Usage: u64,
    pub Demoted: [u64; 5],
}
impl Default for D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_INFORMATION {
    pub BytesCommitted: u64,
    pub MaximumWorkingSet: u64,
    pub MinimumWorkingSet: u64,
    pub NbReferencedAllocationEvictedInPeriod: u32,
    pub Padding: u32,
    pub VideoMemory: D3DKMT_QUERYSTATISTICS_VIDEO_MEMORY,
    pub _Policy: D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_POLICY,
    pub Reserved: [u64; 8],
}
impl Default for D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_POLICY {
    pub UseMRU: u64,
}
pub const D3DKMT_QUERYSTATISTICS_PROCESS_VIDPNSOURCE: D3DKMT_QUERYSTATISTICS_TYPE = 8;
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_PROCESS_VIDPNSOURCE_INFORMATION {
    pub Frame: u32,
    pub CancelledFrame: u32,
    pub QueuedPresent: u32,
    pub Padding: u32,
    pub IsVSyncEnabled: u64,
    pub VSyncOnTotalTimeMs: u64,
    pub VSyncOffKeepPhaseTotalTimeMs: u64,
    pub VSyncOffNoPhaseTotalTimeMs: u64,
    pub Reserved: [u64; 4],
}
impl Default for D3DKMT_QUERYSTATISTICS_PROCESS_VIDPNSOURCE_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUERY_ADAPTER2 {
    pub PhysicalAdapterIndex: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUERY_NODE {
    pub NodeId: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUERY_NODE2 {
    pub PhysicalAdapterIndex: u16,
    pub NodeOrdinal: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUERY_PHYSICAL_ADAPTER {
    pub PhysicalAdapterIndex: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUERY_PROCESS_SEGMENT_GROUP2 {
    pub PhysicalAdapterIndex: u16,
    pub SegmentGroup: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUERY_SEGMENT {
    pub SegmentId: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUERY_SEGMENT2 {
    pub PhysicalAdapterIndex: u16,
    pub SegmentId: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUERY_SEGMENT_GROUP_USAGE {
    pub PhysicalAdapterIndex: u16,
    pub SegmentGroup: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUERY_SEGMENT_USAGE {
    pub PhysicalAdapterIndex: u16,
    pub SegmentId: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUERY_VIDPNSOURCE {
    pub VidPnSourceId: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_QUEUE_PACKET_TYPE_INFORMATION {
    pub PacketSubmited: u32,
    pub PacketCompleted: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union D3DKMT_QUERYSTATISTICS_RESULT {
    pub AdapterInformation: D3DKMT_QUERYSTATISTICS_ADAPTER_INFORMATION,
    pub PhysAdapterInformation: D3DKMT_QUERYSTATISTICS_PHYSICAL_ADAPTER_INFORMATION,
    pub SegmentInformation: D3DKMT_QUERYSTATISTICS_SEGMENT_INFORMATION,
    pub NodeInformation: D3DKMT_QUERYSTATISTICS_NODE_INFORMATION,
    pub VidPnSourceInformation: D3DKMT_QUERYSTATISTICS_VIDPNSOURCE_INFORMATION,
    pub ProcessInformation: D3DKMT_QUERYSTATISTICS_PROCESS_INFORMATION,
    pub ProcessAdapterInformation: D3DKMT_QUERYSTATISTICS_PROCESS_ADAPTER_INFORMATION,
    pub ProcessSegmentInformation: D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_INFORMATION,
    pub ProcessNodeInformation: D3DKMT_QUERYSTATISTICS_PROCESS_NODE_INFORMATION,
    pub ProcessVidPnSourceInformation: D3DKMT_QUERYSTATISTICS_PROCESS_VIDPNSOURCE_INFORMATION,
    pub ProcessSegmentGroupInformation: D3DKMT_QUERYSTATISTICS_PROCESS_SEGMENT_GROUP_INFORMATION,
    pub SegmentUsageInformation: D3DKMT_QUERYSTATISTICS_MEMORY_USAGE,
    pub SegmentGroupUsageInformation: D3DKMT_QUERYSTATISTICS_MEMORY_USAGE,
}
impl Default for D3DKMT_QUERYSTATISTICS_RESULT {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const D3DKMT_QUERYSTATISTICS_SEGMENT: D3DKMT_QUERYSTATISTICS_TYPE = 3;
pub const D3DKMT_QUERYSTATISTICS_SEGMENT2: D3DKMT_QUERYSTATISTICS_TYPE = 12;
pub const D3DKMT_QUERYSTATISTICS_SEGMENT_GROUP_USAGE: D3DKMT_QUERYSTATISTICS_TYPE = 17;
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_SEGMENT_INFORMATION {
    pub CommitLimit: u64,
    pub BytesCommitted: u64,
    pub BytesResident: u64,
    pub Memory: D3DKMT_QUERYSTATISTICS_MEMORY,
    pub Aperture: u32,
    pub TotalBytesEvictedByPriority: [u64; 5],
    pub SystemMemoryEndAddress: u64,
    pub PowerFlags: D3DKMT_QUERYSTATISTICS_SEGMENT_INFORMATION_0,
    pub SegmentProperties: D3DKMT_QUERYSTATISTICS_SEGMENT_INFORMATION_1,
    pub Reserved: [u64; 5],
}
impl Default for D3DKMT_QUERYSTATISTICS_SEGMENT_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_SEGMENT_INFORMATION_0 {
    pub _bitfield: u64,
}
impl D3DKMT_QUERYSTATISTICS_SEGMENT_INFORMATION_0 {
    pub fn PreservedDuringStandby(&self) -> bool {
        self._bitfield & 1 != 0
    }
    pub fn set_PreservedDuringStandby(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !1) | (value as u64);
    }
    pub fn PreservedDuringHibernate(&self) -> bool {
        (self._bitfield >> 1) & 1 != 0
    }
    pub fn set_PreservedDuringHibernate(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 1)) | ((value as u64) << 1);
    }
    pub fn PartiallyPreservedDuringHibernate(&self) -> bool {
        (self._bitfield >> 2) & 1 != 0
    }
    pub fn set_PartiallyPreservedDuringHibernate(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 2)) | ((value as u64) << 2);
    }
    pub fn Reserved(&self) -> u64 {
        self._bitfield >> 3
    }
    pub fn set_Reserved(&mut self, value: u64) {
        self._bitfield =
            (self._bitfield & !(2305843009213693951 << 3)) | ((value & 2305843009213693951) << 3);
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_SEGMENT_INFORMATION_1 {
    pub _bitfield: u64,
}
impl D3DKMT_QUERYSTATISTICS_SEGMENT_INFORMATION_1 {
    pub fn SystemMemory(&self) -> bool {
        self._bitfield & 1 != 0
    }
    pub fn set_SystemMemory(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !1) | (value as u64);
    }
    pub fn PopulatedByReservedDDRByFirmware(&self) -> bool {
        (self._bitfield >> 1) & 1 != 0
    }
    pub fn set_PopulatedByReservedDDRByFirmware(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 1)) | ((value as u64) << 1);
    }
    pub fn SegmentType(&self) -> u64 {
        (self._bitfield << 58) >> 60
    }
    pub fn set_SegmentType(&mut self, value: u64) {
        self._bitfield = (self._bitfield & !(15 << 2)) | ((value & 15) << 2);
    }
    pub fn SegmentGroup(&self) -> u64 {
        (self._bitfield << 56) >> 62
    }
    pub fn set_SegmentGroup(&mut self, value: u64) {
        self._bitfield = (self._bitfield & !(3 << 6)) | ((value & 3) << 6);
    }
    pub fn FullyCPUVisible(&self) -> bool {
        (self._bitfield >> 8) & 1 != 0
    }
    pub fn set_FullyCPUVisible(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 8)) | ((value as u64) << 8);
    }
    pub fn Reserved(&self) -> u64 {
        self._bitfield >> 9
    }
    pub fn set_Reserved(&mut self, value: u64) {
        self._bitfield =
            (self._bitfield & !(36028797018963967 << 9)) | ((value & 36028797018963967) << 9);
    }
}
pub const D3DKMT_QUERYSTATISTICS_SEGMENT_USAGE: D3DKMT_QUERYSTATISTICS_TYPE = 16;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_SYSTEM_MEMORY {
    pub BytesAllocated: u64,
    pub BytesReserved: u64,
    pub SmallAllocationBlocks: u32,
    pub LargeAllocationBlocks: u32,
    pub WriteCombinedBytesAllocated: u64,
    pub WriteCombinedBytesReserved: u64,
    pub CachedBytesAllocated: u64,
    pub CachedBytesReserved: u64,
    pub SectionBytesAllocated: u64,
    pub SectionBytesReserved: u64,
    pub BytesZeroed: u64,
}
pub type D3DKMT_QUERYSTATISTICS_TYPE = i32;
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_VIDEO_MEMORY {
    pub AllocsCommitted: u32,
    pub AllocsResidentInP: [D3DKMT_QUERYSTATISTICS_COUNTER; 5],
    pub AllocsResidentInNonPreferred: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub TotalBytesEvictedDueToPreparation: u64,
}
impl Default for D3DKMT_QUERYSTATISTICS_VIDEO_MEMORY {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const D3DKMT_QUERYSTATISTICS_VIDPNSOURCE: D3DKMT_QUERYSTATISTICS_TYPE = 7;
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATISTICS_VIDPNSOURCE_INFORMATION {
    pub GlobalInformation: D3DKMT_QUERYSTATISTICS_PROCESS_VIDPNSOURCE_INFORMATION,
    pub SystemInformation: D3DKMT_QUERYSTATISTICS_PROCESS_VIDPNSOURCE_INFORMATION,
    pub Reserved: [u64; 8],
}
impl Default for D3DKMT_QUERYSTATISTICS_VIDPNSOURCE_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATSTICS_ALLOCATIONS {
    pub Created: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub Destroyed: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub Opened: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub Closed: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub MigratedSuccess: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub MigratedFail: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub MigratedAbandoned: D3DKMT_QUERYSTATISTICS_COUNTER,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATSTICS_LOCKS {
    pub NbLocks: u32,
    pub NbLocksWaitFlag: u32,
    pub NbLocksDiscardFlag: u32,
    pub NbLocksNoOverwrite: u32,
    pub NbLocksNoReadSync: u32,
    pub NbLocksLinearization: u32,
    pub NbComplexLocks: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATSTICS_PAGING_FAULT {
    pub Faults: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub FaultsFirstTimeAccess: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub FaultsReclaimed: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub FaultsMigration: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub FaultsIncorrectResource: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub FaultsLostContent: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub FaultsEvicted: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub AllocationsMEM_RESET: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub AllocationsUnresetSuccess: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub AllocationsUnresetFail: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub AllocationsUnresetSuccessRead: u32,
    pub AllocationsUnresetFailRead: u32,
    pub Evictions: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub EvictionsDueToPreparation: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub EvictionsDueToLock: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub EvictionsDueToClose: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub EvictionsDueToPurge: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub EvictionsDueToSuspendCPUAccess: D3DKMT_QUERYSTATISTICS_COUNTER,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATSTICS_PAGING_TRANSFER {
    pub BytesFilled: u64,
    pub BytesDiscarded: u64,
    pub BytesMappedIntoAperture: u64,
    pub BytesUnmappedFromAperture: u64,
    pub BytesTransferredFromMdlToMemory: u64,
    pub BytesTransferredFromMemoryToMdl: u64,
    pub BytesTransferredFromApertureToMemory: u64,
    pub BytesTransferredFromMemoryToAperture: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATSTICS_PREPRATION {
    pub BroadcastStall: u32,
    pub NbDMAPrepared: u32,
    pub NbDMAPreparedLongPath: u32,
    pub ImmediateHighestPreparationPass: u32,
    pub AllocationsTrimmed: D3DKMT_QUERYSTATISTICS_COUNTER,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATSTICS_REFERENCE_DMA_BUFFER {
    pub NbCall: u32,
    pub NbAllocationsReferenced: u32,
    pub MaxNbAllocationsReferenced: u32,
    pub NbNULLReference: u32,
    pub NbWriteReference: u32,
    pub NbRenamedAllocationsReferenced: u32,
    pub NbIterationSearchingRenamedAllocation: u32,
    pub NbLockedAllocationReferenced: u32,
    pub NbAllocationWithValidPrepatchingInfoReferenced: u32,
    pub NbAllocationWithInvalidPrepatchingInfoReferenced: u32,
    pub NbDMABufferSuccessfullyPrePatched: u32,
    pub NbPrimariesReferencesOverflow: u32,
    pub NbAllocationWithNonPreferredResources: u32,
    pub NbAllocationInsertedInMigrationTable: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATSTICS_RENAMING {
    pub NbAllocationsRenamed: u32,
    pub NbAllocationsShrinked: u32,
    pub NbRenamedBuffer: u32,
    pub MaxRenamingListLength: u32,
    pub NbFailuresDueToRenamingLimit: u32,
    pub NbFailuresDueToCreateAllocation: u32,
    pub NbFailuresDueToOpenAllocation: u32,
    pub NbFailuresDueToLowResource: u32,
    pub NbFailuresDueToNonRetiredLimit: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATSTICS_SWIZZLING_RANGE {
    pub NbRangesAcquired: u32,
    pub NbRangesReleased: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_QUERYSTATSTICS_TERMINATIONS {
    pub TerminatedShared: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub TerminatedNonShared: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub DestroyedShared: D3DKMT_QUERYSTATISTICS_COUNTER,
    pub DestroyedNonShared: D3DKMT_QUERYSTATISTICS_COUNTER,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct D3DKMT_SEGMENTSIZEINFO {
    pub DedicatedVideoMemorySize: u64,
    pub DedicatedSystemMemorySize: u64,
    pub SharedSystemMemorySize: u64,
}
pub const DACL_SECURITY_INFORMATION: i32 = 4;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DPI_AWARENESS_CONTEXT(pub *mut core::ffi::c_void);
pub const DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE: DPI_AWARENESS_CONTEXT =
    DPI_AWARENESS_CONTEXT(-3 as _);
pub const DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2: DPI_AWARENESS_CONTEXT =
    DPI_AWARENESS_CONTEXT(-4 as _);
pub const DPI_AWARENESS_CONTEXT_SYSTEM_AWARE: DPI_AWARENESS_CONTEXT =
    DPI_AWARENESS_CONTEXT(-2 as _);
pub const DPI_AWARENESS_CONTEXT_UNAWARE: DPI_AWARENESS_CONTEXT = DPI_AWARENESS_CONTEXT(-1 as _);
pub const DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED: DPI_AWARENESS_CONTEXT =
    DPI_AWARENESS_CONTEXT(-5 as _);
pub const DRIVE_REMOTE: i32 = 4;
pub const DUPLICATE_SAME_ACCESS: i32 = 2;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DWORDLONG(pub u64);
pub type DXGK_ENGINE_TYPE = i32;
#[repr(C, packed(1))]
#[derive(Clone, Copy)]
pub struct DXGK_NODEMETADATA {
    pub EngineType: DXGK_ENGINE_TYPE,
    pub FriendlyName: [u16; 32],
    pub Flags: DXGK_NODEMETADATA_FLAGS,
    pub GpuMmuSupported: bool,
    pub IoMmuSupported: bool,
}
impl Default for DXGK_NODEMETADATA {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DXGK_NODEMETADATA_FLAGS {
    pub Anonymous: DXGK_NODEMETADATA_FLAGS_0,
}
impl Default for DXGK_NODEMETADATA_FLAGS {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C, packed(1))]
#[derive(Clone, Copy)]
pub union DXGK_NODEMETADATA_FLAGS_0 {
    pub Anonymous: DXGK_NODEMETADATA_FLAGS_0_0,
    pub Value: u32,
}
impl Default for DXGK_NODEMETADATA_FLAGS_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C, packed(1))]
#[derive(Clone, Copy, Default)]
pub struct DXGK_NODEMETADATA_FLAGS_0_0 {
    pub _bitfield: u32,
}
impl DXGK_NODEMETADATA_FLAGS_0_0 {
    pub fn ContextSchedulingSupported(&self) -> bool {
        self._bitfield & 1 != 0
    }
    pub fn set_ContextSchedulingSupported(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !1) | (value as u32);
    }
    pub fn RingBufferFenceRelease(&self) -> bool {
        (self._bitfield >> 1) & 1 != 0
    }
    pub fn set_RingBufferFenceRelease(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 1)) | ((value as u32) << 1);
    }
    pub fn SupportTrackedWorkload(&self) -> bool {
        (self._bitfield >> 2) & 1 != 0
    }
    pub fn set_SupportTrackedWorkload(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 2)) | ((value as u32) << 2);
    }
    pub fn UserModeSubmission(&self) -> bool {
        (self._bitfield >> 3) & 1 != 0
    }
    pub fn set_UserModeSubmission(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 3)) | ((value as u32) << 3);
    }
    pub fn SupportBuildTestCommandBuffer(&self) -> bool {
        (self._bitfield >> 4) & 1 != 0
    }
    pub fn set_SupportBuildTestCommandBuffer(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 4)) | ((value as u32) << 4);
    }
    pub fn SupportFaultAndStall(&self) -> bool {
        (self._bitfield >> 5) & 1 != 0
    }
    pub fn set_SupportFaultAndStall(&mut self, value: bool) {
        self._bitfield = (self._bitfield & !(1 << 5)) | ((value as u32) << 5);
    }
    pub fn Reserved(&self) -> u32 {
        (self._bitfield << 16) >> 22
    }
    pub fn set_Reserved(&mut self, value: u32) {
        self._bitfield = (self._bitfield & !(1023 << 6)) | ((value & 1023) << 6);
    }
    pub fn MaxInFlightHwQueueBuffers(&self) -> u32 {
        self._bitfield >> 16
    }
    pub fn set_MaxInFlightHwQueueBuffers(&mut self, value: u32) {
        self._bitfield = (self._bitfield & !(65535 << 16)) | ((value & 65535) << 16);
    }
}
pub const ERROR_ALREADY_EXISTS: i32 = 183;
pub const ERROR_BAD_LENGTH: i32 = 24;
pub const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
pub const ERROR_NOT_ALL_ASSIGNED: i32 = 1300;
pub const ERROR_SUCCESS: i32 = 0;
pub const EVENT_TRACE_FLAG_DISK_IO: i32 = 256;
pub const EVENT_TRACE_FLAG_NETWORK_TCPIP: i32 = 65536;
pub const EVENT_TRACE_FLAG_PROCESS: i32 = 1;
pub type FARPROC = Option<unsafe extern "system" fn() -> isize>;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}
pub const FILE_ATTRIBUTE_NORMAL: i32 = 128;
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FILE_ID_128 {
    pub Identifier: [u8; 16],
}
impl Default for FILE_ID_128 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FILE_ID_INFO {
    pub VolumeSerialNumber: u64,
    pub FileId: FILE_ID_128,
}
pub type FILE_INFO_BY_HANDLE_CLASS = i32;
pub const FILE_MAP_WRITE: i32 = 2;
pub const FILE_READ_ATTRIBUTES: i32 = 128;
pub const FILE_SHARE_DELETE: i32 = 4;
pub const FILE_SHARE_READ: i32 = 1;
pub const FILE_SHARE_WRITE: i32 = 2;
pub const FSCTL_READ_FILE_USN_DATA: i32 = 590059;
pub const FileIdInfo: FILE_INFO_BY_HANDLE_CLASS = 18;
pub const GENERIC_READ: u32 = 2147483648;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HANDLE(pub *mut core::ffi::c_void);
pub type HCATADMIN = HANDLE;
pub type HCATINFO = HANDLE;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HCERTSTORE(pub *mut core::ffi::c_void);
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HCRYPTMSG(pub *mut core::ffi::c_void);
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HCRYPTPROV(pub usize);
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HICON(pub *mut core::ffi::c_void);
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HINSTANCE(pub *mut core::ffi::c_void);
pub type HLOCAL = HANDLE;
pub type HMODULE = HINSTANCE;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HWND(pub *mut core::ffi::c_void);
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct IFTYPE(pub u32);
pub type IF_OPER_STATUS = i32;
pub const IF_TYPE_SOFTWARE_LOOPBACK: i32 = 24;
pub const IF_TYPE_TUNNEL: i32 = 131;
pub const INVALID_HANDLE_VALUE: HANDLE = HANDLE(-1 as _);
pub const IfOperStatusUp: IF_OPER_STATUS = 1;
pub const KMTQAITYPE_ADAPTERADDRESS: KMTQUERYADAPTERINFOTYPE = 6;
pub const KMTQAITYPE_ADAPTERADDRESS_RENDER: KMTQUERYADAPTERINFOTYPE = 53;
pub const KMTQAITYPE_ADAPTERGUID: KMTQUERYADAPTERINFOTYPE = 4;
pub const KMTQAITYPE_ADAPTERGUID_RENDER: KMTQUERYADAPTERINFOTYPE = 52;
pub const KMTQAITYPE_ADAPTERPERFDATA: KMTQUERYADAPTERINFOTYPE = 62;
pub const KMTQAITYPE_ADAPTERPERFDATA_CAPS: KMTQUERYADAPTERINFOTYPE = 63;
pub const KMTQAITYPE_ADAPTERREGISTRYINFO: KMTQUERYADAPTERINFOTYPE = 8;
pub const KMTQAITYPE_ADAPTERREGISTRYINFO_RENDER: KMTQUERYADAPTERINFOTYPE = 54;
pub const KMTQAITYPE_ADAPTERTYPE: KMTQUERYADAPTERINFOTYPE = 15;
pub const KMTQAITYPE_ADAPTERTYPE_RENDER: KMTQUERYADAPTERINFOTYPE = 57;
pub const KMTQAITYPE_BLOCKLIST_KERNEL: KMTQUERYADAPTERINFOTYPE = 50;
pub const KMTQAITYPE_BLOCKLIST_RUNTIME: KMTQUERYADAPTERINFOTYPE = 51;
pub const KMTQAITYPE_CHECKDRIVERUPDATESTATUS: KMTQUERYADAPTERINFOTYPE = 11;
pub const KMTQAITYPE_CHECKDRIVERUPDATESTATUS_RENDER: KMTQUERYADAPTERINFOTYPE = 55;
pub const KMTQAITYPE_CPDRIVERNAME: KMTQUERYADAPTERINFOTYPE = 26;
pub const KMTQAITYPE_CROSSADAPTERRESOURCE_SUPPORT: KMTQUERYADAPTERINFOTYPE = 76;
pub const KMTQAITYPE_CURRENTDISPLAYMODE: KMTQUERYADAPTERINFOTYPE = 9;
pub const KMTQAITYPE_DIRECTFLIP_SUPPORT: KMTQUERYADAPTERINFOTYPE = 19;
pub const KMTQAITYPE_DISPLAY_CAPS: KMTQUERYADAPTERINFOTYPE = 74;
pub const KMTQAITYPE_DISPLAY_UMDRIVERNAME: KMTQUERYADAPTERINFOTYPE = 71;
pub const KMTQAITYPE_DLIST_DRIVER_NAME: KMTQUERYADAPTERINFOTYPE = 21;
pub const KMTQAITYPE_DRIVERCAPS_EXT: KMTQUERYADAPTERINFOTYPE = 32;
pub const KMTQAITYPE_DRIVERVERSION: KMTQUERYADAPTERINFOTYPE = 13;
pub const KMTQAITYPE_DRIVERVERSION_RENDER: KMTQUERYADAPTERINFOTYPE = 56;
pub const KMTQAITYPE_DRIVER_DESCRIPTION: KMTQUERYADAPTERINFOTYPE = 65;
pub const KMTQAITYPE_DRIVER_DESCRIPTION_RENDER: KMTQUERYADAPTERINFOTYPE = 66;
pub const KMTQAITYPE_FLIPQUEUEINFO: KMTQUERYADAPTERINFOTYPE = 5;
pub const KMTQAITYPE_GETSEGMENTGROUPSIZE: KMTQUERYADAPTERINFOTYPE = 42;
pub const KMTQAITYPE_GETSEGMENTSIZE: KMTQUERYADAPTERINFOTYPE = 3;
pub const KMTQAITYPE_GET_DEVICE_VIDPN_OWNERSHIP_INFO: KMTQUERYADAPTERINFOTYPE = 47;
pub const KMTQAITYPE_HWDRM_SUPPORT: KMTQUERYADAPTERINFOTYPE = 44;
pub const KMTQAITYPE_HYBRID_DLIST_DLL_MUX_SUPPORT: KMTQUERYADAPTERINFOTYPE = 81;
pub const KMTQAITYPE_HYBRID_DLIST_DLL_SUPPORT: KMTQUERYADAPTERINFOTYPE = 73;
pub const KMTQAITYPE_INDEPENDENTFLIP_SECONDARY_SUPPORT: KMTQUERYADAPTERINFOTYPE = 39;
pub const KMTQAITYPE_INDEPENDENTFLIP_SUPPORT: KMTQUERYADAPTERINFOTYPE = 28;
pub const KMTQAITYPE_KMD_DRIVER_VERSION: KMTQUERYADAPTERINFOTYPE = 49;
pub const KMTQAITYPE_MIRACASTCOMPANIONDRIVERNAME: KMTQUERYADAPTERINFOTYPE = 29;
pub const KMTQAITYPE_MODELIST: KMTQUERYADAPTERINFOTYPE = 10;
pub const KMTQAITYPE_MPO3DDI_SUPPORT: KMTQUERYADAPTERINFOTYPE = 43;
pub const KMTQAITYPE_MPOKERNELCAPS_SUPPORT: KMTQUERYADAPTERINFOTYPE = 45;
pub const KMTQAITYPE_MULTIPLANEOVERLAY_HUD_SUPPORT: KMTQUERYADAPTERINFOTYPE = 23;
pub const KMTQAITYPE_MULTIPLANEOVERLAY_SECONDARY_SUPPORT: KMTQUERYADAPTERINFOTYPE = 38;
pub const KMTQAITYPE_MULTIPLANEOVERLAY_STRETCH_SUPPORT: KMTQUERYADAPTERINFOTYPE = 46;
pub const KMTQAITYPE_MULTIPLANEOVERLAY_SUPPORT: KMTQUERYADAPTERINFOTYPE = 20;
pub const KMTQAITYPE_NODEMETADATA: KMTQUERYADAPTERINFOTYPE = 25;
pub const KMTQAITYPE_NODEPERFDATA: KMTQUERYADAPTERINFOTYPE = 61;
pub const KMTQAITYPE_OUTPUTDUPLCONTEXTSCOUNT: KMTQUERYADAPTERINFOTYPE = 16;
pub const KMTQAITYPE_PANELFITTER_SUPPORT: KMTQUERYADAPTERINFOTYPE = 40;
pub const KMTQAITYPE_PARAVIRTUALIZATION_RENDER: KMTQUERYADAPTERINFOTYPE = 68;
pub const KMTQAITYPE_PHYSICALADAPTERCOUNT: KMTQUERYADAPTERINFOTYPE = 30;
pub const KMTQAITYPE_PHYSICALADAPTERDEVICEIDS: KMTQUERYADAPTERINFOTYPE = 31;
pub const KMTQAITYPE_PHYSICALADAPTERPNPKEY: KMTQUERYADAPTERINFOTYPE = 41;
pub const KMTQAITYPE_QUERYREGISTRY: KMTQUERYADAPTERINFOTYPE = 48;
pub const KMTQAITYPE_QUERY_ADAPTER_UNIQUE_GUID: KMTQUERYADAPTERINFOTYPE = 60;
pub const KMTQAITYPE_QUERY_GPUMMU_CAPS: KMTQUERYADAPTERINFOTYPE = 34;
pub const KMTQAITYPE_QUERY_HW_PROTECTION_TEARDOWN_COUNT: KMTQUERYADAPTERINFOTYPE = 36;
pub const KMTQAITYPE_QUERY_ISBADDRIVERFORHWPROTECTIONDISABLED: KMTQUERYADAPTERINFOTYPE = 37;
pub const KMTQAITYPE_QUERY_MIRACAST_DRIVER_TYPE: KMTQUERYADAPTERINFOTYPE = 33;
pub const KMTQAITYPE_QUERY_MULTIPLANEOVERLAY_DECODE_SUPPORT: KMTQUERYADAPTERINFOTYPE = 35;
pub const KMTQAITYPE_SCANOUT_CAPS: KMTQUERYADAPTERINFOTYPE = 67;
pub const KMTQAITYPE_SERVICENAME: KMTQUERYADAPTERINFOTYPE = 69;
pub const KMTQAITYPE_SETWORKINGSETINFO: KMTQUERYADAPTERINFOTYPE = 7;
pub const KMTQAITYPE_TRACKEDWORKLOAD_SUPPORT: KMTQUERYADAPTERINFOTYPE = 72;
pub const KMTQAITYPE_UMDRIVERNAME: KMTQUERYADAPTERINFOTYPE = 1;
pub const KMTQAITYPE_UMDRIVERPRIVATE: KMTQUERYADAPTERINFOTYPE = 0;
pub const KMTQAITYPE_UMD_DRIVER_VERSION: KMTQUERYADAPTERINFOTYPE = 18;
pub const KMTQAITYPE_UMOPENGLINFO: KMTQUERYADAPTERINFOTYPE = 2;
pub const KMTQAITYPE_VGPUINTERFACEID: KMTQUERYADAPTERINFOTYPE = 79;
pub const KMTQAITYPE_VIRTUALADDRESSINFO: KMTQUERYADAPTERINFOTYPE = 12;
pub const KMTQAITYPE_WDDM_1_2_CAPS: KMTQUERYADAPTERINFOTYPE = 17;
pub const KMTQAITYPE_WDDM_1_2_CAPS_RENDER: KMTQUERYADAPTERINFOTYPE = 58;
pub const KMTQAITYPE_WDDM_1_3_CAPS: KMTQUERYADAPTERINFOTYPE = 22;
pub const KMTQAITYPE_WDDM_1_3_CAPS_RENDER: KMTQUERYADAPTERINFOTYPE = 59;
pub const KMTQAITYPE_WDDM_2_0_CAPS: KMTQUERYADAPTERINFOTYPE = 24;
pub const KMTQAITYPE_WDDM_2_7_CAPS: KMTQUERYADAPTERINFOTYPE = 70;
pub const KMTQAITYPE_WDDM_2_9_CAPS: KMTQUERYADAPTERINFOTYPE = 75;
pub const KMTQAITYPE_WDDM_3_0_CAPS: KMTQUERYADAPTERINFOTYPE = 77;
pub const KMTQAITYPE_WDDM_3_1_CAPS: KMTQUERYADAPTERINFOTYPE = 80;
pub const KMTQAITYPE_WSAUMDIMAGENAME: KMTQUERYADAPTERINFOTYPE = 78;
pub const KMTQAITYPE_XBOX: KMTQUERYADAPTERINFOTYPE = 27;
pub type KMTQUERYADAPTERINFOTYPE = i32;
pub const KMTQUITYPE_GPUVERSION: KMTQUERYADAPTERINFOTYPE = 64;
pub const LIST_MODULES_ALL: i32 = 3;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LUID {
    pub LowPart: u32,
    pub HighPart: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LUID_AND_ATTRIBUTES {
    pub Luid: LUID,
    pub Attributes: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MEMORYSTATUSEX {
    pub dwLength: u32,
    pub dwMemoryLoad: u32,
    pub ullTotalPhys: DWORDLONG,
    pub ullAvailPhys: DWORDLONG,
    pub ullTotalPageFile: DWORDLONG,
    pub ullAvailPageFile: DWORDLONG,
    pub ullTotalVirtual: DWORDLONG,
    pub ullAvailVirtual: DWORDLONG,
    pub ullAvailExtendedVirtual: DWORDLONG,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MIB_IF_ROW2 {
    pub InterfaceLuid: NET_LUID,
    pub InterfaceIndex: NET_IFINDEX,
    pub InterfaceGuid: windows_core::GUID,
    pub Alias: [u16; 257],
    pub Description: [u16; 257],
    pub PhysicalAddressLength: u32,
    pub PhysicalAddress: [u8; 32],
    pub PermanentPhysicalAddress: [u8; 32],
    pub Mtu: u32,
    pub Type: IFTYPE,
    pub TunnelType: TUNNEL_TYPE,
    pub MediaType: NDIS_MEDIUM,
    pub PhysicalMediumType: NDIS_PHYSICAL_MEDIUM,
    pub AccessType: NET_IF_ACCESS_TYPE,
    pub DirectionType: NET_IF_DIRECTION_TYPE,
    pub InterfaceAndOperStatusFlags: MIB_IF_ROW2_0,
    pub OperStatus: IF_OPER_STATUS,
    pub AdminStatus: NET_IF_ADMIN_STATUS,
    pub MediaConnectState: NET_IF_MEDIA_CONNECT_STATE,
    pub NetworkGuid: NET_IF_NETWORK_GUID,
    pub ConnectionType: NET_IF_CONNECTION_TYPE,
    pub TransmitLinkSpeed: u64,
    pub ReceiveLinkSpeed: u64,
    pub InOctets: u64,
    pub InUcastPkts: u64,
    pub InNUcastPkts: u64,
    pub InDiscards: u64,
    pub InErrors: u64,
    pub InUnknownProtos: u64,
    pub InUcastOctets: u64,
    pub InMulticastOctets: u64,
    pub InBroadcastOctets: u64,
    pub OutOctets: u64,
    pub OutUcastPkts: u64,
    pub OutNUcastPkts: u64,
    pub OutDiscards: u64,
    pub OutErrors: u64,
    pub OutUcastOctets: u64,
    pub OutMulticastOctets: u64,
    pub OutBroadcastOctets: u64,
    pub OutQLen: u64,
}
impl Default for MIB_IF_ROW2 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MIB_IF_ROW2_0 {
    pub _bitfield: bool,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MIB_IF_TABLE2 {
    pub NumEntries: u32,
    pub Table: [MIB_IF_ROW2; 1],
}
impl Default for MIB_IF_TABLE2 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub type MIB_IF_TABLE_LEVEL = i32;
pub const MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG: i32 = 131072;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MS_ADDINFO_BLOB {
    pub cbStruct: u32,
    pub cbMemObject: u32,
    pub pbMemObject: *mut u8,
    pub cbMemSignedMsg: u32,
    pub pbMemSignedMsg: *mut u8,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MS_ADDINFO_CATALOGMEMBER {
    pub cbStruct: u32,
    pub pStore: *mut CRYPTCATSTORE,
    pub pMember: *mut CRYPTCATMEMBER,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MS_ADDINFO_DETACHEDSIG {
    pub cbStruct: u32,
    pub hSignatureFile: HANDLE,
    pub cbSignatureObject: u32,
    pub pbSignatureObject: *mut u8,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MS_ADDINFO_FLAT {
    pub cbStruct: u32,
    pub pIndirectData: *mut SIP_INDIRECT_DATA,
}
pub const MaxProcessInfoClass: PROCESSINFOCLASS = 118;
pub const MibIfTableNormalWithoutStatistics: MIB_IF_TABLE_LEVEL = 2;
pub type NDIS_MEDIUM = i32;
pub type NDIS_PHYSICAL_MEDIUM = i32;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NET_IFINDEX(pub u32);
pub type NET_IF_ACCESS_TYPE = i32;
pub type NET_IF_ADMIN_STATUS = i32;
pub type NET_IF_CONNECTION_TYPE = i32;
pub type NET_IF_DIRECTION_TYPE = i32;
pub type NET_IF_MEDIA_CONNECT_STATE = i32;
pub type NET_IF_NETWORK_GUID = windows_core::GUID;
pub type NET_LUID = NET_LUID_LH;
#[repr(C)]
#[derive(Clone, Copy)]
pub union NET_LUID_LH {
    pub Value: u64,
    pub Info: NET_LUID_LH_0,
}
impl Default for NET_LUID_LH {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NET_LUID_LH_0 {
    pub _bitfield: u64,
}
impl NET_LUID_LH_0 {
    pub fn Reserved(&self) -> u64 {
        (self._bitfield << 40) >> 40
    }
    pub fn set_Reserved(&mut self, value: u64) {
        self._bitfield = (self._bitfield & !16777215) | (value & 16777215);
    }
    pub fn NetLuidIndex(&self) -> u64 {
        (self._bitfield << 16) >> 40
    }
    pub fn set_NetLuidIndex(&mut self, value: u64) {
        self._bitfield = (self._bitfield & !(16777215 << 24)) | ((value & 16777215) << 24);
    }
    pub fn IfType(&self) -> u64 {
        self._bitfield >> 48
    }
    pub fn set_IfType(&mut self, value: u64) {
        self._bitfield = (self._bitfield & !(65535 << 48)) | ((value & 65535) << 48);
    }
}
pub type OBJECT_INFORMATION_CLASS = i32;
pub const OPEN_EXISTING: i32 = 3;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OVERLAPPED {
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Anonymous: OVERLAPPED_0,
    pub hEvent: HANDLE,
}
impl Default for OVERLAPPED {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union OVERLAPPED_0 {
    pub Anonymous: OVERLAPPED_0_0,
    pub Pointer: *mut core::ffi::c_void,
}
impl Default for OVERLAPPED_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OVERLAPPED_0_0 {
    pub Offset: u32,
    pub OffsetHigh: u32,
}
pub const OWNER_SECURITY_INFORMATION: i32 = 1;
pub const ObjectBasicInformation: OBJECT_INFORMATION_CLASS = 0;
pub const ObjectTypeInformation: OBJECT_INFORMATION_CLASS = 2;
#[repr(C)]
#[cfg(target_arch = "x86")]
#[derive(Clone, Copy)]
pub struct PACKAGE_ID {
    pub reserved: u32,
    pub processorArchitecture: u32,
    pub version: PACKAGE_VERSION,
    pub name: windows_core::PWSTR,
    pub publisher: windows_core::PWSTR,
    pub resourceId: windows_core::PWSTR,
    pub publisherId: windows_core::PWSTR,
}
#[cfg(target_arch = "x86")]
impl Default for PACKAGE_ID {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C, packed(4))]
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "x86_64"
))]
#[derive(Clone, Copy)]
pub struct PACKAGE_ID {
    pub reserved: u32,
    pub processorArchitecture: u32,
    pub version: PACKAGE_VERSION,
    pub name: windows_core::PWSTR,
    pub publisher: windows_core::PWSTR,
    pub resourceId: windows_core::PWSTR,
    pub publisherId: windows_core::PWSTR,
}
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "x86_64"
))]
impl Default for PACKAGE_ID {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const PACKAGE_INFORMATION_BASIC: i32 = 0;
pub const PACKAGE_INFORMATION_FULL: i32 = 256;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PACKAGE_VERSION {
    pub Anonymous: PACKAGE_VERSION_0,
}
impl Default for PACKAGE_VERSION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
pub union PACKAGE_VERSION_0 {
    pub Version: u64,
    pub Anonymous: PACKAGE_VERSION_0_0,
}
impl Default for PACKAGE_VERSION_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PACKAGE_VERSION_0_0 {
    pub Revision: u16,
    pub Build: u16,
    pub Minor: u16,
    pub Major: u16,
}
pub type PACL = *mut ACL;
pub const PAGE_READWRITE: i32 = 4;
pub type PCCERT_CHAIN_CONTEXT = *const CERT_CHAIN_CONTEXT;
pub type PCCERT_CONTEXT = *const CERT_CONTEXT;
pub type PCCRL_CONTEXT = *const CRL_CONTEXT;
pub type PCCTL_CONTEXT = *const CTL_CONTEXT;
pub type PCERT_CHAIN_ELEMENT = *mut CERT_CHAIN_ELEMENT;
pub type PCERT_ENHKEY_USAGE = *mut CTL_USAGE;
pub type PCERT_EXTENSION = *mut CERT_EXTENSION;
pub type PCERT_INFO = *mut CERT_INFO;
pub type PCERT_REVOCATION_CRL_INFO = *mut CERT_REVOCATION_CRL_INFO;
pub type PCERT_REVOCATION_INFO = *mut CERT_REVOCATION_INFO;
pub type PCERT_SIMPLE_CHAIN = *mut CERT_SIMPLE_CHAIN;
pub type PCERT_STRONG_SIGN_PARA = *mut CERT_STRONG_SIGN_PARA;
pub type PCERT_STRONG_SIGN_SERIALIZED_INFO = *mut CERT_STRONG_SIGN_SERIALIZED_INFO;
pub type PCERT_TRUST_LIST_INFO = *mut CERT_TRUST_LIST_INFO;
pub type PCERT_USAGE_MATCH = *mut CERT_USAGE_MATCH;
pub type PCRL_ENTRY = *mut CRL_ENTRY;
pub type PCRL_INFO = *mut CRL_INFO;
pub type PCRYPT_ATTRIBUTE = *mut CRYPT_ATTRIBUTE;
pub type PCRYPT_ATTR_BLOB = *mut CRYPT_INTEGER_BLOB;
pub type PCTL_ENTRY = *mut CTL_ENTRY;
pub type PCTL_INFO = *mut CTL_INFO;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PDH_FMT_COUNTERVALUE {
    pub CStatus: u32,
    pub Anonymous: PDH_FMT_COUNTERVALUE_0,
}
impl Default for PDH_FMT_COUNTERVALUE {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union PDH_FMT_COUNTERVALUE_0 {
    pub longValue: i32,
    pub doubleValue: f64,
    pub largeValue: i64,
    pub AnsiStringValue: windows_core::PCSTR,
    pub WideStringValue: windows_core::PCWSTR,
}
impl Default for PDH_FMT_COUNTERVALUE_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const PDH_FMT_DOUBLE: u32 = 512;
pub type PDH_HCOUNTER = HANDLE;
pub type PDH_HQUERY = HANDLE;
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PDH_STATUS(pub i32);
pub type PFN_CPD_ADD_CERT = Option<
    unsafe extern "system" fn(
        pprovdata: *const CRYPT_PROVIDER_DATA,
        idxsigner: u32,
        fcountersigner: windows_core::BOOL,
        idxcountersigner: u32,
        pcert2add: *const CERT_CONTEXT,
    ) -> windows_core::BOOL,
>;
pub type PFN_CPD_ADD_PRIVDATA = Option<
    unsafe extern "system" fn(
        pprovdata: *const CRYPT_PROVIDER_DATA,
        pprivdata2add: *const CRYPT_PROVIDER_PRIVDATA,
    ) -> windows_core::BOOL,
>;
pub type PFN_CPD_ADD_SGNR = Option<
    unsafe extern "system" fn(
        pprovdata: *const CRYPT_PROVIDER_DATA,
        fcountersigner: windows_core::BOOL,
        idxsigner: u32,
        psgnr2add: *const CRYPT_PROVIDER_SGNR,
    ) -> windows_core::BOOL,
>;
pub type PFN_CPD_ADD_STORE = Option<
    unsafe extern "system" fn(
        pprovdata: *const CRYPT_PROVIDER_DATA,
        hstore2add: HCERTSTORE,
    ) -> windows_core::BOOL,
>;
pub type PFN_CPD_MEM_ALLOC =
    Option<unsafe extern "system" fn(cbsize: u32) -> *mut core::ffi::c_void>;
pub type PFN_CPD_MEM_FREE = Option<unsafe extern "system" fn(pvmem2free: *const core::ffi::c_void)>;
pub type PFN_PROVIDER_CERTCHKPOLICY_CALL = Option<
    unsafe extern "system" fn(
        pprovdata: *const CRYPT_PROVIDER_DATA,
        idxsigner: u32,
        fcountersignerchain: windows_core::BOOL,
        idxcountersigner: u32,
    ) -> windows_core::BOOL,
>;
pub type PFN_PROVIDER_CERTTRUST_CALL =
    Option<unsafe extern "system" fn(pprovdata: *mut CRYPT_PROVIDER_DATA) -> windows_core::HRESULT>;
pub type PFN_PROVIDER_CLEANUP_CALL =
    Option<unsafe extern "system" fn(pprovdata: *mut CRYPT_PROVIDER_DATA) -> windows_core::HRESULT>;
pub type PFN_PROVIDER_FINALPOLICY_CALL =
    Option<unsafe extern "system" fn(pprovdata: *mut CRYPT_PROVIDER_DATA) -> windows_core::HRESULT>;
pub type PFN_PROVIDER_INIT_CALL =
    Option<unsafe extern "system" fn(pprovdata: *mut CRYPT_PROVIDER_DATA) -> windows_core::HRESULT>;
pub type PFN_PROVIDER_OBJTRUST_CALL =
    Option<unsafe extern "system" fn(pprovdata: *mut CRYPT_PROVIDER_DATA) -> windows_core::HRESULT>;
pub type PFN_PROVIDER_SIGTRUST_CALL =
    Option<unsafe extern "system" fn(pprovdata: *mut CRYPT_PROVIDER_DATA) -> windows_core::HRESULT>;
pub type PFN_PROVIDER_TESTFINALPOLICY_CALL =
    Option<unsafe extern "system" fn(pprovdata: *mut CRYPT_PROVIDER_DATA) -> windows_core::HRESULT>;
pub type PFN_PROVUI_CALL = Option<
    unsafe extern "system" fn(
        hwndsecuritydialog: HWND,
        pprovdata: *const CRYPT_PROVIDER_DATA,
    ) -> windows_core::BOOL,
>;
pub type PMIB_IF_TABLE2 = *mut MIB_IF_TABLE2;
pub type POWER_INFORMATION_LEVEL = i32;
pub type PROCESSINFOCLASS = i32;
pub const PROCESS_DUP_HANDLE: i32 = 64;
pub type PROCESS_INFORMATION_CLASS = i32;
pub type PROCESS_MITIGATION_POLICY = i32;
pub const PROCESS_QUERY_INFORMATION: i32 = 1024;
pub const PROCESS_QUERY_LIMITED_INFORMATION: i32 = 4096;
pub const PROCESS_VM_READ: i32 = 16;
pub const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 2147483648;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PROVDATA_SIP {
    pub cbStruct: u32,
    pub gSubject: windows_core::GUID,
    pub pSip: *mut SIP_DISPATCH_INFO,
    pub pCATSip: *mut SIP_DISPATCH_INFO,
    pub psSipSubjectInfo: *mut SIP_SUBJECTINFO,
    pub psSipCATSubjectInfo: *mut SIP_SUBJECTINFO,
    pub psIndirectData: *mut SIP_INDIRECT_DATA,
}
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PSECURITY_DESCRIPTOR(pub *mut core::ffi::c_void);
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PSID(pub *mut core::ffi::c_void);
pub type PackageOrigin = i32;
pub const PackageOrigin_DeveloperSigned: PackageOrigin = 5;
pub const PackageOrigin_DeveloperUnsigned: PackageOrigin = 4;
pub const PackageOrigin_Inbox: PackageOrigin = 2;
pub const PackageOrigin_LineOfBusiness: PackageOrigin = 6;
pub const PackageOrigin_SignedSBOM: PackageOrigin = 7;
pub const PackageOrigin_Store: PackageOrigin = 3;
pub const PackageOrigin_Unknown: PackageOrigin = 0;
pub const PackageOrigin_Unsigned: PackageOrigin = 1;
pub const ProcessAccessToken: PROCESSINFOCLASS = 9;
pub const ProcessAffinityMask: PROCESSINFOCLASS = 21;
pub const ProcessAffinityUpdateMode: PROCESSINFOCLASS = 45;
pub const ProcessBasePriority: PROCESSINFOCLASS = 5;
pub const ProcessBasicInformation: PROCESSINFOCLASS = 0;
pub const ProcessBreakOnTermination: PROCESSINFOCLASS = 29;
pub const ProcessCheckStackExtentsMode: PROCESSINFOCLASS = 59;
pub const ProcessCommandLineInformation: PROCESSINFOCLASS = 60;
pub const ProcessCommitReleaseInformation: PROCESSINFOCLASS = 65;
pub const ProcessControlFlowGuardPolicy: PROCESS_MITIGATION_POLICY = 7;
pub const ProcessCookie: PROCESSINFOCLASS = 36;
pub const ProcessCycleTime: PROCESSINFOCLASS = 38;
pub const ProcessDEPPolicy: PROCESS_MITIGATION_POLICY = 0;
pub const ProcessDebugFlags: PROCESSINFOCLASS = 31;
pub const ProcessDebugObjectHandle: PROCESSINFOCLASS = 30;
pub const ProcessDebugPort: PROCESSINFOCLASS = 7;
pub const ProcessDefaultHardErrorMode: PROCESSINFOCLASS = 12;
pub const ProcessDeviceMap: PROCESSINFOCLASS = 23;
pub const ProcessDynamicFunctionTableInformation: PROCESSINFOCLASS = 53;
pub const ProcessEnableAlignmentFaultFixup: PROCESSINFOCLASS = 17;
pub const ProcessEnergyTrackingState: PROCESSINFOCLASS = 82;
pub const ProcessExceptionPort: PROCESSINFOCLASS = 8;
pub const ProcessExecuteFlags: PROCESSINFOCLASS = 34;
pub const ProcessFaultInformation: PROCESSINFOCLASS = 63;
pub const ProcessForegroundInformation: PROCESSINFOCLASS = 25;
pub const ProcessGroupInformation: PROCESSINFOCLASS = 47;
pub const ProcessHandleCheckingMode: PROCESSINFOCLASS = 54;
pub const ProcessHandleCount: PROCESSINFOCLASS = 20;
pub const ProcessHandleInformation: PROCESSINFOCLASS = 51;
pub const ProcessHandleTable: PROCESSINFOCLASS = 58;
pub const ProcessHandleTracing: PROCESSINFOCLASS = 32;
pub const ProcessImageFileMapping: PROCESSINFOCLASS = 44;
pub const ProcessImageFileName: PROCESSINFOCLASS = 27;
pub const ProcessImageFileNameWin32: PROCESSINFOCLASS = 43;
pub const ProcessImageInformation: PROCESSINFOCLASS = 37;
pub const ProcessInPrivate: PROCESSINFOCLASS = 70;
pub const ProcessInstrumentationCallback: PROCESSINFOCLASS = 40;
pub const ProcessIoCounters: PROCESSINFOCLASS = 2;
pub const ProcessIoPortHandlers: PROCESSINFOCLASS = 13;
pub const ProcessIoPriority: PROCESSINFOCLASS = 33;
pub const ProcessKeepAliveCount: PROCESSINFOCLASS = 55;
pub const ProcessLUIDDeviceMapsEnabled: PROCESSINFOCLASS = 28;
pub const ProcessLdtInformation: PROCESSINFOCLASS = 10;
pub const ProcessLdtSize: PROCESSINFOCLASS = 11;
pub const ProcessMachineTypeInfo: PROCESS_INFORMATION_CLASS = 9;
pub const ProcessMemoryAllocationMode: PROCESSINFOCLASS = 46;
pub const ProcessMemoryExhaustion: PROCESSINFOCLASS = 62;
pub const ProcessMitigationPolicy: PROCESSINFOCLASS = 52;
pub const ProcessNetworkIoCounters: PROCESSINFOCLASS = 114;
pub const ProcessOwnerInformation: PROCESSINFOCLASS = 49;
pub const ProcessPagePriority: PROCESSINFOCLASS = 39;
pub const ProcessPooledUsageAndLimits: PROCESSINFOCLASS = 14;
pub const ProcessPriorityBoost: PROCESSINFOCLASS = 22;
pub const ProcessPriorityClass: PROCESSINFOCLASS = 18;
pub const ProcessProtectionInformation: PROCESSINFOCLASS = 61;
pub const ProcessQuotaLimits: PROCESSINFOCLASS = 1;
pub const ProcessRaisePriority: PROCESSINFOCLASS = 6;
pub const ProcessRaiseUMExceptionOnInvalidHandleClose: PROCESSINFOCLASS = 71;
pub const ProcessReserved1Information: PROCESSINFOCLASS = 66;
pub const ProcessReserved2Information: PROCESSINFOCLASS = 67;
pub const ProcessRevokeFileHandles: PROCESSINFOCLASS = 56;
pub const ProcessSessionInformation: PROCESSINFOCLASS = 24;
pub const ProcessSubsystemInformation: PROCESSINFOCLASS = 75;
pub const ProcessSubsystemProcess: PROCESSINFOCLASS = 68;
pub const ProcessTelemetryIdInformation: PROCESSINFOCLASS = 64;
pub const ProcessThreadStackAllocation: PROCESSINFOCLASS = 41;
pub const ProcessTimes: PROCESSINFOCLASS = 4;
pub const ProcessTlsInformation: PROCESSINFOCLASS = 35;
pub const ProcessTokenVirtualizationEnabled: PROCESSINFOCLASS = 48;
pub const ProcessUserModeIOPL: PROCESSINFOCLASS = 16;
pub const ProcessUserShadowStackPolicy: PROCESS_MITIGATION_POLICY = 15;
pub const ProcessVmCounters: PROCESSINFOCLASS = 3;
pub const ProcessWin32kSyscallFilterInformation: PROCESSINFOCLASS = 79;
pub const ProcessWindowInformation: PROCESSINFOCLASS = 50;
pub const ProcessWorkingSetControl: PROCESSINFOCLASS = 57;
pub const ProcessWorkingSetWatch: PROCESSINFOCLASS = 15;
pub const ProcessWorkingSetWatchEx: PROCESSINFOCLASS = 42;
pub const ProcessWow64Information: PROCESSINFOCLASS = 26;
pub const ProcessWx86Information: PROCESSINFOCLASS = 19;
pub const ProcessorInformation: POWER_INFORMATION_LEVEL = 11;
pub const SDDL_REVISION_1: i32 = 1;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SEALING_SIGNATURE_ATTRIBUTE {
    pub version: u32,
    pub signerIndex: u32,
    pub signatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub encryptedDigest: CRYPT_DIGEST_BLOB,
}
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
pub const SE_FILE_OBJECT: SE_OBJECT_TYPE = 1;
pub type SE_OBJECT_TYPE = i32;
pub const SE_PRIVILEGE_ENABLED: i32 = 2;
#[repr(C, packed(1))]
#[cfg(target_arch = "x86")]
#[derive(Clone, Copy)]
pub struct SHFILEINFOW {
    pub hIcon: HICON,
    pub iIcon: i32,
    pub dwAttributes: u32,
    pub szDisplayName: [u16; 260],
    pub szTypeName: [u16; 80],
}
#[cfg(target_arch = "x86")]
impl Default for SHFILEINFOW {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "x86_64"
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SHFILEINFOW {
    pub hIcon: HICON,
    pub iIcon: i32,
    pub dwAttributes: u32,
    pub szDisplayName: [u16; 260],
    pub szTypeName: [u16; 80],
}
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm64ec",
    target_arch = "x86_64"
))]
impl Default for SHFILEINFOW {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const SHGFI_DISPLAYNAME: i32 = 512;
pub const SHGFI_USEFILEATTRIBUTES: i32 = 16;
pub type SID_NAME_USE = i32;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SIP_DISPATCH_INFO {
    pub cbSize: u32,
    pub hSIP: HANDLE,
    pub pfGet: pCryptSIPGetSignedDataMsg,
    pub pfPut: pCryptSIPPutSignedDataMsg,
    pub pfCreate: pCryptSIPCreateIndirectData,
    pub pfVerify: pCryptSIPVerifyIndirectData,
    pub pfRemove: pCryptSIPRemoveSignedDataMsg,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SIP_INDIRECT_DATA {
    pub Data: CRYPT_ATTRIBUTE_TYPE_VALUE,
    pub DigestAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub Digest: CRYPT_HASH_BLOB,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SIP_SUBJECTINFO {
    pub cbSize: u32,
    pub pgSubjectType: *mut windows_core::GUID,
    pub hFile: HANDLE,
    pub pwsFileName: windows_core::PCWSTR,
    pub pwsDisplayName: windows_core::PCWSTR,
    pub dwReserved1: u32,
    pub dwIntVersion: u32,
    pub hProv: HCRYPTPROV,
    pub DigestAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub dwFlags: u32,
    pub dwEncodingType: u32,
    pub dwReserved2: u32,
    pub fdwCAPISettings: u32,
    pub fdwSecuritySettings: u32,
    pub dwIndex: u32,
    pub dwUnionChoice: u32,
    pub Anonymous: SIP_SUBJECTINFO_0,
    pub pClientData: *mut core::ffi::c_void,
}
impl Default for SIP_SUBJECTINFO {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union SIP_SUBJECTINFO_0 {
    pub psFlat: *mut MS_ADDINFO_FLAT,
    pub psCatMember: *mut MS_ADDINFO_CATALOGMEMBER,
    pub psBlob: *mut MS_ADDINFO_BLOB,
    pub psDetachedSig: *mut MS_ADDINFO_DETACHEDSIG,
}
impl Default for SIP_SUBJECTINFO_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const STATUS_SUCCESS: windows_core::NTSTATUS = windows_core::NTSTATUS(0x0_u32 as _);
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SYSTEM_INFO {
    pub Anonymous: SYSTEM_INFO_0,
    pub dwPageSize: u32,
    pub lpMinimumApplicationAddress: *mut core::ffi::c_void,
    pub lpMaximumApplicationAddress: *mut core::ffi::c_void,
    pub dwActiveProcessorMask: usize,
    pub dwNumberOfProcessors: u32,
    pub dwProcessorType: u32,
    pub dwAllocationGranularity: u32,
    pub wProcessorLevel: u16,
    pub wProcessorRevision: u16,
}
impl Default for SYSTEM_INFO {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union SYSTEM_INFO_0 {
    pub dwOemId: u32,
    pub Anonymous: SYSTEM_INFO_0_0,
}
impl Default for SYSTEM_INFO_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SYSTEM_INFO_0_0 {
    pub wProcessorArchitecture: u16,
    pub wReserved: u16,
}
pub const TOKEN_ADJUST_PRIVILEGES: i32 = 32;
pub type TOKEN_INFORMATION_CLASS = i32;
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TOKEN_PRIVILEGES {
    pub PrivilegeCount: u32,
    pub Privileges: [LUID_AND_ATTRIBUTES; 1],
}
impl Default for TOKEN_PRIVILEGES {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
pub const TOKEN_QUERY: i32 = 8;
pub const TRACE_LEVEL_INFORMATION: i32 = 4;
pub const TRUST_E_NOSIGNATURE: windows_core::HRESULT = windows_core::HRESULT(0x800B0100_u32 as _);
pub const TRUST_E_SUBJECT_FORM_UNKNOWN: windows_core::HRESULT =
    windows_core::HRESULT(0x800B0003_u32 as _);
pub type TUNNEL_TYPE = i32;
pub const TokenElevation: TOKEN_INFORMATION_CLASS = 20;
pub const TokenUser: TOKEN_INFORMATION_CLASS = 1;
pub type WELL_KNOWN_SID_TYPE = i32;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WINTRUST_BLOB_INFO {
    pub cbStruct: u32,
    pub gSubject: windows_core::GUID,
    pub pcwszDisplayName: windows_core::PCWSTR,
    pub cbMemObject: u32,
    pub pbMemObject: *mut u8,
    pub cbMemSignedMsg: u32,
    pub pbMemSignedMsg: *mut u8,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WINTRUST_CATALOG_INFO {
    pub cbStruct: u32,
    pub dwCatalogVersion: u32,
    pub pcwszCatalogFilePath: windows_core::PCWSTR,
    pub pcwszMemberTag: windows_core::PCWSTR,
    pub pcwszMemberFilePath: windows_core::PCWSTR,
    pub hMemberFile: HANDLE,
    pub pbCalculatedFileHash: *mut u8,
    pub cbCalculatedFileHash: u32,
    pub pcCatalogContext: PCCTL_CONTEXT,
    pub hCatAdmin: HCATADMIN,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WINTRUST_CERT_INFO {
    pub cbStruct: u32,
    pub pcwszDisplayName: windows_core::PCWSTR,
    pub psCertContext: *mut CERT_CONTEXT,
    pub chStores: u32,
    pub pahStores: *mut HCERTSTORE,
    pub dwFlags: u32,
    pub psftVerifyAsOf: *mut FILETIME,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WINTRUST_DATA {
    pub cbStruct: u32,
    pub pPolicyCallbackData: *mut core::ffi::c_void,
    pub pSIPClientData: *mut core::ffi::c_void,
    pub dwUIChoice: u32,
    pub fdwRevocationChecks: u32,
    pub dwUnionChoice: u32,
    pub Anonymous: WINTRUST_DATA_0,
    pub dwStateAction: u32,
    pub hWVTStateData: HANDLE,
    pub pwszURLReference: *mut u16,
    pub dwProvFlags: u32,
    pub dwUIContext: u32,
    pub pSignatureSettings: *mut WINTRUST_SIGNATURE_SETTINGS,
}
impl Default for WINTRUST_DATA {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union WINTRUST_DATA_0 {
    pub pFile: *mut WINTRUST_FILE_INFO,
    pub pCatalog: *mut WINTRUST_CATALOG_INFO,
    pub pBlob: *mut WINTRUST_BLOB_INFO,
    pub pSgnr: *mut WINTRUST_SGNR_INFO,
    pub pCert: *mut WINTRUST_CERT_INFO,
    pub pDetachedSig: *mut WINTRUST_DETACHED_SIG_INFO,
}
impl Default for WINTRUST_DATA_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WINTRUST_DETACHED_SIG_BLOBS {
    pub cbContentObject: i64,
    pub pbContentObject: *mut u8,
    pub cbSignatureObject: u32,
    pub pbSignatureObject: *mut u8,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WINTRUST_DETACHED_SIG_FILE_HANDLES {
    pub hContentFile: HANDLE,
    pub hSignatureFile: HANDLE,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WINTRUST_DETACHED_SIG_INFO {
    pub cbStruct: u32,
    pub dwUnionChoice: u32,
    pub Anonymous: WINTRUST_DETACHED_SIG_INFO_0,
}
impl Default for WINTRUST_DETACHED_SIG_INFO {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union WINTRUST_DETACHED_SIG_INFO_0 {
    pub pDetachedSigHandles: *mut WINTRUST_DETACHED_SIG_FILE_HANDLES,
    pub pDetachedSigBlobs: *mut WINTRUST_DETACHED_SIG_BLOBS,
}
impl Default for WINTRUST_DETACHED_SIG_INFO_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WINTRUST_FILE_INFO {
    pub cbStruct: u32,
    pub pcwszFilePath: windows_core::PCWSTR,
    pub hFile: HANDLE,
    pub pgKnownSubject: *mut windows_core::GUID,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WINTRUST_SGNR_INFO {
    pub cbStruct: u32,
    pub pcwszDisplayName: windows_core::PCWSTR,
    pub psSignerInfo: *mut CMSG_SIGNER_INFO,
    pub chStores: u32,
    pub pahStores: *mut HCERTSTORE,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WINTRUST_SIGNATURE_SETTINGS {
    pub cbStruct: u32,
    pub dwIndex: u32,
    pub dwFlags: u32,
    pub cSecondarySigs: u32,
    pub dwVerifiedSigIndex: u32,
    pub pCryptoPolicy: PCERT_STRONG_SIGN_PARA,
}
pub const WTD_CACHE_ONLY_URL_RETRIEVAL: i32 = 4096;
pub const WTD_CHOICE_CATALOG: i32 = 2;
pub const WTD_CHOICE_FILE: i32 = 1;
pub const WTD_REVOKE_NONE: i32 = 0;
pub const WTD_SAFER_FLAG: i32 = 256;
pub const WTD_STATEACTION_CLOSE: i32 = 2;
pub const WTD_STATEACTION_VERIFY: i32 = 1;
pub const WTD_UI_NONE: i32 = 2;
pub const WinBuiltinAdministratorsSid: WELL_KNOWN_SID_TYPE = 26;
pub const WinLocalSystemSid: WELL_KNOWN_SID_TYPE = 22;
pub type pCryptSIPCreateIndirectData = Option<
    unsafe extern "system" fn(
        psubjectinfo: *mut SIP_SUBJECTINFO,
        pcbindirectdata: *mut u32,
        pindirectdata: *mut SIP_INDIRECT_DATA,
    ) -> windows_core::BOOL,
>;
pub type pCryptSIPGetSignedDataMsg = Option<
    unsafe extern "system" fn(
        psubjectinfo: *mut SIP_SUBJECTINFO,
        pdwencodingtype: *mut u32,
        dwindex: u32,
        pcbsigneddatamsg: *mut u32,
        pbsigneddatamsg: *mut u8,
    ) -> windows_core::BOOL,
>;
pub type pCryptSIPPutSignedDataMsg = Option<
    unsafe extern "system" fn(
        psubjectinfo: *mut SIP_SUBJECTINFO,
        dwencodingtype: u32,
        pdwindex: *mut u32,
        cbsigneddatamsg: u32,
        pbsigneddatamsg: *mut u8,
    ) -> windows_core::BOOL,
>;
pub type pCryptSIPRemoveSignedDataMsg = Option<
    unsafe extern "system" fn(
        psubjectinfo: *mut SIP_SUBJECTINFO,
        dwindex: u32,
    ) -> windows_core::BOOL,
>;
pub type pCryptSIPVerifyIndirectData = Option<
    unsafe extern "system" fn(
        psubjectinfo: *mut SIP_SUBJECTINFO,
        pindirectdata: *mut SIP_INDIRECT_DATA,
    ) -> windows_core::BOOL,
>;
