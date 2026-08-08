use ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS;
use ntapi::winapi::um::winbase::LocalFree;
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, HWND, LPARAM, TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_SAFER_FLAG, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE, WINTRUST_CATALOG_INFO, WTD_CHOICE_CATALOG, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Services::{
    ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, SC_ENUM_PROCESS_INFO, SERVICE_STATE_ALL,
    SERVICE_WIN32,
};
use windows::Win32::System::Threading::{
    OpenProcess, PEB, PROCESS_BASIC_INFORMATION, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, QueryFullProcessImageNameW,
};
use windows::Win32::Storage::Packaging::Appx::{GetApplicationUserModelId, GetPackageFullName};
use windows::Win32::UI::Shell::CommandLineToArgvW;
use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsWindowVisible};

use crate::commands::services::ScHandle;
use crate::state::events::ProcessSignature;

pub unsafe fn query_command_line(pid: u32) -> Option<String> {
    let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

    let mut pbi = PROCESS_BASIC_INFORMATION::default();

    let status = NtQueryInformationProcess(
        handle,
        ProcessBasicInformation,
        &mut pbi as *mut _ as *mut _,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        std::ptr::null_mut(),
    );

    if status.is_err() {
        CloseHandle(handle).ok();
        return None;
    }

    let mut peb = std::mem::zeroed::<PEB>();
    let ok = ReadProcessMemory(
        handle,
        pbi.PebBaseAddress as *const _,
        &mut peb as *mut _ as *mut _,
        std::mem::size_of::<PEB>(),
        None,
    );
    if ok.is_err() {
        CloseHandle(handle).ok();
        return None;
    }

    let mut params = std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>();
    let ok = ReadProcessMemory(
        handle,
        peb.ProcessParameters as *const _,
        &mut params as *mut _ as *mut _,
        std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>(),
        None,
    );
    if ok.is_err() {
        CloseHandle(handle).ok();
        return None;
    }

    let len = params.CommandLine.Length as usize / 2;
    let result = WIDE_SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        scratch.clear();
        scratch.resize(len, 0);
        let ok = ReadProcessMemory(
            handle,
            params.CommandLine.Buffer as *const _,
            scratch.as_mut_ptr() as *mut _,
            params.CommandLine.Length as usize,
            None,
        );
        if ok.is_err() {
            return None;
        }
        Some(String::from_utf16_lossy(&scratch))
    });

    CloseHandle(handle).ok();
    result
}

pub unsafe fn parse_cmd_line(cmd_line: &str) -> Vec<String> {
    with_wide(cmd_line, |cmd_w| {
        let mut argc = 0i32;
        let argv_ptr = CommandLineToArgvW(cmd_w, &mut argc);

        if argv_ptr.is_null() {
            return vec![];
        }

        let mut args = Vec::new();
        for i in 0..argc {
            let arg_ptr = *argv_ptr.offset(i as isize);

            let arg_str = arg_ptr.to_string().unwrap_or_default();
            args.push(arg_str);
        }

        LocalFree(argv_ptr as _);
        args
    })
}


pub unsafe fn get_process_package_info(pid: u32) -> Option<(String, String)> {

    let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) else {
        return None;
    };

    let mut len = 0u32;
    let mut package_full_name = None;
    let mut package_relative_app_id = None;
    let _ = GetPackageFullName(handle, &mut len, None);
    if len > 0 {
        let mut buf = vec![0u16; len as usize];
        if GetPackageFullName(handle, &mut len, Option::from(PWSTR(buf.as_mut_ptr()))).is_ok() {

            package_full_name = Some(String::from_utf16_lossy(&buf[..len as usize - 1]));
        }
    }

    let mut len = 0u32;
    let _ = GetApplicationUserModelId(handle, &mut len, None);
    if len > 0 {
        let mut buf = vec![0u16; len as usize];
        if GetApplicationUserModelId(handle, &mut len, Option::from(PWSTR(buf.as_mut_ptr()))).is_ok() {
            let aumid = String::from_utf16_lossy(&buf[..len as usize - 1]);

            if let Some(pos) = aumid.find('!') {
                package_relative_app_id = Some(aumid[pos + 1..].to_string());
            }
        }
    }

    if let Some(package_relative_app_id) = package_relative_app_id && let Some(package_full_name) = package_full_name {
        Some((package_full_name, package_relative_app_id))
    }
    else {
        None
    }
}
pub unsafe fn query_image_path(pid: u32) -> Option<String> {
    let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
    let result = WIDE_SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        scratch.clear();
        scratch.resize(1024, 0);
        let mut len = scratch.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(scratch.as_mut_ptr()),
            &mut len,
        );
        ok.ok()?;
        Some(String::from_utf16_lossy(&scratch[..len as usize]))
    });
    let _ = CloseHandle(handle);
    result
}

thread_local! {
    static WIDE_SCRATCH: std::cell::RefCell<Vec<u16>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Encode `s` as a null-terminated wide string in a thread-local scratch
/// buffer and run `f` on it. Not reentrant: `f` must not call `with_wide`.
fn with_wide<R>(s: &str, f: impl FnOnce(PCWSTR) -> R) -> R {
    WIDE_SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        scratch.clear();
        scratch.extend(s.encode_utf16().chain(Some(0)));
        f(PCWSTR(scratch.as_ptr()))
    })
}


/// Looks the file up in the system's signature catalogs and verifies the
/// catalog that claims it.
///
/// `None` means no catalog vouches for the file, so the caller's "unsigned"
/// verdict stands; `Some` carries whatever the catalog's signer turned out
/// to be.
fn catalog_signature(path: &str) -> Option<ProcessSignature> {
    let file = open_for_read(path)?;
    let admin = CatalogAdmin::acquire()?;
    let mut hash = admin.file_hash(file.0)?;

    // A catalog names its members by the hash as uppercase hex, and
    // WinVerifyTrust matches on that name.
    let mut tag = String::with_capacity(hash.len() * 2);
    for byte in &hash {
        use std::fmt::Write as _;
        let _ = write!(tag, "{byte:02X}");
    }

    let catalog = admin.find_catalog(&hash)?;
    let info = catalog.info()?;

    let catalog_path: Vec<u16> = info
        .wszCatalogFile
        .iter()
        .take_while(|c| **c != 0)
        .copied()
        .chain(Some(0))
        .collect();
    let tag_w: Vec<u16> = tag.encode_utf16().chain(Some(0)).collect();
    let member_path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let mut catalog_info = WINTRUST_CATALOG_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: PCWSTR(catalog_path.as_ptr()),
            pcwszMemberTag: PCWSTR(tag_w.as_ptr()),
            pcwszMemberFilePath: PCWSTR(member_path.as_ptr()),
            hMemberFile: file.0,
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: hash.len() as u32,
            hCatAdmin: admin.0,
            ..Default::default()
        };

        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_CATALOG,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        data.Anonymous.pCatalog = &mut catalog_info;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);

        let verdict = (status == 0).then(|| match signer_subject(data.hWVTStateData) {
            Some(subject) if subject.contains("Microsoft") => ProcessSignature::Microsoft,
            Some(_) => ProcessSignature::ThirdParty,
            None => ProcessSignature::Unknown,
        });

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);
        verdict
    }
}

/// A read handle, closed on drop.
struct OwnedFile(HANDLE);

impl Drop for OwnedFile {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn open_for_read(path: &str) -> Option<OwnedFile> {
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .ok()
        .map(OwnedFile)
    }
}

/// The catalog admin context, released on drop.
struct CatalogAdmin(isize);

impl Drop for CatalogAdmin {
    fn drop(&mut self) {
        unsafe {
            let _ = CryptCATAdminReleaseContext(self.0, 0);
        }
    }
}

impl CatalogAdmin {
    fn acquire() -> Option<Self> {
        let mut handle = 0isize;
        unsafe {
            CryptCATAdminAcquireContext2(&mut handle, None, windows::core::w!("SHA256"), None, None)
                .ok()?;
        }
        Some(Self(handle))
    }

    /// The file's hash, in whatever algorithm the context was acquired with.
    fn file_hash(&self, file: HANDLE) -> Option<Vec<u8>> {
        let mut len = 0u32;
        unsafe {
            // First call only sizes the buffer, and fails by design.
            let _ = CryptCATAdminCalcHashFromFileHandle2(self.0, file, &mut len, None, None);
            if len == 0 {
                return None;
            }
            let mut hash = vec![0u8; len as usize];
            CryptCATAdminCalcHashFromFileHandle2(self.0, file, &mut len, Some(hash.as_mut_ptr()), None)
                .ok()?;
            hash.truncate(len as usize);
            Some(hash)
        }
    }

    /// The first catalog listing this hash as a member, if any.
    fn find_catalog(&self, hash: &[u8]) -> Option<CatalogContext<'_>> {
        unsafe {
            let context = CryptCATAdminEnumCatalogFromHash(self.0, hash, None, None);
            (context != 0).then_some(CatalogContext {
                admin: self,
                context,
            })
        }
    }
}

struct CatalogContext<'a> {
    admin: &'a CatalogAdmin,
    context: isize,
}

impl Drop for CatalogContext<'_> {
    fn drop(&mut self) {
        unsafe {
            let _ = CryptCATAdminReleaseCatalogContext(self.admin.0, self.context, 0);
        }
    }
}

impl CatalogContext<'_> {
    fn info(&self) -> Option<CATALOG_INFO> {
        let mut info = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        unsafe { CryptCATCatalogInfoFromContext(self.context, &mut info, 0).ok()? };
        Some(info)
    }
}

pub fn check_signature(path: &str) -> ProcessSignature {
    with_wide(path, |path_w| unsafe {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path_w,
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        data.Anonymous.pFile = &mut file_info;

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);

        let result = if status == 0 {
            match signer_subject(data.hWVTStateData) {
                Some(subject) if subject.contains("Microsoft") => ProcessSignature::Microsoft,
                Some(_) => ProcessSignature::ThirdParty,
                None => ProcessSignature::Unknown,
            }
        } else if status == TRUST_E_NOSIGNATURE.0 || status == TRUST_E_SUBJECT_FORM_UNKNOWN.0 {
            // No *embedded* signature is not the same as unsigned: most of
            // Windows' own binaries (dwm.exe, winlogon.exe, wslservice.exe)
            // are signed by catalog instead, and treating them as unsigned
            // filed half the operating system under third-party software.
            catalog_signature(path).unwrap_or(ProcessSignature::Unsigned)
        } else {
            ProcessSignature::Unknown
        };

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);
        result
    })
}

unsafe fn signer_subject(state: HANDLE) -> Option<String> {
    unsafe {
        let prov_data = WTHelperProvDataFromStateData(state);
        if prov_data.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(prov_data, 0, false, 0);
        if signer.is_null() {
            return None;
        }
        let sgnr = &*signer;
        if sgnr.csCertChain == 0 || sgnr.pasCertChain.is_null() {
            return None;
        }
        let cert = (*sgnr.pasCertChain).pCert;
        if cert.is_null() {
            return None;
        }
        let len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
        if len <= 1 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
        Some(String::from_utf16_lossy(&buf[..len as usize - 1]))
    }
}

pub fn is_windows_process(is_kernel: bool, signature: ProcessSignature) -> bool {
    // Deliberately no path heuristics: third-party software (and malware)
    // can live under SystemRoot, so a path prefix proves nothing.
    is_kernel || signature == ProcessSignature::Microsoft
}

pub fn enum_service_pids(scm: ScHandle, buf: &mut Vec<u8>) -> Vec<u32> {
    unsafe {
        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume = 0u32;

        let _ = EnumServicesStatusExW(
            scm.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume),
            None,
        );

        if bytes_needed == 0 {
            return Vec::new();
        }

        // Caller-owned buffer: capacity stays at the high-water mark,
        // no per-call allocation.
        buf.clear();
        buf.resize(bytes_needed as usize, 0);
        resume = 0;
        if EnumServicesStatusExW(
            scm.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(buf.as_mut_slice()),
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume),
            None,
        )
        .is_err()
        {
            return Vec::new();
        }

        let entries = std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            services_returned as usize,
        );
        entries
            .iter()
            .map(|e| e.ServiceStatusProcess.dwProcessId)
            .filter(|&pid| pid != 0)
            .collect()
    }
}

pub fn enum_visible_window_pids() -> Vec<u32> {
    let mut pids = std::collections::HashSet::new();
    unsafe extern "system" fn enum_window_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        unsafe {
            let pids = &mut *(lparam.0 as *mut std::collections::HashSet<u32>);
            if IsWindowVisible(hwnd).as_bool() {
                let mut pid = 0u32;
                GetWindowThreadProcessId(hwnd, Some(&mut pid));
                if pid != 0 {
                    pids.insert(pid);
                }
            }
            BOOL(1)
        }
    }
    unsafe {
        let _ = EnumWindows(
            Some(enum_window_proc),
            LPARAM(&mut pids as *mut _ as isize),
        );
    }
    pids.into_iter().collect()
}

#[cfg(test)]
mod signature_tests {
    use super::{check_signature, ProcessSignature};

    /// dwm.exe is catalog-signed, not embedded-signed. Before catalog
    /// lookup existed this returned `Unsigned`, which filed the window
    /// manager - and most of the rest of Windows - under third-party
    /// software.
    #[test]
    fn catalog_signed_system_binaries_are_recognised_as_microsoft() {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
        for name in ["dwm.exe", "winlogon.exe", "svchost.exe"] {
            let path = format!(r"{system_root}\System32\{name}");
            if !std::path::Path::new(&path).exists() {
                continue;
            }
            assert_eq!(
                check_signature(&path),
                ProcessSignature::Microsoft,
                "{name} should verify through the system catalogs"
            );
        }
    }
}
