use ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS;
use windows::Win32::{
    CATALOG_INFO, LocalFree, CERT_NAME_SIMPLE_DISPLAY_TYPE, CloseHandle, CommandLineToArgvW, CreateFileW,
    CertGetNameStringW, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, FILE_SHARE_DELETE,
    FILE_SHARE_READ, GENERIC_READ, GetApplicationUserModelId, GetPackageFullName, HANDLE,
    HCATADMIN, HCATINFO, HWND, NtQueryInformationProcess, OPEN_EXISTING, PEB,
    PROCESS_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, PROCESSINFOCLASS, ProcessBasicInformation, QueryFullProcessImageNameW,
    ReadProcessMemory, TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, WINTRUST_CATALOG_INFO,
    WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_SAFER_FLAG, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::core::{PCWSTR, PWSTR};

use crate::state::events::ProcessSignature;
use crate::win::{PROCESS_NAME_WIN32, WINTRUST_ACTION_GENERIC_VERIFY_V2, open_process};

pub unsafe fn query_command_line(pid: u32) -> Option<String> {
    let handle = open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid).ok()?;

    let mut pbi = PROCESS_BASIC_INFORMATION::default();

    let status = NtQueryInformationProcess(
        handle,
        ProcessBasicInformation,
        &mut pbi as *mut _ as *mut _,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        None,
    );

    if status.is_err() {
        let _ = CloseHandle(handle);
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
    if !ok.as_bool() {
        let _ = CloseHandle(handle);
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
    if !ok.as_bool() {
        let _ = CloseHandle(handle);
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
        if !ok.as_bool() {
            return None;
        }
        Some(String::from_utf16_lossy(&scratch))
    });

    let _ = CloseHandle(handle);
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

        let _ = LocalFree(HANDLE(argv_ptr as _));
        args
    })
}


pub unsafe fn get_process_package_info(pid: u32) -> Option<(String, String)> {

    let Ok(handle) = open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid) else {
        return None;
    };

    let mut len = 0u32;
    let mut package_full_name = None;
    let mut package_relative_app_id = None;
    let _ = GetPackageFullName(handle, &mut len, None);
    if len > 0 {
        let mut buf = vec![0u16; len as usize];
        if GetPackageFullName(handle, &mut len, Option::from(PWSTR(buf.as_mut_ptr()))) == 0 {

            package_full_name = Some(String::from_utf16_lossy(&buf[..len as usize - 1]));
        }
    }

    let mut len = 0u32;
    let _ = GetApplicationUserModelId(handle, &mut len, None);
    if len > 0 {
        let mut buf = vec![0u16; len as usize];
        if GetApplicationUserModelId(handle, &mut len, Option::from(PWSTR(buf.as_mut_ptr()))) == 0 {
            let aumid = String::from_utf16_lossy(&buf[..len as usize - 1]);

            if let Some(pos) = aumid.find('!') {
                package_relative_app_id = Some(aumid[pos + 1..].to_string());
            }
        }
    }
    let _ = CloseHandle(handle);

    if let Some(package_relative_app_id) = package_relative_app_id && let Some(package_full_name) = package_full_name {
        Some((package_full_name, package_relative_app_id))
    }
    else {
        None
    }
}
pub unsafe fn query_image_path(pid: u32) -> Option<String> {
    let handle = open_process(PROCESS_QUERY_LIMITED_INFORMATION, pid).ok()?;
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
        ok.ok().ok()?;
        Some(String::from_utf16_lossy(&scratch[..len as usize]))
    });
    let _ = CloseHandle(handle);
    result
}

const PROCESS_CONSOLE_HOST_PROCESS: PROCESSINFOCLASS = 49;

/// Pid of the conhost serving `pid`'s console, or 0 when it has none.
pub unsafe fn query_console_host_pid(pid: u32) -> u32 {
    let Ok(handle) = open_process(PROCESS_QUERY_LIMITED_INFORMATION, pid) else {
        return 0;
    };
    let mut value = 0usize;
    let status = NtQueryInformationProcess(
        handle,
        PROCESS_CONSOLE_HOST_PROCESS,
        &mut value as *mut usize as *mut _,
        std::mem::size_of::<usize>() as u32,
        None,
    );
    let _ = CloseHandle(handle);
    if status.is_err() {
        return 0;
    }
    console_host_from(value)
}

fn console_host_from(value: usize) -> u32 {
    if value & 3 == 1 {
        (value & !3) as u32
    } else {
        0
    }
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
            dwUIChoice: WTD_UI_NONE as u32,
            fdwRevocationChecks: WTD_REVOKE_NONE as u32,
            dwUnionChoice: WTD_CHOICE_CATALOG as u32,
            dwStateAction: WTD_STATEACTION_VERIFY as u32,
            dwProvFlags: (WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL) as u32,
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

        data.dwStateAction = WTD_STATEACTION_CLOSE as u32;
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
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ,
            (FILE_SHARE_READ | FILE_SHARE_DELETE) as u32,
            None,
            OPEN_EXISTING as u32,
            0,
            None,
        )
    };
    (handle.0 as isize != -1).then_some(OwnedFile(handle))
}

/// The catalog admin context, released on drop.
struct CatalogAdmin(HCATADMIN);

impl Drop for CatalogAdmin {
    fn drop(&mut self) {
        unsafe {
            let _ = CryptCATAdminReleaseContext(self.0, 0);
        }
    }
}

impl CatalogAdmin {
    fn acquire() -> Option<Self> {
        let mut handle = HCATADMIN::default();
        unsafe {
            CryptCATAdminAcquireContext2(&mut handle, None, windows::core::w!("SHA256"), None, None)
                .ok()
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
                .ok()
                .ok()?;
            hash.truncate(len as usize);
            Some(hash)
        }
    }

    /// The first catalog listing this hash as a member, if any.
    fn find_catalog(&self, hash: &[u8]) -> Option<CatalogContext<'_>> {
        unsafe {
            let context = CryptCATAdminEnumCatalogFromHash(self.0, hash, None, None);
            (!context.0.is_null()).then_some(CatalogContext {
                admin: self,
                context,
            })
        }
    }
}

struct CatalogContext<'a> {
    admin: &'a CatalogAdmin,
    context: HCATINFO,
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
        unsafe { CryptCATCatalogInfoFromContext(self.context, &mut info, 0).ok().ok()? };
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
            dwUIChoice: WTD_UI_NONE as u32,
            fdwRevocationChecks: WTD_REVOKE_NONE as u32,
            dwUnionChoice: WTD_CHOICE_FILE as u32,
            dwStateAction: WTD_STATEACTION_VERIFY as u32,
            dwProvFlags: (WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL) as u32,
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

        data.dwStateAction = WTD_STATEACTION_CLOSE as u32;
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
        let kind = CERT_NAME_SIMPLE_DISPLAY_TYPE as u32;
        let len = CertGetNameStringW(cert, kind, 0, None, None, 0);
        if len <= 1 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        CertGetNameStringW(cert, kind, 0, None, Some(PWSTR(buf.as_mut_ptr())), len);
        Some(String::from_utf16_lossy(&buf[..len as usize - 1]))
    }
}

pub fn is_windows_process(is_kernel: bool, signature: ProcessSignature) -> bool {
    // Deliberately no path heuristics: third-party software (and malware)
    // can live under SystemRoot, so a path prefix proves nothing.
    is_kernel || signature == ProcessSignature::Microsoft
}

#[cfg(test)]
mod signature_tests {
    use super::{check_signature, ProcessSignature};

    /// Walks a few hundred real binaries through the same path the agent
    /// uses. Cheap crash repro: the catalog APIs are hand-written FFI, and a
    /// mistake there shows up as an access violation on some particular file
    /// rather than on the three we spot-check above.
    #[test]
    fn signature_check_survives_every_binary_in_system32() {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
        let dir = std::path::PathBuf::from(&system_root).join("System32");
        let mut checked = 0usize;
        for entry in std::fs::read_dir(&dir).expect("System32 must be readable").flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("exe") {
                continue;
            }
            let Some(path) = path.to_str() else { continue };
            let _ = check_signature(path);
            checked += 1;
        }
        assert!(checked > 50, "expected to have checked a lot of binaries, got {checked}");
    }

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

#[cfg(test)]
mod console_host_tests {
    use super::{console_host_from, query_console_host_pid};

    #[test]
    fn only_the_console_flag_names_a_host() {
        assert_eq!(console_host_from(0x1234 << 2 | 1), 0x1234 << 2);
        assert_eq!(console_host_from(0x1234 << 2), 0, "flag 0 carries the parent pid");
        assert_eq!(console_host_from(0x1234 << 2 | 2), 0, "flag 2 carries some other pid");
        assert_eq!(console_host_from(1), 0, "a console process with no host");
    }

    #[test]
    fn a_test_run_from_a_console_sees_its_host() {
        let host = unsafe { query_console_host_pid(std::process::id()) };
        if host != 0 {
            assert_ne!(host, std::process::id());
        }
    }
}
