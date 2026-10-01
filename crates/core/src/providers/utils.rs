use std::mem::size_of;

use ntapi::winapi::shared::ntdef::UNICODE_STRING;
use windows::Win32::{
    CATALOG_INFO, LocalFree, CERT_CHAIN_POLICY_MICROSOFT_ROOT, CERT_CHAIN_POLICY_PARA,
    CERT_CHAIN_POLICY_STATUS, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertVerifyCertificateChainPolicy,
    MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG, PCCERT_CHAIN_CONTEXT, CloseHandle, CommandLineToArgvW, CreateFileW,
    CertGetNameStringW, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, ERROR_INSUFFICIENT_BUFFER, FILE_SHARE_DELETE,
    FILE_SHARE_READ, GENERIC_READ, GetApplicationUserModelId, GetLastError, GetPackageFullName, HANDLE,
    HCATADMIN, HCATINFO, HWND, NtQueryInformationProcess, OPEN_EXISTING,
    PROCESSINFOCLASS, QueryFullProcessImageNameW,
    TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, WINTRUST_CATALOG_INFO,
    WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_SAFER_FLAG, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::core::{PCWSTR, PWSTR};

use crate::state::events::ProcessSignature;
use crate::win::{PROCESS_NAME_WIN32, WINTRUST_ACTION_GENERIC_VERIFY_V2};

const PROCESS_COMMAND_LINE_INFORMATION: PROCESSINFOCLASS = 60;
const PROCESS_SEQUENCE_NUMBER: PROCESSINFOCLASS = 92;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;

/// The command line as the kernel keeps it; a limited-query handle is
/// enough and nothing is read from the process's own memory.
pub unsafe fn query_command_line(process: HANDLE) -> Option<String> {
    COMMAND_LINE_SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        if scratch.is_empty() {
            scratch.resize(512, 0);
        }
        let mut needed = 0u32;
        let mut status = NtQueryInformationProcess(
            process,
            PROCESS_COMMAND_LINE_INFORMATION,
            scratch.as_mut_ptr().cast(),
            (scratch.len() * 8) as u32,
            Some(&mut needed),
        );
        if matches!(status.0, STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_TOO_SMALL | STATUS_BUFFER_OVERFLOW)
            && needed as usize > scratch.len() * 8
        {
            scratch.resize((needed as usize).div_ceil(8), 0);
            status = NtQueryInformationProcess(
                process,
                PROCESS_COMMAND_LINE_INFORMATION,
                scratch.as_mut_ptr().cast(),
                (scratch.len() * 8) as u32,
                Some(&mut needed),
            );
        }
        if status.is_err() {
            return None;
        }
        unicode_string_in(bytes_of(&scratch)).map(|units| String::from_utf16_lossy(&units))
    })
}

pub(crate) fn bytes_of(words: &[u64]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), words.len() * 8) }
}

/// The characters of the UNICODE_STRING at the start of `buffer`, whose
/// text must lie inside `buffer` too.
pub(crate) fn unicode_string_in(buffer: &[u8]) -> Option<Vec<u16>> {
    let header = size_of::<UNICODE_STRING>();
    if buffer.len() < header {
        return None;
    }
    let string = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<UNICODE_STRING>()) };
    let length = string.Length as usize & !1;
    if length == 0 {
        return Some(Vec::new());
    }
    let start = (string.Buffer as usize).checked_sub(buffer.as_ptr() as usize)?;
    if start < header || start.checked_add(length)? > buffer.len() {
        return None;
    }
    Some(
        buffer[start..start + length]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect(),
    )
}

/// The process's sequence number, which no other process on this boot
/// shares; None where Windows does not tell it.
pub unsafe fn query_sequence_number(process: HANDLE) -> Option<u64> {
    let mut value = 0u64;
    NtQueryInformationProcess(
        process,
        PROCESS_SEQUENCE_NUMBER,
        (&mut value as *mut u64).cast(),
        size_of::<u64>() as u32,
        None,
    )
    .is_ok()
    .then_some(value)
}

pub unsafe fn parse_cmd_line(cmd_line: &str) -> Vec<String> {
    if cmd_line.trim().is_empty() {
        return Vec::new();
    }
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


pub unsafe fn get_process_package_info(handle: HANDLE) -> Option<(String, String)> {
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

    if let Some(package_relative_app_id) = package_relative_app_id && let Some(package_full_name) = package_full_name {
        Some((package_full_name, package_relative_app_id))
    }
    else {
        None
    }
}
/// The Win32 path of the image; a path longer than the first buffer is
/// asked for again with room for the longest one Windows allows.
pub unsafe fn query_image_path(handle: HANDLE) -> Option<String> {
    WIDE_SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        for room in [1024, 32 * 1024] {
            scratch.clear();
            scratch.resize(room, 0);
            let mut len = scratch.len() as u32;
            let ok = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(scratch.as_mut_ptr()),
                &mut len,
            );
            if ok.as_bool() {
                return Some(String::from_utf16_lossy(&scratch[..len as usize]));
            }
            if GetLastError() != ERROR_INSUFFICIENT_BUFFER as u32 {
                return None;
            }
        }
        None
    })
}

const PROCESS_CONSOLE_HOST_PROCESS: PROCESSINFOCLASS = 49;

/// Pid of the conhost serving the process's console, or 0 when it has none.
pub unsafe fn query_console_host_pid(handle: HANDLE) -> u32 {
    let mut value = 0usize;
    let status = NtQueryInformationProcess(
        handle,
        PROCESS_CONSOLE_HOST_PROCESS,
        &mut value as *mut usize as *mut _,
        std::mem::size_of::<usize>() as u32,
        None,
    );
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
    static COMMAND_LINE_SCRATCH: std::cell::RefCell<Vec<u64>> =
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
fn catalog_signature(path: &str) -> Option<(ProcessSignature, Option<String>)> {
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

        let verdict = (status == 0).then(|| signer_verdict(data.hWVTStateData));

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

/// Microsoft only when the signer's chain ends in one of Microsoft's own
/// roots; a subject naming Microsoft proves nothing.
unsafe fn signer_verdict(state: HANDLE) -> (ProcessSignature, Option<String>) {
    let Some((subject, chain)) = (unsafe { signer_of(state) }) else {
        return (ProcessSignature::Unknown, None);
    };
    let signature = if unsafe { roots_at_microsoft(chain) } {
        ProcessSignature::Microsoft
    } else {
        ProcessSignature::ThirdParty
    };
    (signature, subject)
}

/// The product root check and the application root check each accept only
/// their own roots, so both are asked.
unsafe fn roots_at_microsoft(chain: PCCERT_CHAIN_CONTEXT) -> bool {
    if chain.is_null() {
        return false;
    }
    [0, MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG as u32].into_iter().any(|flags| {
        let para = CERT_CHAIN_POLICY_PARA {
            cbSize: size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
            dwFlags: flags,
            ..Default::default()
        };
        let mut status = CERT_CHAIN_POLICY_STATUS {
            cbSize: size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
            ..Default::default()
        };
        unsafe { CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, chain, &para, &mut status) }
            .as_bool()
            && status.dwError == 0
    })
}

#[cfg(test)]
pub fn check_signature(path: &str) -> ProcessSignature {
    check_signer(path).0
}

/// The verdict, and the signer's subject name when the file is signed.
pub fn check_signer(path: &str) -> (ProcessSignature, Option<String>) {
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
            signer_verdict(data.hWVTStateData)
        } else if status == TRUST_E_NOSIGNATURE.0 || status == TRUST_E_SUBJECT_FORM_UNKNOWN.0 {
            // No *embedded* signature is not the same as unsigned: most of
            // Windows' own binaries (dwm.exe, winlogon.exe, wslservice.exe)
            // are signed by catalog instead, and treating them as unsigned
            // filed half the operating system under third-party software.
            catalog_signature(path).unwrap_or((ProcessSignature::Unsigned, None))
        } else {
            (ProcessSignature::Unknown, None)
        };

        data.dwStateAction = WTD_STATEACTION_CLOSE as u32;
        let _ = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);
        result
    })
}

/// The first signer's subject name and the chain WinVerifyTrust built for
/// it, valid until the state is closed.
unsafe fn signer_of(state: HANDLE) -> Option<(Option<String>, PCCERT_CHAIN_CONTEXT)> {
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
        let subject = (len > 1).then(|| {
            let mut buf = vec![0u16; len as usize];
            CertGetNameStringW(cert, kind, 0, None, Some(PWSTR(buf.as_mut_ptr())), len);
            String::from_utf16_lossy(&buf[..len as usize - 1])
        });
        Some((subject, sgnr.pChainContext))
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
        let host = unsafe { query_console_host_pid(windows::Win32::GetCurrentProcess()) };
        if host != 0 {
            assert_ne!(host, std::process::id());
        }
    }
}

#[cfg(test)]
mod command_line_tests {
    use std::mem::size_of;

    use ntapi::winapi::shared::ntdef::UNICODE_STRING;
    use windows::Win32::{GetCurrentProcess, HANDLE};

    use super::{bytes_of, parse_cmd_line, query_command_line, query_sequence_number, unicode_string_in};

    fn buffer(length: u16, text_at: Option<usize>, words: usize) -> Vec<u64> {
        let mut buffer = vec![0u64; words];
        let base = buffer.as_mut_ptr() as usize;
        let text = size_of::<UNICODE_STRING>();
        for (i, unit) in "abcdefgh".encode_utf16().enumerate() {
            let at = text + i * 2;
            if at + 2 <= words * 8 {
                unsafe { std::ptr::write_unaligned((base + at) as *mut u16, unit) };
            }
        }
        let string = UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            Buffer: text_at.map_or(text, |at| at).wrapping_add(base) as *mut u16,
        };
        unsafe { std::ptr::write_unaligned(base as *mut UNICODE_STRING, string) };
        buffer
    }

    #[test]
    fn an_odd_length_drops_the_half_character() {
        let buffer = buffer(7, None, 8);
        assert_eq!(unicode_string_in(bytes_of(&buffer)), Some("abc".encode_utf16().collect()));
    }

    #[test]
    fn text_outside_the_buffer_is_refused() {
        let past_the_end = buffer(16, None, 3);
        assert_eq!(unicode_string_in(bytes_of(&past_the_end)), None);
        let before_the_text = buffer(4, Some(0), 8);
        assert_eq!(unicode_string_in(bytes_of(&before_the_text)), None);
        let elsewhere = buffer(4, Some(usize::MAX / 2), 8);
        assert_eq!(unicode_string_in(bytes_of(&elsewhere)), None);
    }

    #[test]
    fn this_process_reads_its_own_arguments() {
        let line = unsafe { query_command_line(GetCurrentProcess()) }.expect("command line");
        let args = unsafe { parse_cmd_line(&line) };
        assert_eq!(args, std::env::args().collect::<Vec<_>>());
    }

    #[test]
    fn an_empty_command_line_has_no_arguments() {
        assert!(unsafe { parse_cmd_line("") }.is_empty());
        assert!(unsafe { parse_cmd_line("  ") }.is_empty());
    }

    #[test]
    fn a_child_that_writes_an_odd_length_into_its_peb_reads_safely() {
        use std::os::windows::io::AsRawHandle;

        use ntapi::ntpebteb::PEB;
        use ntapi::ntpsapi::{NtQueryInformationProcess, PROCESS_BASIC_INFORMATION, ProcessBasicInformation};
        use ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS;
        use windows::Win32::{ReadProcessMemory, WriteProcessMemory};

        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "ping", "-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("child");
        let process = HANDLE(child.as_raw_handle());
        std::thread::sleep(std::time::Duration::from_millis(300));
        let before = unsafe { query_command_line(process) }.expect("command line");
        assert!(before.to_ascii_lowercase().contains("ping"), "{before:?}");
        unsafe {
            let mut basic = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();
            let status = NtQueryInformationProcess(
                process.0.cast(),
                ProcessBasicInformation,
                (&mut basic as *mut PROCESS_BASIC_INFORMATION).cast(),
                size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            assert_eq!(status, 0);
            let mut peb = std::mem::zeroed::<PEB>();
            let read = |from: usize, to: *mut u8, len: usize| {
                ReadProcessMemory(process, from as _, to.cast(), len, None).as_bool()
            };
            assert!(read(basic.PebBaseAddress as usize, (&mut peb as *mut PEB).cast(), size_of::<PEB>()));
            let mut params = std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>();
            let at = peb.ProcessParameters as usize;
            assert!(read(at, (&mut params as *mut RTL_USER_PROCESS_PARAMETERS).cast(), size_of::<RTL_USER_PROCESS_PARAMETERS>()));
            let odd: u16 = (params.CommandLine.Length | 1).min(params.CommandLine.MaximumLength | 1);
            let field = at + std::mem::offset_of!(RTL_USER_PROCESS_PARAMETERS, CommandLine);
            let wrote = WriteProcessMemory(process, field as _, (&odd as *const u16).cast(), 2, None);
            assert!(wrote.as_bool(), "write the odd length");

            let after = query_command_line(process);
            let _ = child.kill();
            assert!(
                after.as_ref().is_none_or(|line| before.starts_with(line.as_str())),
                "the kernel refuses an odd length or hands whole characters: {after:?}"
            );
        }
    }

    #[test]
    fn this_process_has_a_sequence_number() {
        assert!(unsafe { query_sequence_number(GetCurrentProcess()) }.is_some_and(|n| n != 0));
    }
}
