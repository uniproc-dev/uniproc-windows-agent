use ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS;
use ntapi::winapi::um::winbase::LocalFree;
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, LPARAM, TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_SAFER_FLAG, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
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
            ProcessSignature::Unsigned
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
