use ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS;
use ntapi::winapi::um::winbase::LocalFree;
use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::Win32::Foundation::{CloseHandle};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{OpenProcess, PEB, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::Storage::Packaging::Appx::{GetApplicationUserModelId, GetPackageFullName};
use windows::Win32::UI::Shell::CommandLineToArgvW;

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
    let mut buf = vec![0u16; len];
    let ok = ReadProcessMemory(
        handle,
        params.CommandLine.Buffer as *const _,
        buf.as_mut_ptr() as *mut _,
        params.CommandLine.Length as usize,
        None,
    );

    CloseHandle(handle).ok();

    if ok.is_err() {
        return None;
    }

    Some(String::from_utf16_lossy(&buf))
}

pub unsafe fn parse_cmd_line(cmd_line: &str) -> Vec<String> {
    let u16_cmd = cmd_line.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let mut argc = 0i32;
    let argv_ptr = CommandLineToArgvW(PCWSTR(u16_cmd.as_ptr()), &mut argc);

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