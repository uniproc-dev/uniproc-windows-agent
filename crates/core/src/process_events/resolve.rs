//! What a start needs from the machine: the drive a device path is on, the
//! account a SID names, a new process's working directory.

use std::time::{Duration, Instant};

use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::{NtQueryInformationProcess, PROCESS_BASIC_INFORMATION, ProcessBasicInformation};
use ntapi::ntrtl::RTL_USER_PROCESS_PARAMETERS;
use ntapi::winapi::shared::ntdef::UNICODE_STRING;
use smol_str::SmolStr;
use crate::bindings::{
    ConvertSidToStringSidW, HANDLE, LocalFree, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, PSID,
    QueryDosDeviceW, ReadProcessMemory,
};
use windows_core::{PCWSTR, PWSTR};

use super::assemble::Resolve;
use crate::providers::process::passport::SidNames;
use crate::win::OwnedProcess;

/// The machine as starts are told.
pub(crate) struct Machine {
    sids: SidNames,
    drives: Drives,
    services: Box<dyn FnMut(u32) -> Vec<SmolStr> + Send>,
    images: Box<dyn FnMut(u32, u64) -> SmolStr + Send>,
}

impl Machine {
    /// `services` names the services a process hosts; `images` the image of
    /// a listed process by pid and sequence number.
    pub fn new(
        services: impl FnMut(u32) -> Vec<SmolStr> + Send + 'static,
        images: impl FnMut(u32, u64) -> SmolStr + Send + 'static,
    ) -> Self {
        Self {
            sids: SidNames::default(),
            drives: Drives::default(),
            services: Box::new(services),
            images: Box::new(images),
        }
    }

    /// The Win32 image path of the listed process; empty when none is listed.
    pub fn listed_image(&mut self, pid: u32, sequence_number: u64) -> SmolStr {
        (self.images)(pid, sequence_number)
    }
}

impl Resolve for Machine {
    fn image_path(&mut self, nt: &str) -> SmolStr {
        self.drives.win32(nt).map_or_else(|| nt.into(), SmolStr::from)
    }

    fn user(&mut self, sid: &[u8]) -> SmolStr {
        user(&mut self.sids, sid)
    }

    fn parent_services(&mut self, pid: u32) -> Vec<SmolStr> {
        (self.services)(pid)
    }
}

/// `DOMAIN\name` of `sid`, or the SID string when it does not resolve;
/// empty for no SID.
fn user(sids: &mut SidNames, sid: &[u8]) -> SmolStr {
    if sid.is_empty() {
        return SmolStr::default();
    }
    let name = sids.name(sid);
    if !name.is_empty() {
        return name;
    }
    sid_string(sid).map(SmolStr::from).unwrap_or_default()
}

fn sid_string(sid: &[u8]) -> Option<String> {
    let mut text = PWSTR::null();
    let converted = unsafe { ConvertSidToStringSidW(PSID(sid.as_ptr() as *mut _), &mut text) };
    if !converted.as_bool() {
        return None;
    }
    let string = unsafe { text.to_string() }.ok();
    unsafe { LocalFree(HANDLE(text.0.cast())) };
    string
}

/// How long a path on no drive keeps the drives from being read again.
const DRIVES_REREAD_AFTER: Duration = Duration::from_secs(10);

/// The device each drive letter names, read again when a path is on none.
#[derive(Default)]
struct Drives {
    devices: Vec<(String, String)>,
    read_at: Option<Instant>,
}

impl Drives {
    /// `nt` with its device replaced by the drive letter on it.
    fn win32(&mut self, nt: &str) -> Option<String> {
        if let Some(path) = self.find(nt) {
            return Some(path);
        }
        if self.read_at.is_some_and(|at| at.elapsed() < DRIVES_REREAD_AFTER) {
            return None;
        }
        self.read();
        self.find(nt)
    }

    fn find(&self, nt: &str) -> Option<String> {
        self.devices.iter().find_map(|(device, letter)| {
            let rest = nt.get(device.len()..)?;
            (nt[..device.len()].eq_ignore_ascii_case(device) && rest.starts_with('\\')).then(|| format!("{letter}{rest}"))
        })
    }

    fn read(&mut self) {
        self.read_at = Some(Instant::now());
        self.devices = (b'A'..=b'Z')
            .filter_map(|letter| {
                let drive = format!("{}:", letter as char);
                let name: Vec<u16> = drive.encode_utf16().chain(Some(0)).collect();
                let mut target = [0u16; 512];
                let len = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(PWSTR(target.as_mut_ptr())), target.len() as u32) };
                let device = target[..len as usize].split(|&unit| unit == 0).next().filter(|d| !d.is_empty())?;
                Some((String::from_utf16_lossy(device), drive))
            })
            .collect();
    }
}

/// Where the process `pid` was working when read; empty when it is gone or
/// cannot be read.
pub(crate) fn working_directory(pid: u32) -> SmolStr {
    read_working_directory(pid).map(SmolStr::from).unwrap_or_default()
}

fn read_working_directory(pid: u32) -> Option<String> {
    let process = OwnedProcess::open(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, pid).ok()?;
    let read = |from: usize, to: *mut u8, len: usize| unsafe {
        ReadProcessMemory(process.0, from as _, to.cast(), len, None).as_bool()
    };
    let mut basic = unsafe { std::mem::zeroed::<PROCESS_BASIC_INFORMATION>() };
    let status = unsafe {
        NtQueryInformationProcess(
            process.0.0.cast(),
            ProcessBasicInformation,
            (&mut basic as *mut PROCESS_BASIC_INFORMATION).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status != 0 || basic.PebBaseAddress.is_null() {
        return None;
    }
    let mut parameters_at = 0usize;
    let peb = basic.PebBaseAddress as usize + std::mem::offset_of!(PEB, ProcessParameters);
    if !read(peb, (&mut parameters_at as *mut usize).cast(), size_of::<usize>()) || parameters_at == 0 {
        return None;
    }
    let mut directory = unsafe { std::mem::zeroed::<UNICODE_STRING>() };
    let field = parameters_at + std::mem::offset_of!(RTL_USER_PROCESS_PARAMETERS, CurrentDirectory);
    if !read(field, (&mut directory as *mut UNICODE_STRING).cast(), size_of::<UNICODE_STRING>()) {
        return None;
    }
    let mut units = vec![0u16; directory.Length as usize / 2];
    if units.is_empty() || !read(directory.Buffer as usize, units.as_mut_ptr().cast(), units.len() * 2) {
        return None;
    }
    Some(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::{GetCurrentProcess, QueryFullProcessImageNameW};
    use windows_core::PWSTR;

    const PROCESS_NAME_NATIVE: u32 = 1;

    fn native_image_path() -> String {
        let mut buffer = [0u16; 1024];
        let mut len = buffer.len() as u32;
        unsafe { QueryFullProcessImageNameW(GetCurrentProcess(), PROCESS_NAME_NATIVE, PWSTR(buffer.as_mut_ptr()), &mut len) }
            .ok()
            .unwrap();
        String::from_utf16_lossy(&buffer[..len as usize])
    }

    #[test]
    fn a_device_path_reads_with_its_drive_letter() {
        let nt = native_image_path();
        assert!(nt.starts_with(r"\Device\"), "{nt}");
        let win32 = Drives::default().win32(&nt);
        let exe = std::env::current_exe().unwrap();
        assert_eq!(win32.map(|p| p.to_lowercase()), Some(exe.to_string_lossy().to_lowercase()));
    }

    #[test]
    fn a_path_on_no_drive_stays_as_it_is() {
        let mut machine = Machine::new(|_| Vec::new(), |_, _| SmolStr::default());
        assert_eq!(machine.image_path(r"\Device\Nowhere\x.exe"), r"\Device\Nowhere\x.exe");
        assert_eq!(Drives::default().win32(r"\Device\Nowhere\x.exe"), None);
    }

    #[test]
    fn a_sid_that_names_nobody_reads_as_its_string() {
        let mut sids = SidNames::default();
        let unknown = [1u8, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0];
        assert_eq!(user(&mut sids, &unknown), "S-1-5-21-1-2-3");
        let system = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let name = user(&mut sids, &system);
        assert!(name.contains('\\') && !name.starts_with("S-1-"), "{name}");
        assert_eq!(user(&mut sids, &[]), "");
    }

    #[test]
    fn a_process_s_working_directory_is_read_while_it_runs() {
        let directory = std::env::temp_dir().canonicalize().unwrap();
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "ping", "-n", "30", "127.0.0.1"])
            .current_dir(&directory)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let read = working_directory(child.id());
        let _ = child.kill();
        let _ = child.wait();
        let expected = directory.to_string_lossy().trim_start_matches(r"\\?\").to_lowercase();
        assert_eq!(read.trim_end_matches('\\').to_lowercase(), expected);
        assert_eq!(working_directory(child.id()), "", "gone");
    }
}
