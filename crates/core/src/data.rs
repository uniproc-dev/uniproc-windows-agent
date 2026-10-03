//! `%ProgramData%\Uniproc`, where the agent keeps its files, open only to
//! SYSTEM and Administrators.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use crate::bindings::{
    ACL, BY_HANDLE_FILE_INFORMATION, ConvertStringSecurityDescriptorToSecurityDescriptorW, CreateDirectoryW,
    DACL_SECURITY_INFORMATION, ERROR_ALREADY_EXISTS, GetFileInformationByHandle, GetLastError,
    GetNamedSecurityInfoW, GetSecurityDescriptorDacl, HANDLE, IsWellKnownSid, LocalFree,
    OWNER_SECURITY_INFORMATION, PACL, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SDDL_REVISION_1, SE_FILE_OBJECT, SECURITY_ATTRIBUTES, SECURITY_INFORMATION, SetNamedSecurityInfoW,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_core::{BOOL, PCWSTR};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Full control for SYSTEM and Administrators, inherited by everything
/// inside, and nothing from the parent.
const DACL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// The directory, created or taken over with [`DACL`]. Refused when it is a
/// reparse point or belongs to anyone but SYSTEM or Administrators: whoever
/// made it could have placed anything inside.
pub fn dir() -> io::Result<PathBuf> {
    let root = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let dir = root.join("Uniproc");
    secure(&dir)?;
    Ok(dir)
}

/// Makes `name` in [`dir`] safe to open: a file there that someone else
/// owns, that is a reparse point or that has a second name is removed.
pub fn claim(name: &str) -> io::Result<PathBuf> {
    let path = dir()?.join(name);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
        Ok(meta) => {
            let plain = meta.is_file() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0;
            if !(plain && owned_by_the_machine(&path)? && single_link(&path)?) {
                tracing::warn!(path = %path.display(), "removing a file the agent did not make");
                remove(&path, &meta)?;
            }
        }
    }
    Ok(path)
}

fn remove(path: &Path, meta: &std::fs::Metadata) -> io::Result<()> {
    if meta.is_dir() {
        std::fs::remove_dir(path)
    } else {
        std::fs::remove_file(path)
    }
}

fn secure(dir: &Path) -> io::Result<()> {
    let descriptor = Descriptor::parse(DACL)?;
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => match create(dir, &descriptor) {
            Err(e) if e.raw_os_error() == Some(ERROR_ALREADY_EXISTS) => secure(dir),
            created => created,
        },
        Err(e) => Err(e),
        Ok(meta) => {
            if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(io::Error::other(format!("{} is not a plain directory", dir.display())));
            }
            if !owned_by_the_machine(dir)? {
                return Err(io::Error::other(format!(
                    "{} belongs to neither SYSTEM nor Administrators",
                    dir.display()
                )));
            }
            protect(dir, &descriptor)
        }
    }
}

fn create(dir: &Path, descriptor: &Descriptor) -> io::Result<()> {
    let wide = wide(dir);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: BOOL(0),
    };
    if unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&attributes)) }.as_bool() {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32))
    }
}

fn protect(dir: &Path, descriptor: &Descriptor) -> io::Result<()> {
    let wide = wide(dir);
    let status = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            SECURITY_INFORMATION(DACL_SECURITY_INFORMATION as u32 | PROTECTED_DACL_SECURITY_INFORMATION),
            None,
            None,
            Some(descriptor.dacl()?),
            None,
        )
    };
    win32(status)
}

fn owned_by_the_machine(path: &Path) -> io::Result<bool> {
    let wide = wide(path);
    let mut owner = PSID::default();
    let mut held = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            SECURITY_INFORMATION(OWNER_SECURITY_INFORMATION as u32),
            Some(&mut owner),
            None,
            None,
            None,
            &mut held,
        )
    };
    win32(status)?;
    let ours = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid).as_bool() || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
    };
    unsafe { LocalFree(HANDLE(held.0)) };
    Ok(ours)
}

fn single_link(path: &Path) -> io::Result<bool> {
    let file = std::fs::File::open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }.as_bool() {
        Ok(info.nNumberOfLinks == 1)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn win32(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// A security descriptor parsed from SDDL, freed when dropped.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn parse(sddl: &str) -> io::Result<Self> {
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let parsed = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                SDDL_REVISION_1 as u32,
                &mut descriptor,
                None,
            )
        };
        if parsed.as_bool() {
            Ok(Self(descriptor))
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn dacl(&self) -> io::Result<*const ACL> {
        let (mut present, mut defaulted) = (BOOL(0), BOOL(0));
        let mut dacl: PACL = std::ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }.as_bool()
            && present.as_bool()
            && !dacl.is_null()
        {
            Ok(dacl.cast_const())
        } else {
            Err(io::Error::other("the descriptor carries no DACL"))
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(HANDLE(self.0.0)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dacl_parses_and_carries_two_entries() {
        let descriptor = Descriptor::parse(DACL).unwrap();
        let dacl = descriptor.dacl().unwrap();
        assert_eq!(unsafe { (*dacl).AceCount }, 2);
    }

    #[test]
    #[ignore = "requires admin"]
    fn the_directory_is_open_only_to_system_and_administrators() {
        let dir = dir().expect("the data directory");
        assert!(owned_by_the_machine(&dir).unwrap());
        let output = std::process::Command::new("icacls").arg(&dir).output().unwrap();
        let listing = String::from_utf8_lossy(&output.stdout).to_lowercase();
        assert!(!listing.contains("builtin\\users"), "{listing}");
        assert!(!listing.contains("(i)"), "nothing is inherited: {listing}");
    }

    #[test]
    #[ignore = "requires admin"]
    fn a_second_name_for_a_file_is_removed_before_use() {
        let dir = dir().expect("the data directory");
        let original = dir.join("claim-test-original");
        let _ = std::fs::remove_file(dir.join("claim-test-link"));
        std::fs::write(&original, "kept").unwrap();
        std::fs::hard_link(&original, dir.join("claim-test-link")).unwrap();

        let claimed = claim("claim-test-link").unwrap();
        assert!(!claimed.exists(), "the second name is gone");
        assert_eq!(std::fs::read_to_string(&original).unwrap(), "kept", "the file it named is untouched");
        std::fs::remove_file(original).unwrap();
    }
}
