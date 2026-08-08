//! Resolving the human-facing name of a process.
//!
//! The OS-reported name is an image name (`explorer.exe`), which is what the
//! rest of the agent keys on. What a person expects to read is "Windows
//! Explorer", and Windows keeps that in three unrelated places depending on
//! what kind of program it is:
//!
//! * packaged (MSIX/UWP) apps declare it in their manifest, reachable through
//!   the package id and `SHLoadIndirectString`;
//! * classic Win32 binaries carry it as `FileDescription` in their version
//!   resource;
//! * anything else can still be asked of the shell, which at worst hands back
//!   a prettied-up file name.
//!
//! They are tried in that order: the manifest is authoritative for packaged
//! apps, the version resource is what Task Manager shows, and the shell is a
//! fallback that always answers something.
//!
//! Ported from the pre-agent scanner (`uniproc`'s `domain/features/processes/
//! scanner/ctx/windows.rs`), which resolved the same three sources in-process
//! before this moved behind the RPC boundary.

use std::ptr::addr_of;
use windows::Win32::Foundation::FALSE;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::Storage::Packaging::Appx::{
    PACKAGE_ID, PACKAGE_INFORMATION_BASIC, PackageIdFromFullName,
};
use windows::Win32::UI::Shell::{
    SHFILEINFOW, SHGFI_DISPLAYNAME, SHGFI_USEFILEATTRIBUTES, SHGetFileInfoW, SHLoadIndirectString,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

/// Best available display name, or `None` if nothing answered - in which case
/// the consumer keeps showing the image name.
///
/// `image_path` is a Win32 path (as returned by `query_image_path`), not an NT
/// device path: the version-resource APIs cannot open `\Device\...`.
pub fn resolve(image_path: &str, package_full_name: &str) -> Option<String> {
    if !package_full_name.is_empty()
        && let Some(name) = package_display_name(package_full_name)
    {
        return Some(name);
    }

    if image_path.is_empty() {
        return None;
    }

    file_description(image_path).or_else(|| shell_display_name(image_path))
}

/// The publisher of a packaged app, as the OS recorded it at install time
/// (`CN=Microsoft Corporation, O=Microsoft Corporation, ...`).
///
/// Trustworthy without us verifying anything: Windows refuses to install a
/// package whose signature does not check out, so the publisher on a package
/// that *is* installed has already been through that check. This is the only
/// signer information a packaged binary has - the files inside an MSIX carry
/// no signature of their own, the package as a whole does.
pub fn package_publisher(package_full_name: &str) -> Option<String> {
    let full_name = HSTRING::from(package_full_name);
    let mut buffer_size = 0u32;

    unsafe {
        let _ = PackageIdFromFullName(
            PCWSTR(full_name.as_ptr()),
            PACKAGE_INFORMATION_BASIC,
            &mut buffer_size,
            None,
        );
    }
    if buffer_size == 0 {
        return None;
    }

    let mut buffer = vec![0u8; buffer_size as usize];
    unsafe {
        PackageIdFromFullName(
            PCWSTR(full_name.as_ptr()),
            PACKAGE_INFORMATION_BASIC,
            &mut buffer_size,
            Some(buffer.as_mut_ptr()),
        )
        .ok()
        .ok()?;

        let pkg_id = buffer.as_ptr() as *const PACKAGE_ID;
        let publisher: PWSTR = addr_of!((*pkg_id).publisher).read_unaligned();
        publisher.to_string().ok().filter(|p| !p.is_empty())
    }
}

/// The `AppName` resource a packaged app declares in its manifest.
fn package_display_name(package_full_name: &str) -> Option<String> {
    let full_name = HSTRING::from(package_full_name);
    let mut buffer_size = 0u32;

    // First call sizes the buffer; it is expected to fail with
    // ERROR_INSUFFICIENT_BUFFER, so the result is deliberately ignored.
    unsafe {
        let _ = PackageIdFromFullName(
            PCWSTR(full_name.as_ptr()),
            PACKAGE_INFORMATION_BASIC,
            &mut buffer_size,
            None,
        );
    }
    if buffer_size == 0 {
        return None;
    }

    let mut buffer = vec![0u8; buffer_size as usize];
    let base_name = unsafe {
        PackageIdFromFullName(
            PCWSTR(full_name.as_ptr()),
            PACKAGE_INFORMATION_BASIC,
            &mut buffer_size,
            Some(buffer.as_mut_ptr()),
        )
        .ok()
        .ok()?;

        // PACKAGE_ID is written into `buffer` with no alignment guarantee.
        let pkg_id = buffer.as_ptr() as *const PACKAGE_ID;
        let name: PWSTR = addr_of!((*pkg_id).name).read_unaligned();
        name.to_string().ok()?
    };

    // The indirect string is what the manifest's `DisplayName` points at when
    // it is localized (`ms-resource:` rather than a literal).
    let indirect = HSTRING::from(format!(
        "@{{{package_full_name}?ms-resource://{base_name}/resources/AppName}}"
    ));
    let mut out = [0u16; 256];

    unsafe {
        SHLoadIndirectString(PCWSTR(indirect.as_ptr()), &mut out, None).ok()?;
    }

    let resolved = String::from_utf16_lossy(&out)
        .trim_matches('\0')
        .trim()
        .to_string();

    // A leading '@' means the reference was handed back unresolved - that is
    // not a name, it is the lookup failing quietly.
    (!resolved.is_empty() && !resolved.starts_with('@')).then_some(resolved)
}

/// `FileDescription` from the binary's version resource - the string Task
/// Manager shows in its Name column for classic Win32 programs.
fn file_description(image_path: &str) -> Option<String> {
    let path = HSTRING::from(image_path);

    unsafe {
        let mut handle = 0u32;
        let size = GetFileVersionInfoSizeW(PCWSTR(path.as_ptr()), Some(&mut handle));
        if size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        GetFileVersionInfoW(
            PCWSTR(path.as_ptr()),
            None,
            size,
            buffer.as_mut_ptr() as *mut _,
        )
        .ok()?;

        // The string table is keyed by language+codepage, and there is no
        // fixed one to assume: ask the file which translations it carries and
        // take the first.
        let mut translate = std::ptr::null_mut();
        let mut translate_len = 0u32;
        if VerQueryValueW(
            buffer.as_ptr() as *const _,
            windows::core::w!("\\VarFileInfo\\Translation"),
            &mut translate,
            &mut translate_len,
        ) == FALSE
            || translate_len < 4
        {
            return None;
        }

        let lang = (translate as *const u32).read_unaligned();
        let sub_block = HSTRING::from(format!(
            "\\StringFileInfo\\{:04x}{:04x}\\FileDescription",
            lang & 0xFFFF,
            (lang >> 16) & 0xFFFF
        ));

        let mut description = std::ptr::null_mut();
        let mut description_len = 0u32;
        if VerQueryValueW(
            buffer.as_ptr() as *const _,
            PCWSTR(sub_block.as_ptr()),
            &mut description,
            &mut description_len,
        ) == FALSE
        {
            return None;
        }

        let text = PWSTR(description as *mut _).to_string().ok()?;
        let trimmed = text.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }
}

/// What Explorer would call the file. `SHGFI_USEFILEATTRIBUTES` keeps this
/// from touching the disk, so it stays cheap and works even if the file is
/// gone by now.
fn shell_display_name(image_path: &str) -> Option<String> {
    let path = HSTRING::from(image_path);
    let mut info = SHFILEINFOW::default();

    unsafe {
        SHGetFileInfoW(
            PCWSTR(path.as_ptr()),
            windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
            Some(&mut info),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_DISPLAYNAME | SHGFI_USEFILEATTRIBUTES,
        );
    }

    let name = String::from_utf16_lossy(&info.szDisplayName)
        .trim_matches('\0')
        .trim()
        .to_string();

    (!name.is_empty()).then_some(name)
}
