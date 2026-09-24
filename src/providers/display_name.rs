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
use windows::Win32::Foundation::{ERROR_SUCCESS, FALSE};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::Storage::Packaging::Appx::{
    GetPackagePathByFullName, PACKAGE_ID, PACKAGE_INFORMATION_BASIC, PACKAGE_INFORMATION_FULL,
    PackageIdFromFullName,
};
use windows::Win32::UI::Shell::{
    SHFILEINFOW, SHGFI_DISPLAYNAME, SHGFI_USEFILEATTRIBUTES, SHGetFileInfoW, SHLoadIndirectString,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use crate::aligned::AlignedBuf;

/// Best available display name, or `None` if nothing answered - in which case
/// the consumer keeps showing the image name.
///
/// `image_path` is a Win32 path (as returned by `query_image_path`), not an NT
/// device path: the version-resource APIs cannot open `\Device\...`.
/// `app_id` is the part of the process's AUMID after `!`: one package can hold
/// several applications, each with a name of its own.
pub fn resolve(image_path: &str, package_full_name: &str, app_id: &str) -> Option<String> {
    if !package_full_name.is_empty()
        && let Some(name) = package_display_name(package_full_name, app_id)
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

    // FULL, not BASIC: the basic id carries the publisher *hash*
    // (`8wekyb3d8bbwe`), and leaves the `publisher` field - the certificate
    // subject we actually want - as a null pointer.
    unsafe {
        let _ = PackageIdFromFullName(
            PCWSTR(full_name.as_ptr()),
            PACKAGE_INFORMATION_FULL,
            &mut buffer_size,
            None,
        );
    }
    if buffer_size == 0 {
        return None;
    }

    let mut buffer = AlignedBuf::zeroed(buffer_size as usize);
    unsafe {
        PackageIdFromFullName(
            PCWSTR(full_name.as_ptr()),
            PACKAGE_INFORMATION_FULL,
            &mut buffer_size,
            Some(buffer.as_mut_ptr()),
        )
        .ok()
        .ok()?;

        let pkg_id = buffer.as_ptr() as *const PACKAGE_ID;
        let publisher: PWSTR = addr_of!((*pkg_id).publisher).read_unaligned();
        // A field the API chose not to fill is a null pointer, and
        // `PWSTR::to_string` dereferences without checking - that read is an
        // access violation, not a `None`.
        if publisher.is_null() {
            return None;
        }
        publisher.to_string().ok().filter(|p| !p.is_empty())
    }
}

/// The name the package's manifest declares for this application, the one
/// Start and Task Manager show.
///
/// Read from the manifest rather than guessed: `DisplayName` is either a
/// literal or an `ms-resource:` reference to a key of the package's own
/// choosing. Only when the manifest cannot be read does this fall back to the
/// conventional `AppName` key.
fn package_display_name(package_full_name: &str, app_id: &str) -> Option<String> {
    let base_name = package_base_name(package_full_name)?;

    let declared = package_path(package_full_name)
        .and_then(|dir| std::fs::read_to_string(dir.join("AppxManifest.xml")).ok())
        .and_then(|xml| manifest_display_name(&xml, app_id));

    match declared {
        Some(value) => match resource_uris(&value, &base_name) {
            Some(uris) => uris
                .iter()
                .find_map(|uri| load_indirect(package_full_name, uri)),
            None => Some(value),
        },
        None => load_indirect(
            package_full_name,
            &format!("ms-resource://{base_name}/resources/AppName"),
        ),
    }
}

/// Where the package is installed.
fn package_path(package_full_name: &str) -> Option<std::path::PathBuf> {
    let full_name = HSTRING::from(package_full_name);
    let mut len = 0u32;
    unsafe {
        let _ = GetPackagePathByFullName(PCWSTR(full_name.as_ptr()), &mut len, None);
    }
    if len == 0 {
        return None;
    }

    let mut buf = vec![0u16; len as usize];
    let status = unsafe {
        GetPackagePathByFullName(PCWSTR(full_name.as_ptr()), &mut len, Some(PWSTR(buf.as_mut_ptr())))
    };
    if status != ERROR_SUCCESS {
        return None;
    }

    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(std::path::PathBuf::from(String::from_utf16_lossy(&buf[..end])))
}

/// The raw `DisplayName` a manifest declares for `app_id`: the application's
/// own `VisualElements/@DisplayName`, else the package's
/// `Properties/DisplayName`. Returned as written - a literal or an
/// `ms-resource:` reference.
fn manifest_display_name(xml: &str, app_id: &str) -> Option<String> {
    let doc = roxmltree::Document::parse(xml).ok()?;

    let from_application = doc
        .descendants()
        .find(|n| n.tag_name().name() == "Application" && n.attribute("Id") == Some(app_id))
        .and_then(|app| app.descendants().find(|n| n.tag_name().name() == "VisualElements"))
        .and_then(|visual| visual.attribute("DisplayName"));

    let from_package = || {
        doc.descendants()
            .find(|n| n.tag_name().name() == "Properties")
            .and_then(|props| props.children().find(|c| c.tag_name().name() == "DisplayName"))
            .and_then(|name| name.text())
    };

    from_application
        .or_else(from_package)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// The full `ms-resource://` URIs a manifest value may refer to, most likely
/// first, or `None` when the value is a literal name.
///
/// A leading slash (`ms-resource:/Map/Key`) or an empty authority
/// (`ms-resource:///Map/Key`) is rooted at the package. A relative path is
/// ambiguous: Snipping Tool's `AppName/Text` lives in the default `Resources`
/// map, while Paint's `Resources/AppDisplayName` and the shell's
/// `CrossDeviceResume/Resources/AppDisplayName` already spell out the whole
/// path. Both readings are offered, the default map first.
fn resource_uris(value: &str, package_name: &str) -> Option<Vec<String>> {
    const SCHEME: &str = "ms-resource:";
    let head = value.get(..SCHEME.len())?;
    if !head.eq_ignore_ascii_case(SCHEME) {
        return None;
    }
    let rest = &value[SCHEME.len()..];

    let paths = if let Some(authority) = rest.strip_prefix("//") {
        if authority.starts_with('/') {
            vec![format!("//{package_name}{authority}")]
        } else {
            vec![format!("//{authority}")]
        }
    } else if rest.starts_with('/') {
        vec![format!("//{package_name}{rest}")]
    } else {
        vec![
            format!("//{package_name}/Resources/{rest}"),
            format!("//{package_name}/{rest}"),
        ]
    };

    Some(paths.into_iter().map(|path| format!("{SCHEME}{path}")).collect())
}

/// Resolves an `ms-resource:` URI against the package's resources.
fn load_indirect(package_full_name: &str, uri: &str) -> Option<String> {
    let indirect = HSTRING::from(format!("@{{{package_full_name}?{uri}}}"));
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

/// The package's name without version, architecture or publisher: the
/// authority its resource URIs use.
fn package_base_name(package_full_name: &str) -> Option<String> {
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

    let mut buffer = AlignedBuf::zeroed(buffer_size as usize);
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
        let name: PWSTR = addr_of!((*pkg_id).name).read_unaligned();
        if name.is_null() {
            return None;
        }
        name.to_string().ok()
    }
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

        let mut buffer = AlignedBuf::zeroed(size as usize);
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

#[cfg(test)]
mod tests {
    use super::{manifest_display_name, package_publisher, resolve, resource_uris};

    const GALLERY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Properties>
    <DisplayName>WinUI 3 Gallery</DisplayName>
  </Properties>
  <Applications>
    <Application Id="App" Executable="WinUIGallery.exe">
      <uap:VisualElements DisplayName="WinUI 3 Gallery" Description="Gallery" />
    </Application>
  </Applications>
</Package>"#;

    const TWO_APPS: &str = r#"<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Properties>
    <DisplayName>ms-resource:PackageName</DisplayName>
  </Properties>
  <Applications>
    <Application Id="Editor">
      <uap:VisualElements DisplayName="ms-resource:EditorTitle" />
    </Application>
    <Application Id="Viewer">
      <uap:VisualElements DisplayName="Viewer" />
    </Application>
    <Application Id="Headless" />
  </Applications>
</Package>"#;

    #[test]
    fn a_literal_display_name_is_read_as_written() {
        assert_eq!(
            manifest_display_name(GALLERY, "App").as_deref(),
            Some("WinUI 3 Gallery")
        );
    }

    #[test]
    fn each_application_gets_its_own_name() {
        assert_eq!(
            manifest_display_name(TWO_APPS, "Editor").as_deref(),
            Some("ms-resource:EditorTitle")
        );
        assert_eq!(manifest_display_name(TWO_APPS, "Viewer").as_deref(), Some("Viewer"));
    }

    #[test]
    fn an_application_without_visual_elements_falls_back_to_the_package() {
        assert_eq!(
            manifest_display_name(TWO_APPS, "Headless").as_deref(),
            Some("ms-resource:PackageName")
        );
        assert_eq!(
            manifest_display_name(TWO_APPS, "NoSuchApp").as_deref(),
            Some("ms-resource:PackageName")
        );
    }

    #[test]
    fn a_manifest_that_does_not_parse_answers_nothing() {
        assert_eq!(manifest_display_name("<Package", "App"), None);
    }

    #[test]
    fn a_literal_is_not_a_resource() {
        assert_eq!(resource_uris("WinUI 3 Gallery", "Pkg"), None);
        assert_eq!(resource_uris("", "Pkg"), None);
        assert_eq!(resource_uris("ms-res", "Pkg"), None);
    }

    #[test]
    fn a_rooted_path_has_one_reading() {
        let pkg = "Microsoft.WindowsTerminal";
        let full = vec!["ms-resource://Microsoft.WindowsTerminal/Resources/AppName".to_string()];

        assert_eq!(resource_uris("ms-resource:/Resources/AppName", pkg), Some(full.clone()));
        assert_eq!(resource_uris("ms-resource:///Resources/AppName", pkg), Some(full));
    }

    #[test]
    fn a_relative_path_is_tried_in_the_default_map_first_then_at_the_root() {
        assert_eq!(
            resource_uris("ms-resource:AppName/Text", "Microsoft.ScreenSketch"),
            Some(vec![
                "ms-resource://Microsoft.ScreenSketch/Resources/AppName/Text".to_string(),
                "ms-resource://Microsoft.ScreenSketch/AppName/Text".to_string(),
            ])
        );
        assert_eq!(
            resource_uris("MS-RESOURCE:Resources/AppDisplayName", "Microsoft.Paint"),
            Some(vec![
                "ms-resource://Microsoft.Paint/Resources/Resources/AppDisplayName".to_string(),
                "ms-resource://Microsoft.Paint/Resources/AppDisplayName".to_string(),
            ])
        );
    }

    #[test]
    fn a_named_authority_is_kept() {
        assert_eq!(
            resource_uris("ms-resource://Other.Package/Resources/X", "Pkg"),
            Some(vec!["ms-resource://Other.Package/Resources/X".to_string()])
        );
    }

    /// The packaged path reads a `PACKAGE_ID` out of a byte buffer with
    /// pointer arithmetic, so it gets exercised against every package
    /// actually installed here rather than a hand-picked one.
    #[test]
    fn packaged_apps_resolve_without_crashing() {
        let root = std::env::var("ProgramFiles").unwrap_or_else(|_| String::from(r"C:\Program Files"));
        let apps = std::path::PathBuf::from(root).join("WindowsApps");
        let Ok(entries) = std::fs::read_dir(&apps) else {
            // Unreadable without elevation - nothing to assert, and saying so
            // beats a test that silently checks nothing.
            eprintln!("skipped: {} is not readable", apps.display());
            return;
        };

        let mut checked = 0usize;
        for entry in entries.flatten().take(200) {
            let Some(full_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let _ = package_publisher(&full_name);
            let _ = resolve("", &full_name, "App");
            checked += 1;
        }
        eprintln!("checked {checked} packages");
    }

    /// Every argument being empty or nonsense must be an answer, not a crash.
    #[test]
    fn nonsense_input_is_answered_not_crashed() {
        assert_eq!(package_publisher(""), None);
        assert_eq!(package_publisher("not-a-package"), None);
        assert_eq!(resolve("", "", ""), None);

        // A path that does not exist still gets a shell name: SHGetFileInfo
        // is asked with USEFILEATTRIBUTES, so it answers from the name alone
        // without touching the disk. Deliberate - it keeps the call cheap and
        // still names a process whose image has since been deleted.
        assert_eq!(
            resolve(r"C:\does\not\exist.exe", "", ""),
            Some(String::from("exist.exe"))
        );
    }
}
