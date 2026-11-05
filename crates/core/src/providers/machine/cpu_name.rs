use std::io;
use std::sync::OnceLock;

use smol_str::SmolStr;
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

pub fn read() -> Option<SmolStr> {
    static NAME: OnceLock<Option<SmolStr>> = OnceLock::new();
    cached(&NAME, || {
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")?
            .get_value("ProcessorNameString")
    })
}

fn cached(
    cache: &OnceLock<Option<SmolStr>>,
    load: impl FnOnce() -> io::Result<String>,
) -> Option<SmolStr> {
    cache
        .get_or_init(|| {
            let value = load().ok()?;
            let value = value.trim();
            (!value.is_empty()).then(|| SmolStr::new(value))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn processor_name_is_trimmed_without_rewriting_the_brand_string() {
        let value = cached(&OnceLock::new(), || {
            Ok("  AMD Ryzen 9  9950X 16-Core Processor \t\r\n".into())
        });
        assert_eq!(
            value.as_deref(),
            Some("AMD Ryzen 9  9950X 16-Core Processor")
        );
        assert!(cached(&OnceLock::new(), || Ok(" \t\r\n".into())).is_none());
    }

    #[test]
    fn available_and_missing_names_are_both_read_only_once() {
        for value in [Some("CPU"), Some("  "), None] {
            let cache = OnceLock::new();
            let calls = Cell::new(0);
            let mut results = Vec::new();
            for _ in 0..3 {
                results.push(cached(&cache, || {
                    calls.set(calls.get() + 1);
                    value
                        .map(str::to_owned)
                        .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))
                }));
            }
            assert_eq!(calls.get(), 1);
            let expected = value.filter(|value| !value.trim().is_empty());
            assert!(results.iter().all(|result| result.as_deref() == expected));
        }
    }
}
