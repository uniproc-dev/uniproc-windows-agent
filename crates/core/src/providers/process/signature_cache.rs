use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use windows::Win32::{
    DeviceIoControl, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FSCTL_READ_FILE_USN_DATA, FileIdInfo, GetFileInformationByHandleEx, HANDLE,
};

use amethystate::store::builder::Backend;
use amethystate::store::config::AfterGivingUp;
use amethystate::store::{OnUnreadable, UnreadableEntries, WillNotOpen};
use amethystate::{ReactiveMap, Store, StoreBuilder, amethystate};

use crate::state::events::ProcessSignature;

/// Which resolver produced a verdict. Raised whenever the way a verdict is
/// worked out changes, so entries an older build wrote are recomputed instead
/// of served - the file they describe has not changed, the answer has.
pub const RESOLVER: u32 = 7;

#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CachedVerdict {
    pub signature: u8,
    pub is_windows_process: bool,
    pub display_name: String,
    #[serde(default)]
    pub signer: String,
    pub size: u64,
    pub modified_ms: u64,
    #[serde(default)]
    pub resolver: u32,
    #[serde(default)]
    pub file_id: [u64; 2],
    #[serde(default)]
    pub usn: i64,
}

/// What tells one version of a file from another. Size and modification
/// time can be set by whoever writes the file; the file id changes when it
/// is replaced, and the volume's change journal moves the USN on every
/// write, which nobody sets by hand.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stamp {
    pub size: u64,
    pub modified_ms: u64,
    pub file_id: [u64; 2],
    pub usn: i64,
}

#[amethystate(prefix = "signatures")]
pub struct SignatureCache {
    #[amestate(default = {})]
    verdicts: ReactiveMap<String, CachedVerdict>,
}

pub fn signature_to_code(signature: ProcessSignature) -> u8 {
    match signature {
        ProcessSignature::Unknown => 0,
        ProcessSignature::Unsigned => 1,
        ProcessSignature::Microsoft => 2,
        ProcessSignature::ThirdParty => 3,
    }
}

pub fn signature_from_code(code: u8) -> ProcessSignature {
    match code {
        1 => ProcessSignature::Unsigned,
        2 => ProcessSignature::Microsoft,
        3 => ProcessSignature::ThirdParty,
        _ => ProcessSignature::Unknown,
    }
}

/// The file's stamp, read through a handle that may only read attributes.
/// The USN is 0 on a volume without a change journal.
pub fn file_stamp(path: &str) -> Option<Stamp> {
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES as u32)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u32)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    let modified_ms = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_millis() as u64;
    let handle = HANDLE(file.as_raw_handle());

    let mut id = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .ok()
    .ok()?;
    let bytes = id.FileId.Identifier;
    let file_id = [
        u64::from_le_bytes(bytes[..8].try_into().ok()?),
        u64::from_le_bytes(bytes[8..].try_into().ok()?),
    ];

    Some(Stamp {
        size: meta.len(),
        modified_ms,
        file_id,
        usn: last_usn(handle).unwrap_or(0),
    })
}

/// The USN of the last change the volume's journal recorded for the file.
fn last_usn(file: HANDLE) -> Option<i64> {
    let mut record = [0u64; 128];
    let mut returned = 0u32;
    unsafe {
        DeviceIoControl(
            file,
            FSCTL_READ_FILE_USN_DATA as u32,
            None,
            0,
            Some(record.as_mut_ptr().cast()),
            (record.len() * 8) as u32,
            Some(&mut returned),
            None,
        )
    }
    .ok()
    .ok()?;
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(record.as_ptr().cast(), returned as usize) };
    let at = match u16::from_le_bytes(bytes.get(4..6)?.try_into().ok()?) {
        2 => 24,
        3 => 40,
        _ => return None,
    };
    Some(i64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// Where the store `name` lives, with the files its backends write claimed
/// for the agent.
fn store_path(name: &str) -> std::io::Result<PathBuf> {
    for extension in ["redb", "meta", "json"] {
        crate::data::claim(&format!("{name}.{extension}"))?;
    }
    Ok(crate::data::dir()?.join(name))
}

fn builder(path: PathBuf) -> StoreBuilder {
    StoreBuilder::new(path)
        .backend(Backend::Redb)
        .when_it_will_not_open(WillNotOpen::StartFresh)
        .rules(|r| {
            r.on_unreadable(OnUnreadable::UseDefault)
                .unreadable_entries(UnreadableEntries::Skip)
        })
        .disk(|d| {
            d.debounce(Duration::from_secs(5))
                .on_failure(|_| AfterGivingUp::Ignore)
        })
}

pub struct PersistentSignatures {
    _store: Store,
    cache: SignatureCache,
}

impl PersistentSignatures {
    pub fn cache(&self) -> &SignatureCache {
        &self.cache
    }
}

impl Drop for PersistentSignatures {
    fn drop(&mut self) {
        let entries = self.cache.verdicts().len();
        match self._store.save_now() {
            Ok(()) => tracing::warn!(entries, "drop probe: final save ok"),
            Err(err) => tracing::warn!(%err, entries, "drop probe: final save FAILED"),
        }
    }
}

pub fn open(name: &str) -> Option<PersistentSignatures> {
    let path = match store_path(name) {
        Ok(path) => path,
        Err(err) => {
            tracing::warn!(%err, "the signature cache stays in memory: the agent's directory is not its own");
            return None;
        }
    };

    let store = match builder(path).build() {
        Ok(store) => store,
        Err(err) => {
            tracing::warn!(%err, "could not open the signature cache store");
            return None;
        }
    };

    let cache = match SignatureCache::new_with(&store) {
        Ok(cache) => cache,
        Err(err) => {
            tracing::warn!(%err, "could not open the signature cache");
            return None;
        }
    };

    tracing::warn!(
        loaded = cache.verdicts().len(),
        "signature cache opened"
    );

    Some(PersistentSignatures {
        _store: store,
        cache,
    })
}

impl CachedVerdict {
    /// Whether this verdict still answers for the file: the same stamp, a
    /// change journal behind it, worked out by the resolver this build runs.
    fn describes(&self, stamp: Stamp) -> bool {
        stamp.usn != 0
            && self.size == stamp.size
            && self.modified_ms == stamp.modified_ms
            && self.file_id == stamp.file_id
            && self.usn == stamp.usn
            && self.resolver == RESOLVER
    }
}

impl SignatureCache {
    pub fn lookup(&self, path: &str, stamp: Stamp) -> Option<CachedVerdict> {
        self.verdicts().get(path).filter(|cached| cached.describes(stamp))
    }

    pub fn remember(&self, path: &str, verdict: CachedVerdict) {
        if let Err(err) = self.verdicts().insert(path.to_string(), &verdict) {
            tracing::warn!(%err, path, "could not persist a signature verdict");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cache_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PersistentSignatures>();
    }

    fn stamp() -> Stamp {
        Stamp {
            size: 10,
            modified_ms: 1,
            file_id: [7, 0],
            usn: 900,
        }
    }

    fn verdict(stamp: Stamp) -> CachedVerdict {
        CachedVerdict {
            signature: 3,
            is_windows_process: false,
            display_name: "probe".to_string(),
            signer: "CN=Probe".to_string(),
            size: stamp.size,
            modified_ms: stamp.modified_ms,
            resolver: RESOLVER,
            file_id: stamp.file_id,
            usn: stamp.usn,
        }
    }

    #[test]
    fn a_verdict_answers_for_the_file_it_was_worked_out_from() {
        assert!(verdict(stamp()).describes(stamp()));
    }

    #[test]
    fn a_changed_file_is_recomputed() {
        let cached = verdict(stamp());
        assert!(!cached.describes(Stamp { size: 11, ..stamp() }), "size changed");
        assert!(!cached.describes(Stamp { modified_ms: 2, ..stamp() }), "modified since");
        assert!(!cached.describes(Stamp { file_id: [8, 0], ..stamp() }), "another file at the path");
        assert!(!cached.describes(Stamp { usn: 901, ..stamp() }), "written with size and time put back");
    }

    #[test]
    fn a_volume_without_a_change_journal_is_never_served_from_the_cache() {
        let unjournaled = Stamp { usn: 0, ..stamp() };
        assert!(!verdict(unjournaled).describes(unjournaled));
    }

    #[test]
    fn a_verdict_an_older_resolver_wrote_is_recomputed() {
        let stale = CachedVerdict {
            resolver: RESOLVER - 1,
            ..verdict(stamp())
        };
        assert!(!stale.describes(stamp()));
    }

    #[test]
    fn a_write_that_puts_size_and_time_back_moves_the_stamp() {
        let path = std::env::temp_dir().join(format!("uniproc-stamp-{}.bin", std::process::id()));
        std::fs::write(&path, b"first").unwrap();
        let path_text = path.to_str().unwrap();
        let before = file_stamp(path_text).expect("stamp");
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();

        std::fs::write(&path, b"other").unwrap();
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(modified).unwrap();
        let after = file_stamp(path_text).expect("stamp");
        std::fs::remove_file(&path).unwrap();

        assert_eq!((after.size, after.modified_ms, after.file_id), (before.size, before.modified_ms, before.file_id));
        if before.usn != 0 {
            assert_ne!(after.usn, before.usn, "the change journal saw the write");
        }
    }

    #[test]
    fn every_signature_survives_the_round_trip() {
        for signature in [
            ProcessSignature::Unknown,
            ProcessSignature::Unsigned,
            ProcessSignature::Microsoft,
            ProcessSignature::ThirdParty,
        ] {
            assert_eq!(signature_from_code(signature_to_code(signature)), signature);
        }
    }

    #[test]
    fn an_unknown_code_reads_back_as_unknown() {
        assert_eq!(signature_from_code(200), ProcessSignature::Unknown);
    }
}
