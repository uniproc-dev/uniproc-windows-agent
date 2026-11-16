use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use crate::bindings::{
    DeviceIoControl, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FSCTL_READ_FILE_USN_DATA, FileIdInfo, GetFileInformationByHandleEx, HANDLE,
};

use amethystate::store::builder::Backend;
use amethystate::store::{OnUnreadable, StorePath, UnreadableEntries, WillNotOpen};
use amethystate::{Store, StoreBuilder};
#[cfg(test)]
use amethystate::{ReactiveMap, amethystate};

use crate::state::events::ProcessSignature;

/// Which resolver produced a verdict. Raised whenever the way a verdict is
/// worked out changes, so entries an older build wrote are recomputed instead
/// of served - the file they describe has not changed, the answer has.
pub const RESOLVER: u32 = 7;

pub(super) const TTL: Duration = Duration::from_secs(24 * 60 * 60);

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub(super) fn fresh(saved_at_ms: u64, now: u64) -> bool {
    saved_at_ms != 0 && now.checked_sub(saved_at_ms).is_some_and(|age| age < TTL.as_millis() as u64)
}

fn expired(saved_at_ms: u64, now: u64) -> bool {
    saved_at_ms == 0 || now.checked_sub(saved_at_ms).is_some_and(|age| age >= TTL.as_millis() as u64)
}

#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CachedVerdict {
    #[serde(default)]
    pub saved_at_ms: u64,
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

#[cfg(test)]
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
        .disk(|d| d.debounce(Duration::from_secs(5)))
}

pub struct PersistentSignatures {
    store: Store,
}

impl Drop for PersistentSignatures {
    fn drop(&mut self) {
        if let Err(error) = self.store.save_now() {
            tracing::warn!(%error, "could not flush the signature cache");
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

    Some(PersistentSignatures { store })
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

impl PersistentSignatures {
    pub fn lookup(&self, path: &str, stamp: Stamp) -> Option<CachedVerdict> {
        self.lookup_at(path, stamp, now_ms())
    }

    fn lookup_at(&self, path: &str, stamp: Stamp, now: u64) -> Option<CachedVerdict> {
        match self.store.get::<CachedVerdict>(["signatures", "verdicts", path]) {
            Ok(Some(cached)) if expired(cached.saved_at_ms, now) => {
                if let Err(error) = self.store.delete(["signatures", "verdicts", path]) {
                    tracing::warn!(%error, path, "could not remove an expired signature verdict");
                }
                None
            }
            Ok(cached) => cached.filter(|cached| cached.describes(stamp) && fresh(cached.saved_at_ms, now)),
            Err(error) => {
                tracing::warn!(%error, path, "could not read a signature verdict");
                None
            }
        }
    }

    pub fn remember(&self, path: &str, verdict: CachedVerdict) {
        if let Err(err) = self.store.set(["signatures", "verdicts", path], &verdict) {
            tracing::warn!(%err, path, "could not persist a signature verdict");
        }
    }

    pub(super) fn cleanup(&self) {
        self.cleanup_at(now_ms());
    }

    fn cleanup_at(&self, now: u64) -> usize {
        let prefix = StorePath::from_segments(["signatures", "verdicts"]);
        let keys = match self.store.scan_keys(&prefix) {
            Ok(keys) => keys,
            Err(error) => {
                tracing::warn!(%error, "could not list signature verdicts for expiry");
                return 0;
            }
        };
        let mut removed = 0;
        for key in keys {
            if key.len() != prefix.len() + 1 || prefix.entry_name(&key).is_none() {
                continue;
            }
            match self.store.get::<CachedVerdict>(&key) {
                Ok(Some(cached)) if expired(cached.saved_at_ms, now) => {
                    match self.store.delete(&key) {
                        Ok(()) => removed += 1,
                        Err(error) => tracing::warn!(%error, "could not remove an expired signature verdict"),
                    }
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "could not read a signature verdict for expiry"),
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_lifetime_is_one_day_from_write_time() {
        let saved = 1_000;
        let day = TTL.as_millis() as u64;
        assert!(fresh(saved, saved));
        assert!(fresh(saved, saved + day - 1));
        assert!(!fresh(saved, saved + day));
        assert!(!fresh(saved, saved + day + 1));
        assert!(!fresh(0, saved));
        assert!(!fresh(saved + 1, saved));
        let mut legacy = serde_json::to_value(verdict(stamp())).unwrap();
        legacy.as_object_mut().unwrap().remove("saved_at_ms");
        let legacy: CachedVerdict = serde_json::from_value(legacy).unwrap();
        assert!(!fresh(legacy.saved_at_ms, now_ms()));
    }

    #[test]
    fn expired_reads_delete_persisted_entries_without_renewing_hits() {
        let directory = std::env::temp_dir().join(format!("uniproc-signature-expiry-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("cache");
        let saved = 1_000;
        let day = TTL.as_millis() as u64;
        {
            let cache = PersistentSignatures { store: builder(path.clone()).build().unwrap() };
            let entry = CachedVerdict { saved_at_ms: saved, ..verdict(stamp()) };
            cache.remember("old.exe", entry.clone());
            assert_eq!(cache.lookup_at("old.exe", stamp(), saved + day - 1), Some(entry.clone()));
            assert_eq!(cache.store.get::<CachedVerdict>(["signatures", "verdicts", "old.exe"]).unwrap(), Some(entry));
            assert_eq!(cache.lookup_at("old.exe", stamp(), saved + day), None);
            assert_eq!(cache.store.get::<CachedVerdict>(["signatures", "verdicts", "old.exe"]).unwrap(), None);
        }
        {
            let store = builder(path).build().unwrap();
            assert_eq!(store.get::<CachedVerdict>(["signatures", "verdicts", "old.exe"]).unwrap(), None);
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cleanup_removes_only_expired_direct_entries_and_persists_deletions() {
        let directory = std::env::temp_dir().join(format!("uniproc-signature-cleanup-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("cache");
        let day = TTL.as_millis() as u64;
        let now = day * 2;
        {
            let cache = PersistentSignatures { store: builder(path.clone()).build().unwrap() };
            for (name, saved) in [("expired", day), ("fresh", day + 1), ("future", now + 1), ("missing", 0)] {
                cache.remember(name, CachedVerdict { saved_at_ms: saved, ..verdict(stamp()) });
            }
            let expired = CachedVerdict { saved_at_ms: day, ..verdict(stamp()) };
            cache.store.set(["signatures", "verdicts", "deep", "entry"], &expired).unwrap();
            cache.store.set(["signatures", "verdicts-neighbor", "entry"], &expired).unwrap();
            cache.store.set(["signatures", "verdicts", "corrupt"], &42u32).unwrap();
            cache.store.save_now().unwrap();
            assert_eq!(cache.cleanup_at(now), 2);
            assert_eq!(cache.cleanup_at(now), 0);
            assert_eq!(cache.lookup_at("future", stamp(), now), None);
            assert!(cache.store.get::<CachedVerdict>(["signatures", "verdicts", "future"]).unwrap().is_some());
        }
        {
            let store = builder(path).build().unwrap();
            for name in ["expired", "missing"] {
                assert_eq!(store.get::<CachedVerdict>(["signatures", "verdicts", name]).unwrap(), None);
            }
            for name in ["fresh", "future"] {
                assert!(store.get::<CachedVerdict>(["signatures", "verdicts", name]).unwrap().is_some());
            }
            assert!(store.get::<CachedVerdict>(["signatures", "verdicts", "deep", "entry"]).unwrap().is_some());
            assert!(store.get::<CachedVerdict>(["signatures", "verdicts-neighbor", "entry"]).unwrap().is_some());
            assert_eq!(store.get::<u32>(["signatures", "verdicts", "corrupt"]).unwrap(), Some(42));
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

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
            saved_at_ms: now_ms(),
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
    fn point_access_preserves_legacy_entries_and_flushes_updates() {
        let directory = std::env::temp_dir().join(format!("uniproc-lazy-signatures-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("cache");
        let original = r"C:\Программы\app.v1\old.exe";
        let added = r"D:\other.app\new.exe";
        let cached = verdict(stamp());
        {
            let store = builder(path.clone()).build().unwrap();
            let legacy = SignatureCache::try_new_with(&store).unwrap();
            legacy.verdicts().insert(original.to_string(), &cached).unwrap();
            store.set(["unrelated", "entry"], &42u32).unwrap();
            store.save_now().unwrap();
        }
        {
            let cache = PersistentSignatures { store: builder(path.clone()).build().unwrap() };
            assert_eq!(cache.lookup(original, stamp()), Some(cached.clone()));
            assert_eq!(cache.lookup(original, Stamp { usn: 901, ..stamp() }), None);
            assert_eq!(cache.lookup(added, stamp()), None);
            cache.remember(added, cached.clone());
            assert_eq!(cache.lookup(added, stamp()), Some(cached.clone()));
            cache.store.set(["signatures", "verdicts", "malformed"], &42u32).unwrap();
            assert_eq!(cache.lookup("malformed", stamp()), None);
        }
        {
            let store = builder(path).build().unwrap();
            let legacy = SignatureCache::try_new_with(&store).unwrap();
            assert_eq!(legacy.verdicts().get(original), Some(cached.clone()));
            assert_eq!(legacy.verdicts().get(added), Some(cached));
            assert_eq!(store.get::<u32>(["unrelated", "entry"]).unwrap(), Some(42));
        }
        std::fs::remove_dir_all(directory).unwrap();
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
