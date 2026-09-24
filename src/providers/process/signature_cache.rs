use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use amethystate::store::builder::Backend;
use amethystate::store::config::AfterGivingUp;
use amethystate::store::{OnUnreadable, UnreadableEntries, WillNotOpen};
use amethystate::{ReactiveMap, Store, StoreBuilder, amethystate};

use crate::state::events::ProcessSignature;

/// Which resolver produced a verdict. Raised whenever the way a verdict is
/// worked out changes, so entries an older build wrote are recomputed instead
/// of served - the file they describe has not changed, the answer has.
pub const RESOLVER: u32 = 3;

#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CachedVerdict {
    pub signature: u8,
    pub is_windows_process: bool,
    pub display_name: String,
    pub size: u64,
    pub modified_ms: u64,
    #[serde(default)]
    pub resolver: u32,
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

pub fn file_stamp(path: &str) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis() as u64;
    Some((meta.len(), modified))
}

fn store_path() -> PathBuf {
    let root = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    root.join("Uniproc").join("signature-cache")
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

pub fn open() -> Option<PersistentSignatures> {
    let path = store_path();
    if let Some(parent) = path.parent()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        tracing::warn!(%err, "could not create the signature cache directory");
        return None;
    }

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
    /// Whether this verdict still answers for the file: the same size and
    /// modification time, worked out by the resolver this build runs.
    fn describes(&self, stamp: (u64, u64)) -> bool {
        self.size == stamp.0 && self.modified_ms == stamp.1 && self.resolver == RESOLVER
    }
}

impl SignatureCache {
    pub fn lookup(&self, path: &str, stamp: (u64, u64)) -> Option<CachedVerdict> {
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

    fn verdict(size: u64) -> CachedVerdict {
        CachedVerdict {
            signature: 3,
            is_windows_process: false,
            display_name: "probe".to_string(),
            size,
            modified_ms: 1,
            resolver: RESOLVER,
        }
    }

    #[test]
    fn a_verdict_answers_for_the_file_it_was_worked_out_from() {
        assert!(verdict(10).describes((10, 1)));
    }

    #[test]
    fn a_changed_file_is_recomputed() {
        assert!(!verdict(10).describes((11, 1)), "size changed");
        assert!(!verdict(10).describes((10, 2)), "modified since");
    }

    #[test]
    fn a_verdict_an_older_resolver_wrote_is_recomputed() {
        let stale = CachedVerdict {
            resolver: RESOLVER - 1,
            ..verdict(10)
        };
        assert!(!stale.describes((10, 1)));
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
