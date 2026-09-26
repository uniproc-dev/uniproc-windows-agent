use std::time::Duration;

use uniproc_windows_core::SupervisorConfig;

/// Memory is read this often while someone watches.
pub const ATTACHED_MEMORY_INTERVAL: Duration = Duration::from_millis(1000);

/// And this often while nobody does.
#[cfg(feature = "service")]
pub const IDLE_MEMORY_INTERVAL: Duration = Duration::from_millis(2000);

/// The service's sessions and store: the plain names.
#[cfg(feature = "service")]
pub fn service() -> SupervisorConfig {
    SupervisorConfig {
        session_namespace: None,
        signature_store: "signature-cache".to_string(),
    }
}

/// An agent inside the caller's process, beside the service without touching it.
pub fn embedded() -> SupervisorConfig {
    SupervisorConfig {
        session_namespace: Some("Uniproc-Embedded-".to_string()),
        signature_store: "signature-cache-embedded".to_string(),
    }
}
