use uniproc_windows_core::SupervisorConfig;

/// The service's sessions and store: the plain names.
pub fn service() -> SupervisorConfig {
    SupervisorConfig {
        session_namespace: None,
        signature_store: "signature-cache".to_string(),
    }
}

/// An agent inside an app, beside the service without touching it.
pub fn in_app() -> SupervisorConfig {
    SupervisorConfig {
        session_namespace: Some("Uniproc-Embedded-".to_string()),
        signature_store: "signature-cache-embedded".to_string(),
    }
}
