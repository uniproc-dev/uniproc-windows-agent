use std::collections::BTreeMap;

use serde_json::{Value, json};

#[derive(Default)]
struct Redactor {
    names: BTreeMap<String, String>,
    changed: usize,
}

pub fn apply(report: &mut Value, include_sensitive: bool) {
    if include_sensitive {
        if report.get("privacy").is_none() {
            report["privacy"] = json!({"mode":"sensitive","explicit_opt_in":true});
        }
        return;
    }
    let mut redactor = Redactor::default();
    redactor.visit(report, &mut Vec::new());
    report["privacy"] = json!({"mode":"pseudonymized","policy_version":1,"processor_version":env!("CARGO_PKG_VERSION"),"processor_commit":env!("UNIPROC_BUILD_COMMIT"),"replacements":redactor.changed,"scope":"per report; mapping is not exported","retained":"numeric metrics, timestamps, hardware models, OS and driver versions can still fingerprint a machine","raw_text":"identity, arguments, paths and free-form error text are replaced; numeric raw values are unchanged"});
}

impl Redactor {
    fn name(&mut self, kind: &str, value: &str) -> String {
        if value.is_empty() {
            return String::new();
        }
        self.changed += 1;
        if let Some(alias) = self.names.get(value) {
            return alias.clone();
        }
        let alias = format!("anon-{kind}-{}", self.names.len() + 1);
        self.names.insert(value.into(), alias.clone());
        alias
    }

    fn visit(&mut self, value: &mut Value, path: &mut Vec<String>) {
        if path
            .first()
            .is_some_and(|s| matches!(s.as_str(), "catalog" | "privacy"))
        {
            return;
        }
        match value {
            Value::Object(map) => {
                if path
                    .first()
                    .is_some_and(|s| matches!(s.as_str(), "fields" | "issues"))
                    && map.contains_key("path")
                    && map.contains_key("raw")
                {
                    let original = map["path"].as_str().unwrap_or("").to_owned();
                    let mut virtual_path: Vec<String> = original
                        .split('/')
                        .skip(1)
                        .map(|s| s.replace("~1", "/").replace("~0", "~"))
                        .collect();
                    let previous = map["raw"].clone();
                    self.visit(&mut map["raw"], &mut virtual_path);
                    if previous != map["raw"] {
                        map.insert("redacted".into(), json!(true));
                        if map.contains_key("formatted") {
                            map.insert("formatted".into(), map["raw"].clone());
                        }
                    }
                    if let Some(reason) = map.get_mut("reason") {
                        self.reason(reason);
                    }
                    map.insert("path".into(), Value::String(self.field_path(&original)));
                    return;
                }
                let old = std::mem::take(map);
                for (key, mut child) in old {
                    let new_key = if path
                        .last()
                        .is_some_and(|s| s == "service_statuses_after_samples")
                    {
                        self.name("service", &key)
                    } else {
                        key.clone()
                    };
                    path.push(key);
                    self.visit(&mut child, path);
                    path.pop();
                    map.insert(new_key, child);
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter_mut().enumerate() {
                    path.push(index.to_string());
                    self.visit(child, path);
                    path.pop();
                }
            }
            Value::String(text) => {
                if let Some(kind) = sensitive(path, text) {
                    *text = self.name(kind, text);
                }
            }
            _ => {}
        }
    }

    fn field_path(&mut self, path: &str) -> String {
        let mut parts: Vec<_> = path.split('/').map(str::to_owned).collect();
        if parts.get(1).is_some_and(|s| s == "samples")
            && parts.get(3).is_some_and(|s| s == "services")
            && parts.len() > 4
        {
            let name = parts[4].replace("~1", "/").replace("~0", "~");
            parts[4] = self.name("service", &name);
        }
        if parts.get(1).is_some_and(|s| s == "service_statuses") && parts.len() > 2 {
            let name = parts[2].replace("~1", "/").replace("~0", "~");
            parts[2] = self.name("service", &name);
        }
        parts.join("/")
    }

    fn reason(&mut self, value: &mut Value) {
        if let Some(text) = value.as_str() {
            if !matches!(
                text,
                "provider returned its no-data sentinel"
                    | "driver uses zero for an unreported reading"
                    | "not supplied; this API does not expose a per-field failure reason"
                    | "temperature lies outside the diagnostic plausibility range"
                    | "counter decreased; no rate inferred across this interval"
                    | "available physical memory exceeds total"
                    | "committed memory exceeds its limit"
                    | "idle time exceeds kernel time, which includes idle"
            ) {
                *value = Value::String(self.name("message", text));
            }
        }
    }
}

fn sensitive(path: &[String], value: &str) -> Option<&'static str> {
    let key = path.last().map(String::as_str).unwrap_or("");
    let inside = |name: &str| path.iter().any(|s| s == name);
    if matches!(key, "error" | "snapshot_error") {
        return Some("message");
    }
    if matches!(
        key,
        "user" | "account" | "computer_name" | "hostname" | "serial_number" | "mac_address"
    ) {
        return Some("identity");
    }
    if matches!(key, "path" | "image_path") {
        return Some("path");
    }
    if inside("cmdline") {
        return Some("argument");
    }
    if key == "id"
        && !["disk:", "interface:", "CPU", "VideoController"]
            .iter()
            .any(|prefix| {
                value.strip_prefix(prefix).is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                })
            })
    {
        return Some("device");
    }
    let private = inside("processes")
        || inside("states")
        || inside("events")
        || inside("services")
        || inside("service_statuses")
        || inside("service_statuses_after_samples");
    if private {
        if inside("wanted")
            && inside("processes")
            && uniproc_windows_agent::api::ProcessMetrics::all()
                .iter()
                .any(|metric| format!("{metric:?}") == value)
        {
            return None;
        }
        if enum_value(key, value) {
            return None;
        }
        if key == "name" && inside("services") || inside("Started") && inside("services") {
            return Some("service");
        }
        return Some("text");
    }
    if inside("network_adapters") && key == "name" {
        return Some("network-label");
    }
    if value.contains(":\\") || value.starts_with("\\\\") || value.contains(":/") {
        return Some("path");
    }
    None
}

fn enum_value(key: &str, value: &str) -> bool {
    matches!(key,"architecture"|"signature"|"uac_virtualization"|"isolation"|"dpi_awareness"|"stack_protection"|"extended_cfg"|"io_priority"|"base_priority"|"state"|"startup_type"|"category"|"status") &&
        "Unknown X86 X64 Arm Arm64 Arm64X86Compatible Arm64X64Compatible Unsigned Microsoft ThirdParty NotAllowed Disabled Enabled None AppContainer Uwp Silo Unaware System PerMonitor PerMonitorV2 UnawareGdiScaled Off Compatible Strict CompatibleAudit StrictAudit Audit On VeryLow Low Normal High Critical Idle BelowNormal AboveNormal Realtime Stopped StartPending StopPending Running ContinuePending PausePending Paused Boot Automatic Manual available unavailable unknown error cpu gpu memory storage".split_whitespace().any(|v|v == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_and_secrets_are_removed_from_every_copy() {
        let secret = "example-private-token";
        let user = "ExampleUser-Private";
        let service = "ExampleHost-Private";
        let path = "C:\\Users\\ExampleUser-Private\\app.exe";
        let mut report = json!({"catalog":{"description":"public schema"},"raw_samples":[{"snapshot":{"processes":{"value":[{"user":user,"image_path":path,"cmdline":[path,secret],"architecture":"X64"}]},"services":{"value":[{"name":service,"account":user,"image_path":path}]}}}],"service_statuses_after_samples":{service:{"status":"available","value":{"state":"Running"}}},"events":[{"events":[{"kind":{"Started":{"user":user,"cmdline":[secret],"services":[service]}}}]}],"health_after":{"snapshot_error":format!("failed {secret} at {path}")},"fields":[{"path":format!("/samples/0/services/{service}/account"),"raw":user,"formatted":user},{"path":"/samples/0/processes/7:99/info/image_path","raw":path,"formatted":path}],"issues":[{"path":format!("/samples/0/services/{service}/account"),"raw":user,"reason":format!("error for {user}")}],"numeric":18446744073709551615u64});
        report["service_statuses_after_samples"] = json!(BTreeMap::from([(
            service,
            json!({"status":"available","value":{"state":"Running"}})
        )]));
        apply(&mut report, false);
        let text = serde_json::to_string(&report).unwrap();
        for private in [secret, user, service, "C:\\\\Users"] {
            assert!(!text.contains(private), "leaked {private}");
        }
        assert_eq!(report["numeric"], json!(u64::MAX));
        assert_eq!(
            report["raw_samples"][0]["snapshot"]["processes"]["value"][0]["architecture"],
            "X64"
        );
        assert_eq!(report["fields"][0]["raw"], report["issues"][0]["raw"]);
        assert_eq!(report["fields"][0]["path"], report["issues"][0]["path"]);
        assert_eq!(
            report["fields"][1]["raw"],
            report["raw_samples"][0]["snapshot"]["processes"]["value"][0]["image_path"]
        );
    }

    #[test]
    fn sensitive_output_requires_an_explicit_opt_in() {
        let mut report = json!({"raw_samples":[{"processes":[{"user":"PrivateUser"}]}]});
        apply(&mut report, true);
        assert_eq!(
            report["raw_samples"][0]["processes"][0]["user"],
            "PrivateUser"
        );
        assert_eq!(report["privacy"]["mode"], "sensitive");
    }

    #[test]
    fn only_numeric_local_device_ids_are_exempt() {
        let path = vec!["system".into(), "cpu".into(), "id".into()];
        assert_eq!(sensitive(&path, "CPU0"), None);
        assert_eq!(sensitive(&path, "CPU-private-serial"), Some("device"));
    }

    #[test]
    #[ignore = "requires UNIPROC_DIAGNOSTIC_REPORT pointing to a saved native dump"]
    fn native_capture_removes_identities_without_changing_counters() {
        let path =
            std::env::var_os("UNIPROC_DIAGNOSTIC_REPORT").expect("set the native report path");
        let mut report: Value =
            serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();
        let samples = report["raw_samples"].as_array().unwrap();
        let counters: Vec<_> = samples
            .iter()
            .map(|s| s["sample"]["columns"].clone())
            .collect();
        let wanted: Vec<_> = samples
            .iter()
            .map(|s| s["sample"]["wanted"].clone())
            .collect();
        let mut identities = std::collections::BTreeSet::new();
        for sample in samples {
            for process in sample["snapshot"]["processes"]["value"].as_array().unwrap() {
                for key in ["user", "image_path"] {
                    if let Some(value) = process[key]
                        .as_str()
                        .filter(|v| !v.is_empty() && (key == "user" || v.contains(":\\")))
                    {
                        identities.insert(value.to_owned());
                    }
                }
            }
        }
        apply(&mut report, false);
        apply(&mut report, false);
        fn check(value: &Value, identities: &std::collections::BTreeSet<String>) {
            match value {
                Value::String(text) => assert!(
                    !identities.contains(text),
                    "an original identity or path survived redaction"
                ),
                Value::Array(items) => items.iter().for_each(|v| check(v, identities)),
                Value::Object(items) => items.values().for_each(|v| check(v, identities)),
                _ => {}
            }
        }
        check(&report, &identities);
        for (index, sample) in report["raw_samples"].as_array().unwrap().iter().enumerate() {
            assert_eq!(sample["sample"]["columns"], counters[index]);
            assert_eq!(sample["sample"]["wanted"], wanted[index]);
        }
        println!(
            "Native report privacy audit passed; all raw counter columns and requested metrics preserved"
        );
    }
}
