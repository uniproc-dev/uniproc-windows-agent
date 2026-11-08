use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone, Serialize)]
pub struct Field {
    pub path: String,
    pub raw: Value,
    pub unit: String,
    pub formatted: String,
    pub availability: String,
    pub validation: String,
    pub reason: Option<String>,
    pub delta: Option<Value>,
    pub rate_per_second: Option<f64>,
    pub rate_formatted: Option<String>,
    pub previous_raw: Option<Value>,
    pub interval_seconds: Option<f64>,
}

pub fn fields(value: &Value, path: &str, columns: &Value) -> Vec<Field> {
    let mut out = Vec::new();
    walk(value, path, columns, &mut out);
    out
}

fn walk(value: &Value, path: &str, columns: &Value, out: &mut Vec<Field>) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, child) in map {
                walk(
                    child,
                    &format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                    columns,
                    out,
                );
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (index, child) in items.iter().enumerate() {
                walk(child, &format!("{path}/{index}"), columns, out);
            }
        }
        _ => out.push(field(value, path, columns)),
    }
}

pub fn metadata<'a>(path: &str, columns: &'a Value) -> Option<&'a Value> {
    if !path.contains("/metrics/") {
        return None;
    }
    columns
        .as_array()?
        .iter()
        .find(|column| column["column"].as_str() == path.rsplit('/').next())
}

fn field(raw: &Value, path: &str, columns: &Value) -> Field {
    let key = path.rsplit('/').next().unwrap_or("");
    let meta = metadata(path, columns);
    let unit = meta
        .and_then(|m| m["unit"].as_str())
        .unwrap_or_else(|| unit(path, key, raw));
    let sentinel = meta.and_then(|m| m["sentinel"].as_u64());
    let unknown = raw.is_null()
        || raw
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("unknown"));
    let gap = sentinel.is_some() && raw.as_u64() == sentinel;
    let no_driver_reading = raw.as_u64() == Some(0)
        && (path.contains("/gpus/")
            && matches!(
                key,
                "temperature" | "frequency" | "max_frequency" | "memory_frequency" | "fan_rpm"
            )
            || path.contains("/cpu/") && matches!(key, "max_mhz" | "current_mhz"));
    let source_error = key == "status"
        && raw
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("error"))
        || key == "snapshot_error" && !raw.is_null()
        || matches!(key, "running" | "pumping") && path.contains("/sessions/") && raw == false;
    let unavailable = unknown
        || gap
        || no_driver_reading
        || key == "status"
            && raw
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case("unavailable"));
    let invalid_temperature = key == "celsius"
        && raw
            .as_f64()
            .is_some_and(|v| !(-273.15..=300.0).contains(&v));
    let reason = if gap {
        Some("provider returned its no-data sentinel")
    } else if no_driver_reading {
        Some("driver uses zero for an unreported reading")
    } else if unknown {
        Some("not supplied; this API does not expose a per-field failure reason")
    } else if invalid_temperature {
        Some("temperature lies outside the diagnostic plausibility range")
    } else {
        None
    };
    let loss = (key.ends_with("_lost") || key == "dropped_by_sink" || key == "lost")
        && raw.as_u64().is_some_and(|v| v > 0);
    Field {
        path: path.into(),
        raw: raw.clone(),
        unit: unit.into(),
        formatted: if unavailable {
            "unavailable".into()
        } else {
            format(raw, unit)
        },
        availability: if source_error {
            "error"
        } else if unavailable {
            "unavailable"
        } else if raw.as_array().is_some_and(Vec::is_empty) {
            "empty"
        } else {
            "available"
        }
        .into(),
        validation: if source_error || invalid_temperature {
            "invalid"
        } else if loss {
            "loss_observed"
        } else if unavailable {
            "not_checked"
        } else if unit == "unspecified" {
            "unclassified"
        } else {
            "valid"
        }
        .into(),
        reason: reason.map(str::to_owned),
        delta: None,
        rate_per_second: None,
        rate_formatted: None,
        previous_raw: None,
        interval_seconds: None,
    }
}

fn unit<'a>(path: &str, key: &str, raw: &Value) -> &'a str {
    if path.contains("/security_services_running/")
        || path.contains("/security_services_configured/")
        || path.contains("/cpuid/") && key == "model"
        || matches!(key, "ubr" | "bus_type")
    {
        return "native code";
    }
    if matches!(key, "parent_sequence_number" | "number") {
        return "identifier";
    }
    if key == "cpu_cycles" {
        return "cycles";
    }
    if key == "peak_commit" {
        return "bytes";
    }
    if matches!(key, "handles" | "hard_faults") {
        return "count";
    }
    if path.contains("/header/pids/")
        || path.contains("/header/sequence_numbers/")
        || path.contains("/changes/passports/")
        || path.contains("/changes/left/")
        || path.contains("/changes/states/")
        || path.contains("/list_tags/")
    {
        return "identifier";
    }
    if raw.is_boolean() {
        return "boolean";
    }
    if raw.is_string() {
        return "text";
    }
    if raw.is_array() || raw.is_object() {
        return "collection";
    }
    if key == "celsius" {
        return "celsius";
    }
    if key == "temperature" && path.contains("/gpus/") {
        return "0.1 celsius";
    }
    if key == "power" && path.contains("/gpus/") {
        return "0.1 percent";
    }
    if key == "fan_rpm" {
        return "rpm";
    }
    if key.ends_with("_mhz") {
        return "MHz";
    }
    if key.ends_with("frequency") {
        return "Hz";
    }
    if key.ends_with("_link_speed") || key == "speed_bps" {
        return "bit/s";
    }
    if key.ends_with("_ms") {
        return "ms";
    }
    if key.ends_with("_us") {
        return "us";
    }
    if key.ends_with("_utc") {
        return "UTC";
    }
    if key == "time" || key == "start_time" || key == "history_from" {
        return "FILETIME 100ns";
    }
    if key.ends_with("_time") || key == "sampled_at" {
        return "100ns";
    }
    if key.contains("bytes")
        || matches!(
            key,
            "working_set"
                | "private_working_set"
                | "commit"
                | "committed"
                | "total_physical"
                | "available_physical"
                | "commit_limit"
                | "dedicated_limit"
                | "dedicated_usage"
                | "shared_limit"
                | "shared_usage"
        )
    {
        return "bytes";
    }
    if matches!(
        key,
        "pid"
            | "parent_pid"
            | "session_id"
            | "sequence_number"
            | "luid"
            | "adapter_luid"
            | "row"
            | "engine"
            | "ordinal"
            | "snapshot"
            | "passport_etag"
            | "etag"
            | "console_host_pid"
            | "job_object_id"
    ) {
        return "identifier";
    }
    if key.ends_with("_count")
        || key.ends_with("_ops")
        || key.ends_with("_lost")
        || key.ends_with("_buffers")
        || matches!(
            key,
            "dropped_by_sink"
                | "buffers"
                | "buffers_written"
                | "runs"
                | "lost"
                | "handle_count"
                | "core_count"
        )
    {
        return "count";
    }
    if key == "affinity_mask" {
        return "bitmask";
    }
    if matches!(
        key,
        "signature_eax" | "max_basic_leaf" | "max_extended_leaf"
    ) {
        return "native code";
    }
    if key == "group" {
        return "identifier";
    }
    if key == "win32_error" {
        return "Win32 error code";
    }
    if matches!(
        key,
        "checkpoint"
            | "exit_code"
            | "service_exit_code"
            | "service_type"
            | "accepted_controls"
            | "architecture"
            | "family"
            | "revision"
            | "stepping"
            | "if_type"
            | "vbs_status"
            | "security_services_configured"
            | "security_services_running"
    ) {
        return "native code";
    }
    if matches!(key, "index" | "interface_index" | "console_host_pid") {
        return "identifier";
    }
    if matches!(key, "cores" | "logical_processors" | "bytes") {
        return "count";
    }
    if matches!(key, "secs" | "nanos") {
        return if key == "secs" { "s" } else { "ns" };
    }
    if raw.is_null() {
        return "unknown";
    }
    "unspecified"
}

pub fn format(raw: &Value, unit: &str) -> String {
    let Some(value) = raw.as_f64() else {
        return raw
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| raw.to_string());
    };
    match unit {
        "bytes" => {
            let mut scaled = value;
            let names = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
            let mut index = 0;
            while scaled.abs() >= 1024.0 && index < names.len() - 1 {
                scaled /= 1024.0;
                index += 1;
            }
            format!("{scaled:.2} {}", names[index])
        }
        "100ns" => format!("{:.6} s", value / 10_000_000.0),
        "ms" => format!("{:.3} s", value / 1000.0),
        "us" => format!("{:.6} s", value / 1_000_000.0),
        "MHz" => format!("{:.3} GHz", value / 1000.0),
        "Hz" => format!("{:.3} MHz", value / 1_000_000.0),
        "FILETIME 100ns" => time::OffsetDateTime::from_unix_timestamp_nanos(
            (raw.as_u64().unwrap_or(0) as i128 - 116444736000000000i128) * 100,
        )
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| format!("{raw} FILETIME 100ns")),
        "0.1 celsius" => format!("{:.1} °C", value / 10.0),
        "celsius" => format!("{value:.1} °C"),
        "0.1 percent" => format!("{:.1}%", value / 10.0),
        "count" | "identifier" | "text" | "boolean" | "collection" => raw.to_string(),
        _ => format!("{raw} {unit}"),
    }
}

pub fn rates(current: &mut [Field], previous: &[Field], seconds: f64, columns: &Value) {
    if !seconds.is_finite() || seconds <= 0.0 {
        return;
    }
    let previous: BTreeMap<_, _> = previous
        .iter()
        .map(|field| (identity(&field.path), field))
        .collect();
    for field in current {
        if field.availability != "available" {
            continue;
        }
        let meta = metadata(&field.path, columns);
        let key = field.path.rsplit('/').next().unwrap_or("");
        let cumulative = meta.map(|m| m["cumulative"] == true).unwrap_or_else(|| {
            (field.path.contains("/machine/") || field.path.contains("/gpu_engines/"))
                && (matches!(
                    key,
                    "rx_bytes"
                        | "tx_bytes"
                        | "read_bytes"
                        | "write_bytes"
                        | "read_ops"
                        | "write_ops"
                        | "running_time"
                        | "idle_time"
                        | "kernel_time"
                        | "user_time"
                        | "interrupt_time"
                        | "dpc_time"
                ))
        });
        if !cumulative {
            continue;
        }
        let Some(before) = previous
            .get(&identity(&field.path))
            .filter(|f| f.availability == "available")
        else {
            continue;
        };
        let (Some(now), Some(old)) = (field.raw.as_u64(), before.raw.as_u64()) else {
            continue;
        };
        let delta = if now >= old {
            Some(now - old)
        } else if meta.and_then(|m| m["wrap_bits"].as_u64()) == Some(32) {
            Some((u32::MAX as u64 - old) + now + 1)
        } else if meta.and_then(|m| m["wrap_bits"].as_u64()) == Some(64) {
            Some(now.wrapping_sub(old))
        } else {
            None
        };
        if let Some(delta) = delta {
            field.previous_raw = Some(before.raw.clone());
            field.interval_seconds = Some(seconds);
            field.delta = Some(json!(delta));
            field.rate_per_second = Some(delta as f64 / seconds);
            let rate = delta as f64 / seconds;
            field.rate_formatted = Some(if field.unit == "100ns" {
                format!("{:.3}% of one processor/engine", rate / 100_000.0)
            } else {
                format!("{}/s", format(&json!(rate), &field.unit))
            });
        } else {
            field.validation = "counter_reset".into();
            field.reason = Some("counter decreased; no rate inferred across this interval".into());
        }
    }
}

pub fn validate(fields: &mut [Field], sample: &Value, prefix: &str) {
    let checks = [
        (
            "/machine/memory/available_physical",
            "/machine/memory/total_physical",
            "available physical memory exceeds total",
        ),
        (
            "/machine/memory/committed",
            "/machine/memory/commit_limit",
            "committed memory exceeds its limit",
        ),
        (
            "/machine/cpu/idle_time",
            "/machine/cpu/kernel_time",
            "idle time exceeds kernel time, which includes idle",
        ),
    ];
    for (a, b, reason) in checks {
        if let (Some(a_value), Some(b_value)) = (
            sample.pointer(a).and_then(Value::as_u64),
            sample.pointer(b).and_then(Value::as_u64),
        ) {
            if a_value > b_value {
                if let Some(field) = fields.iter_mut().find(|f| f.path == format!("{prefix}{a}")) {
                    field.validation = "invalid".into();
                    field.reason = Some(reason.into());
                }
            }
        }
    }
}

pub fn cpu_percentages(fields: &[Field], processors: Option<u64>) -> Value {
    let mut times = BTreeMap::<String, (f64, u8)>::new();
    for field in fields {
        if let Some(rate) = field.rate_per_second {
            if let Some(parent) = field
                .path
                .strip_suffix("/metrics/cpu_user_time")
                .or_else(|| field.path.strip_suffix("/metrics/cpu_kernel_time"))
            {
                let entry = times.entry(parent.into()).or_default();
                entry.0 += rate;
                entry.1 += 1;
            }
        }
    }
    json!({"unit":"percent of all active logical processors","logical_processors":processors,"values":times.into_iter().map(|(path,(rate,count))|(path,processors.filter(|&n|n>0 && count == 2).map(|n|rate / (100_000.0*n as f64)))).collect::<BTreeMap<_,_>>()})
}

pub fn unavailable_children(value: &mut Value, schema: &Value, defs: &Value, depth: usize) {
    if depth > 16 {
        return;
    }
    let resolved = schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|s| s.strip_prefix("#/$defs/"))
        .and_then(|name| defs.get(name))
        .unwrap_or(schema);
    let resolved = resolved
        .get("anyOf")
        .and_then(Value::as_array)
        .and_then(|variants| {
            variants
                .iter()
                .find(|s| s.get("$ref").is_some() || s.get("properties").is_some())
        })
        .unwrap_or(resolved);
    if resolved.get("$ref").is_some() {
        unavailable_children(value, resolved, defs, depth + 1);
        return;
    }
    if let Some(properties) = resolved.get("properties").and_then(Value::as_object) {
        if value.is_null() {
            *value = json!({});
        }
        if let Some(object) = value.as_object_mut() {
            for (name, child_schema) in properties {
                let child = object.entry(name).or_insert(Value::Null);
                unavailable_children(child, child_schema, defs, depth + 1);
            }
        }
    }
}

fn identity(path: &str) -> &str {
    path.strip_prefix("/samples/")
        .and_then(|s| s.find('/').map(|index| &s[index..]))
        .unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_missing_and_a_sentinel_have_different_meanings() {
        let catalog =
            json!([{"column":"working_set","unit":"bytes","cumulative":false,"sentinel":u64::MAX}]);
        let values = fields(
            &json!({"a":{"metrics":{"working_set":0}},"b":{"metrics":{"working_set":null}},"c":{"metrics":{"working_set":u64::MAX}}}),
            "",
            &catalog,
        );
        assert_eq!(
            values
                .iter()
                .map(|f| f.availability.as_str())
                .collect::<Vec<_>>(),
            ["available", "unavailable", "unavailable"]
        );
        assert_eq!(values[0].formatted, "0.00 B");
        assert_eq!(values[2].raw, json!(u64::MAX));
    }

    #[test]
    fn rates_use_identity_and_preserve_exact_integer_deltas() {
        let catalog = json!([{"column":"cpu_cycles","unit":"cycles","cumulative":true}]);
        let before = fields(
            &json!({"processes":{"7:11":{"metrics":{"cpu_cycles":9007199254740993u64}}}}),
            "/samples/0",
            &catalog,
        );
        let mut after = fields(
            &json!({"processes":{"7:11":{"metrics":{"cpu_cycles":9007199254741000u64}},"7:12":{"metrics":{"cpu_cycles":5}}}}),
            "/samples/1",
            &catalog,
        );
        rates(&mut after, &before, 2.0, &catalog);
        assert_eq!(after[0].delta, Some(json!(7)));
        assert_eq!(after[0].rate_per_second, Some(3.5));
        assert_eq!(after[1].delta, None);
    }

    #[test]
    fn null_groups_expand_to_catalogued_unavailable_fields() {
        let defs = json!({"Cpu":{"properties":{"base_mhz":{"type":"integer"},"hypervisor":{"type":"boolean"}}}});
        let schema =
            json!({"properties":{"cpu":{"anyOf":[{"$ref":"#/$defs/Cpu"},{"type":"null"}]}}});
        let mut value = json!({"cpu":null});
        unavailable_children(&mut value, &schema, &defs, 0);
        assert_eq!(value, json!({"cpu":{"base_mhz":null,"hypervisor":null}}));
        let fields = fields(&value, "/machine", &json!([]));
        assert!(fields.iter().all(|f| f.availability == "unavailable"));
    }

    #[test]
    fn contradictory_memory_is_invalid_without_erasing_the_raw_value() {
        let value = json!({"machine":{"memory":{"available_physical":200,"total_physical":100}}});
        let mut fields = fields(&value, "/samples/0", &json!([]));
        validate(&mut fields, &value, "/samples/0");
        assert_eq!(fields[0].validation, "invalid");
        assert_eq!(fields[0].raw, json!(200));
    }

    #[test]
    fn retained_exit_counters_and_system_codes_have_units() {
        let events = json!({"kind":{"Exited":{"cpu_cycles":9007199254740993u64,"peak_commit":1048576,"handles":0,"hard_faults":3},"Started":{"parent_sequence_number":42}}});
        let got = fields(&events, "/events/0/events/17", &json!([]));
        assert!(got.iter().all(|f| f.validation == "valid"));
        assert_eq!(
            got.iter()
                .find(|f| f.path.ends_with("peak_commit"))
                .unwrap()
                .formatted,
            "1.00 MiB"
        );
        assert_eq!(
            got.iter()
                .find(|f| f.path.ends_with("cpu_cycles"))
                .unwrap()
                .raw,
            json!(9007199254740993u64)
        );
        for (path, value) in [
            ("/cpu_context/cpuid/model", 165),
            ("/system/windows/data/0/ubr", 9711),
            ("/system/security/data/0/security_services_running/0", 2),
            ("/system/storage/data/0/bus_type", 17),
        ] {
            assert_eq!(field(&json!(value), path, &json!([])).unit, "native code");
        }
    }

    #[test]
    #[ignore = "requires UNIPROC_DIAGNOSTIC_REPORT pointing to a saved native dump"]
    fn saved_native_report_has_no_unclassified_fields() {
        let path =
            std::env::var_os("UNIPROC_DIAGNOSTIC_REPORT").expect("set the saved report path");
        let report: Value = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();
        let catalog = &report["catalog"]["core"]["columns"];
        let entries = report["fields"].as_array().unwrap();
        assert!(!entries.is_empty());
        let unknown: Vec<_> = entries
            .iter()
            .filter_map(|entry| {
                let path = entry["path"].as_str().unwrap();
                let classified = field(&entry["raw"], path, catalog);
                (classified.validation == "unclassified").then_some(path)
            })
            .collect();
        assert!(
            unknown.is_empty(),
            "unclassified source fields: {unknown:?}"
        );
        println!(
            "Audited {} native field observations using current unit metadata",
            entries.len()
        );
    }
}
