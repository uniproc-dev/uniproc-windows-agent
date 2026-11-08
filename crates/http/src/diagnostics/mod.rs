mod context;
mod fields;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use uniproc_windows_agent::api::{
    MachineMetrics, MetricSpec, ProcessInfo, ProcessMetrics, ServiceStats, Snapshot, Update,
};
use uniproc_windows_agent::core_diagnostics;

use super::App;

static BUSY: AtomicBool = AtomicBool::new(false);
const MAX_RAW_BYTES: usize = 64 * 1024 * 1024;
const MAX_FIELDS: usize = 500_000;

struct Collection;
impl Drop for Collection {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

#[derive(Deserialize)]
pub(super) struct Options {
    #[serde(default = "duration")]
    duration_ms: u64,
    #[serde(default = "interval")]
    interval_ms: u64,
}

fn duration() -> u64 {
    3000
}
fn interval() -> u64 {
    1000
}

impl Options {
    fn validate(&self) -> Result<(), String> {
        if !(100..=10_000).contains(&self.interval_ms) {
            return Err("interval_ms must be between 100 and 10000".into());
        }
        if self.duration_ms < self.interval_ms
            || self.duration_ms > 30_000
            || self.duration_ms.div_ceil(self.interval_ms) > 15
        {
            return Err("duration_ms must cover at least one interval, at most 30 seconds and at most 16 samples".into());
        }
        Ok(())
    }
}

pub(super) async fn endpoint(
    State(app): State<Arc<App>>,
    Query(options): Query<Options>,
) -> Result<Json<Value>, (StatusCode, String)> {
    options
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    BUSY.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .map_err(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                "another dump is collecting".into(),
            )
        })?;
    let _collection = Collection;
    collect(&app, options)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

async fn collect(app: &App, options: Options) -> Result<Value, String> {
    let started = Instant::now();
    let started_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    let inventory = tokio::task::spawn_blocking(context::collect);
    let catalog = core_diagnostics::catalog();
    let columns = &catalog["columns"];
    let spec = MetricSpec {
        interval: Duration::from_millis(options.interval_ms),
        processes: ProcessMetrics::all(),
        machine: MachineMetrics::all(),
    };
    let health_before = health(app);
    let mut watch = app.agent.watch(spec);
    let mut events = app.agent.watch_process_events();
    let mut batches = Vec::new();
    let mut raw = Vec::new();
    let mut observations = Vec::new();
    let mut derived = Vec::new();
    let mut all_fields = Vec::new();
    let mut previous = Vec::new();
    let mut previous_at = None;
    let mut raw_bytes = 0usize;
    let count = options.duration_ms.div_ceil(options.interval_ms) + 1;
    for index in 0..count {
        let update = tokio::time::timeout(Duration::from_secs(15), watch.next())
            .await
            .map_err(|_| "service did not deliver a sample within 15 seconds".to_owned())?;
        let sampled_at = update.sample.sampled_at;
        let raw_value = raw_frame(&update)?;
        raw_bytes += serde_json::to_vec(&raw_value)
            .map_err(|e| e.to_string())?
            .len();
        if raw_bytes > MAX_RAW_BYTES {
            return Err("dump exceeded the 64 MiB raw-data limit; reduce duration".into());
        }
        let mut normalized = normalize(&update)?;
        let defs = &catalog["schema"]["$defs"];
        fields::unavailable_children(&mut normalized["machine"], &defs["MachineSample"], defs, 0);
        let mut current = fields::fields(&normalized, &format!("/samples/{index}"), columns);
        if let Some(before) = previous_at {
            if sampled_at <= before {
                return Err("sample clock did not advance".into());
            }
            fields::rates(
                &mut current,
                &previous,
                (sampled_at - before) as f64 / 10_000_000.0,
                columns,
            );
        }
        fields::validate(&mut current, &normalized, &format!("/samples/{index}"));
        derived.push(fields::cpu_percentages(
            &current,
            update
                .sample
                .machine
                .cpu_inventory
                .as_ref()
                .and_then(|i| i.logical_processor_count)
                .map(u64::from),
        ));
        previous_at = Some(sampled_at);
        previous = current.clone();
        all_fields.extend(current);
        if all_fields.len() > MAX_FIELDS {
            return Err("dump exceeded 500000 field observations; reduce duration".into());
        }
        observations.push(coverage(&normalize(&update)?, columns));
        raw.push(raw_value);
        while let Some(batch) = events.try_next() {
            let value = serde_json::to_value(batch).map_err(|e| e.to_string())?;
            raw_bytes += serde_json::to_vec(&value).map_err(|e| e.to_string())?.len();
            if raw_bytes > MAX_RAW_BYTES {
                return Err("event history exceeded the 64 MiB dump limit".into());
            }
            batches.push(value);
        }
    }
    let system = inventory.await.map_err(|e| e.to_string())?;
    let after = health(app);
    let cpu_context = core_diagnostics::cpu_context();
    all_fields.extend(fields::fields(&cpu_context, "/cpu_context", columns));
    all_fields.extend(fields::fields(&system, "/system", columns));
    all_fields.extend(fields::fields(&after, "/health", columns));
    all_fields.extend(fields::fields(&json!(batches), "/events", columns));
    let mut issues: Vec<_> = all_fields.iter().filter(|f| f.validation != "valid" || matches!(f.availability.as_str(),"error"|"unavailable")).map(|f| json!({"path":f.path,"raw":f.raw,"availability":f.availability,"validation":f.validation,"reason":f.reason})).collect();
    issues.sort_by_key(|issue| match issue["validation"].as_str() {
        Some("invalid") => 0,
        Some("loss_observed") => 1,
        Some("counter_reset") => 2,
        Some("unclassified") => 3,
        _ => 4,
    });
    Ok(json!({
        "schema_version":1,
        "collection":{"started_unix_ms":started_unix_ms,"elapsed_ms":started.elapsed().as_millis() as u64,"requested_duration_ms":options.duration_ms,"requested_interval_ms":options.interval_ms,"samples":raw.len(),"raw_bytes":raw_bytes,"reconnections":0,"transport":"service-local diagnostic subscription","power_inventory":"excluded"},
        "service":{"version":env!("CARGO_PKG_VERSION"),"commit":env!("UNIPROC_BUILD_COMMIT"),"pid":std::process::id(),"protocol":format!("{}.{}.{}",uniproc_windows_agent::wire::PROTOCOL.version.major,uniproc_windows_agent::wire::PROTOCOL.version.minor,uniproc_windows_agent::wire::PROTOCOL.version.patch)},
        "catalog":{"core":catalog,"process_info":schemars::schema_for!(ProcessInfo),"services":schemars::schema_for!(ServiceStats),"formatting":"diagnostic IEC bytes; GHz; native units; rates per second, independent of localized UI"},
        "cpu_context":cpu_context,"system":system,"health_before":health_before,"health_after":after,
        "raw_samples":raw,"events":batches,"fields":all_fields,"derived_cpu_percentages":derived,"coverage":observations,"issues":issues,
        "source_observability":{"support":"schema catalog lists implemented capabilities","startup":"ETW session running/pumping states are current observations; historical startup errors are not retained by this API","ingestion":"per-field availability, event history and cumulative loss counters; no events during an interval does not prove source failure","field_failure_reasons":"unknown when the underlying provider exposes only null or a sentinel","reconnections":"not applicable to the in-service collector; external client reconnect history is not exposed"}
    }))
}

fn health(app: &App) -> Value {
    let latest = app.agent.latest();
    json!({"report_age_ms":latest.reported_at.map(|at|at.elapsed().as_millis() as u64),"snapshot_error":latest.snapshot_error,"dropped_by_sink":latest.dropped_by_sink,"sessions":latest.sessions,"spans":app.telemetry.spans.costs().iter().map(|(name,c)|json!({"name":name,"runs":c.runs,"last_us":c.last.as_micros() as u64,"mean_us":c.mean.as_micros() as u64,"max_us":c.max.as_micros() as u64})).collect::<Vec<_>>()})
}

fn raw_frame(update: &Update) -> Result<Value, String> {
    let Snapshot {
        services,
        processes,
        states,
    } = &update.snapshot;
    Ok(
        json!({"sample":serde_json::to_value(&update.sample).map_err(|e|e.to_string())?,"snapshot":{"services":{"etag":services.etag,"value":services.value},"processes":{"etag":processes.etag,"value":processes.value},"states":{"etag":states.etag,"value":states.value}}}),
    )
}

fn normalize(update: &Update) -> Result<Value, String> {
    let sample = &update.sample;
    if sample.pids.len() != sample.sequence_numbers.len() {
        return Err("PID and instance columns differ in length".into());
    }
    let columns = serde_json::to_value(&sample.columns).map_err(|e| e.to_string())?;
    let passports: BTreeMap<_, _> = update
        .snapshot
        .processes
        .value
        .iter()
        .map(|p| ((p.pid, p.sequence_number), p))
        .collect();
    let states: BTreeMap<_, _> = update
        .snapshot
        .states
        .value
        .states
        .iter()
        .map(|p| ((p.pid, p.sequence_number), p))
        .collect();
    let mut processes = serde_json::Map::new();
    for (row, (&pid, &sequence)) in sample
        .pids
        .iter()
        .zip(sample.sequence_numbers.iter())
        .enumerate()
    {
        let mut metrics = serde_json::Map::new();
        for (name, column) in columns.as_object().ok_or("columns are not an object")? {
            let value = match column.as_array() {
                Some(values) if values.len() == sample.pids.len() => values[row].clone(),
                Some(_) => {
                    return Err(format!(
                        "column {name} does not match the process row count"
                    ));
                }
                None => Value::Null,
            };
            metrics.insert(name.clone(), value);
        }
        processes.insert(format!("{pid}:{sequence}"),json!({"info":passports.get(&(pid,sequence)),"state":states.get(&(pid,sequence)),"metrics":metrics}));
    }
    let mut machine = serde_json::to_value(&sample.machine).map_err(|e| e.to_string())?;
    for (group, id) in [("gpus", "luid"), ("network_adapters", "luid")] {
        if let Some(items) = machine[group].as_array() {
            let mapped: BTreeMap<_, _> = items
                .iter()
                .map(|item| (item[id].to_string(), item.clone()))
                .collect();
            machine[group] = json!(mapped);
        }
    }
    if let Some(gpus) = machine["gpus"].as_object_mut() {
        for gpu in gpus.values_mut() {
            if let Some(engines) = gpu["engines"].as_array() {
                let mapped: BTreeMap<_, _> = engines
                    .iter()
                    .map(|e| (e["ordinal"].to_string(), e.clone()))
                    .collect();
                gpu["engines"] = json!(mapped);
            }
        }
    }
    let services: BTreeMap<_, _> = update
        .snapshot
        .services
        .value
        .iter()
        .map(|s| (s.name.clone(), s))
        .collect();
    let sparse: BTreeMap<_, _> = sample
        .gpu_engines
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|engine| {
            let row = engine.row as usize;
            let key = format!(
                "{}:{}:{}:{}",
                sample.pids.get(row).copied().unwrap_or(0),
                sample.sequence_numbers.get(row).copied().unwrap_or(0),
                engine.adapter_luid,
                engine.engine
            );
            (key, engine)
        })
        .collect();
    Ok(
        json!({"sampled_at":sample.sampled_at,"header":{"snapshot":sample.snapshot,"passport_etag":sample.passport_etag,"period":sample.period,"wanted":sample.wanted},"machine":machine,"processes":processes,"services":services,"gpu_engines":sparse}),
    )
}

fn coverage(sample: &Value, columns: &Value) -> Value {
    let count = sample["processes"].as_object().map_or(0, |p| p.len());
    let metrics: Vec<_> = columns.as_array().into_iter().flatten().map(|column| {
        let name = column["column"].as_str().unwrap_or("");
        let available = sample["processes"].as_object().into_iter().flat_map(|p|p.values()).filter(|p| !p["metrics"][name].is_null() && !(column["sentinel"].is_number() && column["sentinel"] == p["metrics"][name])).count();
        json!({"metric":column["metric"],"column":name,"requested":true,"rows":count,"available":available,"unavailable":count-available})
    }).collect();
    json!({"process_metrics":metrics,"machine_groups":sample["machine"].as_object().map(|groups|groups.iter().map(|(name,value)|json!({"group":name,"requested":true,"availability":if value.is_null(){"unavailable"}else{"available"}})).collect::<Vec<_>>())})
}

pub fn render(report: &Value, full: bool) -> String {
    let mut text = format!(
        "Uniproc service {} ({})\nSamples: {}, elapsed: {} ms\nFields: {}, issues: {}\n",
        report["service"]["version"],
        report["service"]["commit"],
        report["collection"]["samples"],
        report["collection"]["elapsed_ms"],
        report["fields"].as_array().map_or(0, Vec::len),
        report["issues"].as_array().map_or(0, Vec::len)
    );
    text.push_str(&format!(
        "CPU context: {}\nWindows: {}\nHealth: {}\n",
        report["cpu_context"], report["system"]["windows"], report["health_after"]
    ));
    let mut statuses = BTreeMap::<String, usize>::new();
    if let Some(fields) = report["fields"].as_array() {
        for field in fields {
            *statuses
                .entry(format!(
                    "{}/{}",
                    field["availability"].as_str().unwrap_or("unknown"),
                    field["validation"].as_str().unwrap_or("unknown")
                ))
                .or_default() += 1;
        }
    }
    text.push_str(&format!("Status counts: {}\n", json!(statuses)));
    let rows = if full {
        &report["fields"]
    } else {
        &report["issues"]
    };
    if let Some(rows) = rows.as_array() {
        for row in rows.iter().take(if full { usize::MAX } else { 25 }) {
            text.push_str(&format!(
                "{} | raw={} | {} | unit={} | {} / {}",
                row["path"].as_str().unwrap_or(""),
                row["raw"],
                row["formatted"].as_str().unwrap_or(""),
                row["unit"].as_str().unwrap_or(""),
                row["availability"].as_str().unwrap_or(""),
                row["validation"].as_str().unwrap_or("")
            ));
            if !row["delta"].is_null() {
                text.push_str(&format!(
                    " | delta={} rate={}/s ({})",
                    row["delta"],
                    row["rate_per_second"],
                    row["rate_formatted"].as_str().unwrap_or("")
                ));
            }
            if let Some(reason) = row["reason"].as_str() {
                text.push_str(&format!(" | {reason}"));
            }
            text.push('\n');
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_collection_requires_multiple_observations() {
        assert!(
            Options {
                duration_ms: 3000,
                interval_ms: 1000
            }
            .validate()
            .is_ok()
        );
        for options in [
            Options {
                duration_ms: 0,
                interval_ms: 1000,
            },
            Options {
                duration_ms: 30000,
                interval_ms: 100,
            },
            Options {
                duration_ms: 30001,
                interval_ms: 1000,
            },
        ] {
            assert!(options.validate().is_err());
        }
    }

    #[test]
    fn process_metrics_keep_pid_instance_identity_and_all_catalogued_columns() {
        use uniproc_windows_agent::api::{Changes, Columns, ProcessStates, Sample, Tagged};
        let update = Update {
            snapshot: Snapshot {
                services: Tagged {
                    etag: 1,
                    value: Arc::from([]),
                },
                processes: Tagged {
                    etag: 2,
                    value: Arc::from([ProcessInfo {
                        pid: 7,
                        sequence_number: 99,
                        ..Default::default()
                    }]),
                },
                states: Tagged {
                    etag: 3,
                    value: ProcessStates::default(),
                },
            },
            sample: Sample {
                pids: Arc::from([7]),
                sequence_numbers: Arc::from([99]),
                columns: Columns {
                    working_set: Some(Arc::from([0])),
                    ..Default::default()
                },
                ..Default::default()
            },
            changes: Changes::default(),
        };
        let value = normalize(&update).unwrap();
        assert_eq!(value["processes"]["7:99"]["metrics"]["working_set"], 0);
        assert_eq!(value["processes"]["7:99"]["info"]["pid"], 7);
        let catalog = core_diagnostics::catalog();
        assert_eq!(
            value["processes"]["7:99"]["metrics"]
                .as_object()
                .unwrap()
                .len(),
            catalog["columns"].as_array().unwrap().len()
        );
        assert!(value["processes"]["7:99"]["metrics"]["handles"].is_null());
        let raw = raw_frame(&update).unwrap();
        assert_eq!(raw["sample"]["columns"]["working_set"], json!([0]));
        assert_eq!(raw["snapshot"]["processes"]["etag"], 2);
    }
}
