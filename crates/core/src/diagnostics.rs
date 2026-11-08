use serde_json::{Value, json};

use crate::{Columns, Process, ProcessEventBatch, ProcessState, Sample, SessionHealth};

#[allow(dead_code)]
#[derive(schemars::JsonSchema)]
struct CoreModels {
    sample: Sample,
    process: Process,
    process_state: ProcessState,
    process_events: ProcessEventBatch,
    session_health: SessionHealth,
}

pub fn diagnostic_schema() -> Value {
    serde_json::to_value(schemars::schema_for!(CoreModels)).expect("JSON schema is serializable")
}

pub fn catalog() -> Value {
    json!({"columns": Columns::catalog(), "schema": diagnostic_schema(),
        "sparse_process_metrics": [{"metric": "GpuEngines", "field": "gpu_engines", "unit": "100ns", "cumulative": true, "wrap_bits": 64}]})
}

pub fn cpu_context() -> Value {
    crate::providers::machine::cpu_context()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MachineSample, NO_DATA_U32, ProcessMetric, ProcessMetrics};

    #[test]
    fn every_process_metric_has_generated_column_metadata_or_sparse_metadata() {
        let catalog = catalog();
        let mut metrics: Vec<Value> = catalog["columns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|column| column["metric"].clone())
            .collect();
        metrics.extend(
            catalog["sparse_process_metrics"]
                .as_array()
                .unwrap()
                .iter()
                .map(|metric| metric["metric"].clone()),
        );
        for metric in ProcessMetrics::all() {
            let name = serde_json::to_value(metric).unwrap();
            assert_eq!(
                metrics.iter().filter(|value| **value == name).count(),
                1,
                "{metric:?}"
            );
        }
        assert_eq!(metrics.len(), ProcessMetrics::all().len());
        let defaults = serde_json::to_value(Columns::default()).unwrap();
        assert_eq!(
            defaults.as_object().unwrap().len(),
            catalog["columns"].as_array().unwrap().len()
        );
        for column in catalog["columns"].as_array().unwrap() {
            assert!(defaults.get(column["column"].as_str().unwrap()).is_some());
            if column["metric"] == serde_json::to_value(ProcessMetric::PageFaults).unwrap() {
                assert!(column["sentinel"].is_null());
                assert_eq!(column["wrap_bits"], 32);
            }
        }
    }

    #[test]
    fn serialization_preserves_absence_sentinels_zero_and_wrapping_counters() {
        let columns = Columns {
            page_faults: Some(vec![u32::MAX].into()),
            user_objects: Some(vec![NO_DATA_U32, 0].into()),
            ..Default::default()
        };
        let value = serde_json::to_value(columns).unwrap();
        assert_eq!(value["page_faults"][0], u32::MAX);
        assert_eq!(value["user_objects"][0], NO_DATA_U32);
        assert_eq!(value["user_objects"][1], 0);
        assert!(value["working_set"].is_null());
        let schema = diagnostic_schema();
        let serialized = serde_json::to_value(MachineSample::default()).unwrap();
        let properties = schema["$defs"]["MachineSample"]["properties"]
            .as_object()
            .unwrap();
        assert_eq!(properties.len(), serialized.as_object().unwrap().len());
        for field in serialized.as_object().unwrap().keys() {
            assert!(properties.contains_key(field));
        }
    }

    #[test]
    fn cpu_context_reports_the_source_of_the_same_cached_inventory() {
        let context = cpu_context();
        let inventory = crate::providers::machine::cpu_context();
        assert_eq!(context, inventory);
        if context["base_mhz"].is_null() {
            assert!(context["base_mhz_source"].is_null());
        } else {
            assert!(matches!(
                context["base_mhz_source"].as_str(),
                Some("cpuid_16h" | "intel_brand_string")
            ));
        }
    }

    #[test]
    fn wanted_metrics_are_named_lists_in_the_full_sample() {
        let sample = Sample {
            wanted: crate::MetricSpec {
                interval: std::time::Duration::from_millis(200),
                processes: crate::ProcessMetric::WorkingSet.into(),
                machine: crate::MachineMetric::Cpu.into(),
            },
            ..Default::default()
        };
        let value = serde_json::to_value(sample).unwrap();
        assert_eq!(value["wanted"]["processes"], json!(["WorkingSet"]));
        assert_eq!(value["wanted"]["machine"], json!(["Cpu"]));
        assert!(value["machine"]["cpu_inventory"].is_null());
    }

    #[test]
    fn process_states_and_events_preserve_unknown_false_and_loss_counts() {
        let state = ProcessState {
            vm_host: Some(false),
            ..Default::default()
        };
        let value = serde_json::to_value(state).unwrap();
        assert_eq!(value["vm_host"], false);
        assert!(value["suspended"].is_null());
        let event = crate::ProcessEvent {
            pid: 42,
            sequence_number: 123,
            time: 456,
            kind: crate::ProcessEventKind::Started(crate::ProcessStarted {
                command_line: "example.exe --hello=привет".into(),
                elevated: Some(false),
                ..Default::default()
            }),
        };
        let batch = ProcessEventBatch {
            history_from: 100,
            events: vec![std::sync::Arc::new(event)],
            lost: u32::MAX,
        };
        let value = serde_json::to_value(batch).unwrap();
        assert_eq!(value["lost"], u32::MAX);
        assert_eq!(value["events"][0]["kind"]["Started"]["elevated"], false);
        assert_eq!(
            value["events"][0]["kind"]["Started"]["command_line"],
            "example.exe --hello=привет"
        );
    }
}
