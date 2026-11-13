use crate::sample::{CpuDetails, CpuInstructionSetSemantics};
use raw_cpuid::{CpuId, CpuIdReader};
use smol_str::SmolStr;
use std::sync::Arc;

pub(super) fn identity<R: CpuIdReader>(cpuid: &CpuId<R>) -> CpuDetails {
    let features = cpuid.get_feature_info();
    CpuDetails {
        vendor: cpuid.get_vendor_info().and_then(|vendor| {
            let name = vendor.as_str().trim_matches('\0').trim();
            (!name.is_empty()).then(|| SmolStr::new(name))
        }),
        family: features
            .as_ref()
            .map(|features| u32::from(features.family_id())),
        model: features
            .as_ref()
            .map(|features| u32::from(features.model_id())),
        stepping: features
            .as_ref()
            .map(|features| u32::from(features.stepping_id())),
        ..Default::default()
    }
}

pub(super) fn complete(mut details: CpuDetails) -> CpuDetails {
    macro_rules! detected {
        ($($name:tt),* $(,)?) => {
            [$((SmolStr::new($name), std::is_x86_feature_detected!($name))),*]
        }
    }
    let selected = detected!(
        "sse",
        "sse2",
        "sse3",
        "ssse3",
        "sse4.1",
        "sse4.2",
        "avx",
        "avx2",
        "fma",
        "f16c",
        "aes",
        "pclmulqdq",
        "popcnt",
        "bmi1",
        "bmi2",
        "avx512f",
        "avx512dq",
        "avx512cd",
        "avx512bw",
        "avx512vl"
    );
    let mut usable: Vec<SmolStr> = selected
        .into_iter()
        .filter_map(|(name, usable)| usable.then(|| SmolStr::new(name.to_ascii_uppercase())))
        .collect();
    usable.sort_unstable();
    usable.dedup();
    details.instruction_sets = Some(Arc::from(usable));
    details.instruction_sets_semantics = CpuInstructionSetSemantics::OsUsable;
    details.instruction_sets_scope = "selected_x86_features".into();
    details
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details_keep_absence_zero_and_empty_feature_lists_distinct() {
        let missing = serde_json::to_value(CpuDetails::default()).unwrap();
        assert!(missing["family"].is_null());
        assert!(missing["instruction_sets"].is_null());
        assert_eq!(missing["instruction_sets_semantics"], "Unknown");
        let present = serde_json::to_value(CpuDetails {
            family: Some(0),
            microcode_revision: Some(0),
            instruction_sets: Some(Arc::from([])),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(present["family"], 0);
        assert_eq!(present["microcode_revision"], 0);
        assert_eq!(present["instruction_sets"], serde_json::json!([]));
    }

    #[test]
    fn missing_cpuid_identity_does_not_invent_a_model_or_microcode() {
        let cpuid = CpuId::with_cpuid_fn(|_, _| raw_cpuid::CpuIdResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        });
        let details = identity(&cpuid);
        assert_eq!(details.family, None);
        assert_eq!(details.model, None);
        assert_eq!(details.stepping, None);
        assert_eq!(details.microcode_revision, None);
        assert_eq!(details.instruction_sets, None);
        assert_eq!(
            details.instruction_sets_semantics,
            CpuInstructionSetSemantics::Unknown
        );
    }

    #[test]
    fn selected_instruction_sets_are_sorted_os_usable_and_not_advertised() {
        let details = complete(CpuDetails::default());
        let sets = details.instruction_sets.as_ref().unwrap();
        assert!(sets.windows(2).all(|names| names[0] < names[1]));
        assert_eq!(
            sets.iter().any(|name| name == "AVX"),
            std::is_x86_feature_detected!("avx")
        );
        assert_eq!(
            sets.iter().any(|name| name == "AVX2"),
            std::is_x86_feature_detected!("avx2")
        );
        assert_eq!(
            details.instruction_sets_semantics,
            CpuInstructionSetSemantics::OsUsable
        );
        assert_eq!(details.instruction_sets_scope, "selected_x86_features");
        assert_eq!(details.microcode_revision, None);
        println!("cpu_details={}", serde_json::to_string(&details).unwrap());
    }
}
