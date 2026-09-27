//! What the core says about processes, in the terms Task Manager shows them.
//! A value the agent could not read is `Unknown`, `None`, empty or 0.

/// Task Manager's Architecture column; 16, 32 or 64-bit follows from it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Architecture {
    #[default]
    Unknown,
    X86,
    X64,
    Arm,
    Arm64,
    /// CHPE.
    Arm64X86Compatible,
    /// ARM64EC.
    Arm64X64Compatible,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum UacVirtualization {
    #[default]
    Unknown,
    NotAllowed,
    Disabled,
    Enabled,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Isolation {
    #[default]
    Unknown,
    None,
    AppContainer,
    Uwp,
    Silo,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum DpiAwareness {
    #[default]
    Unknown,
    Unaware,
    System,
    PerMonitor,
    PerMonitorV2,
    UnawareGdiScaled,
}

/// Hardware-enforced stack protection: compatible modules only or all
/// modules, each optionally in audit mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum StackProtection {
    #[default]
    Unknown,
    Off,
    Compatible,
    Strict,
    CompatibleAudit,
    StrictAudit,
}

/// Extended Control Flow Guard (XFG).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ExtendedCfg {
    #[default]
    Unknown,
    Off,
    Audit,
    On,
}

/// `VeryLow` is what Task Manager shows as Background.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IoPriority {
    #[default]
    Unknown,
    VeryLow,
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProcessPriority {
    Idle,
    BelowNormal,
    Normal,
    AboveNormal,
    High,
    Realtime,
}

impl ProcessPriority {
    /// The class a process's base priority stands for.
    pub fn from_base(base: i32) -> Option<Self> {
        match base {
            4 => Some(Self::Idle),
            6 => Some(Self::BelowNormal),
            8 => Some(Self::Normal),
            10 => Some(Self::AboveNormal),
            13 => Some(Self::High),
            24 => Some(Self::Realtime),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Mitigations {
    /// Data execution prevention.
    pub dep: Option<bool>,
    pub stack_protection: StackProtection,
    pub extended_cfg: ExtendedCfg,
}

/// How a process runs right now; changes rarely.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessState {
    pub pid: u32,
    pub sequence_number: u64,
    /// Every thread waits with reason Suspended.
    pub suspended: Option<bool>,
    /// EcoQoS throttling together with the Idle priority class, as Task Manager sets it.
    pub efficiency_mode: Option<bool>,
    pub base_priority: Option<ProcessPriority>,
    /// EcoQoS throttling on its own.
    pub power_throttling: Option<bool>,
    /// Kernel id of the process's job, 0 when it is in none.
    pub job_object_id: u32,
    pub io_priority: IoPriority,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_priority_class_has_its_base_priority() {
        assert_eq!(ProcessPriority::from_base(4), Some(ProcessPriority::Idle));
        assert_eq!(ProcessPriority::from_base(8), Some(ProcessPriority::Normal));
        assert_eq!(ProcessPriority::from_base(13), Some(ProcessPriority::High));
        assert_eq!(ProcessPriority::from_base(24), Some(ProcessPriority::Realtime));
        assert_eq!(ProcessPriority::from_base(0), None, "the Idle process has none");
    }
}
