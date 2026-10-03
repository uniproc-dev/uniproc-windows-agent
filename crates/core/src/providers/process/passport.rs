//! The Details columns a process keeps for its lifetime, read once when it shows up.

use std::collections::HashMap;

use smol_str::SmolStr;

use windows::Win32::{
    AreDpiAwarenessContextsEqual, CloseHandle, DPI_AWARENESS_CONTEXT,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    DPI_AWARENESS_CONTEXT_SYSTEM_AWARE, DPI_AWARENESS_CONTEXT_UNAWARE,
    DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED, GetDpiAwarenessContextForProcess, GetProcessInformation,
    GetProcessMitigationPolicy, GetTokenInformation, HANDLE, IsWow64Process2, LookupAccountSidW,
    OpenProcessToken, PSID, ProcessControlFlowGuardPolicy,
    ProcessDEPPolicy, ProcessMachineTypeInfo, ProcessUserShadowStackPolicy, TOKEN_QUERY,
    TokenElevation, TokenUser,
};
use windows::core::PWSTR;

use crate::model::{
    Architecture, DpiAwareness, ExtendedCfg, Isolation, Mitigations, StackProtection,
    UacVirtualization,
};

const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

const TOKEN_VIRTUALIZATION_ALLOWED: i32 = 23;
const TOKEN_VIRTUALIZATION_ENABLED: i32 = 24;
const TOKEN_IS_APP_CONTAINER: i32 = 29;

const DEP_ENABLE: u32 = 1;
const CFG_ENABLE_XFG: u32 = 1 << 3;
const CFG_ENABLE_XFG_AUDIT: u32 = 1 << 4;
const SHADOW_STACK_ENABLE: u32 = 1;
const SHADOW_STACK_AUDIT: u32 = 1 << 1;
const SHADOW_STACK_STRICT: u32 = 1 << 4;

/// What [`probe`] could read; the rest stays unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Passport {
    pub user: SmolStr,
    pub architecture: Architecture,
    pub elevated: Option<bool>,
    pub uac_virtualization: UacVirtualization,
    pub isolation: Isolation,
    pub dpi_awareness: DpiAwareness,
    pub mitigations: Option<Mitigations>,
}

struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// `DOMAIN\name` per SID, looked up once.
#[derive(Default)]
pub struct SidNames(HashMap<Box<[u8]>, SmolStr>);

impl SidNames {
    pub(crate) fn name(&mut self, sid: &[u8]) -> SmolStr {
        if let Some(name) = self.0.get(sid) {
            return name.clone();
        }
        let name = SmolStr::from(lookup_account(sid).unwrap_or_default());
        self.0.insert(sid.into(), name.clone());
        name
    }
}

/// Reads what the process lets a limited-query handle see. `sid` is the
/// user's SID when the caller already has it; otherwise it is read from the
/// token. A packaged process in an AppContainer is `Uwp`.
pub fn probe(process: Option<HANDLE>, sid: Option<&[u8]>, packaged: bool, names: &mut SidNames) -> Passport {
    let Some(process) = process else {
        return Passport {
            user: sid.map(|sid| names.name(sid)).unwrap_or_default(),
            ..Default::default()
        };
    };
    let token = open_token(process);
    let sid = sid
        .map(Box::from)
        .or_else(|| token.as_ref().and_then(|t| token_user(t.0)));

    let app_container = token.as_ref().and_then(|t| token_flag(t.0, TOKEN_IS_APP_CONTAINER));
    let architecture = architecture(process);
    Passport {
        user: sid.map(|sid| names.name(&sid)).unwrap_or_default(),
        architecture,
        elevated: token.as_ref().and_then(|t| token_flag(t.0, TokenElevation)),
        uac_virtualization: token.as_ref().map_or(UacVirtualization::Unknown, |t| {
            uac_virtualization(
                token_flag(t.0, TOKEN_VIRTUALIZATION_ALLOWED),
                token_flag(t.0, TOKEN_VIRTUALIZATION_ENABLED),
            )
        }),
        isolation: isolation(app_container, packaged),
        dpi_awareness: dpi_awareness(process),
        mitigations: mitigations(process, architecture),
    }
}

fn open_token(process: HANDLE) -> Option<Owned> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY as u32, &mut token) }
        .as_bool()
        .then_some(Owned(token))
}

fn token_flag(token: HANDLE, class: i32) -> Option<bool> {
    let mut value = 0u32;
    let mut returned = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some((&mut value as *mut u32).cast()),
            size_of::<u32>() as u32,
            &mut returned,
        )
    }
    .as_bool()
    .then_some(value != 0)
}

fn token_user(token: HANDLE) -> Option<Box<[u8]>> {
    let mut buf = crate::aligned::AlignedBuf::zeroed(256);
    let mut returned = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            buf.len() as u32,
            &mut returned,
        )
    };
    if !ok.as_bool() {
        return None;
    }
    let sid = unsafe { buf.as_ptr().cast::<*const u8>().read() };
    if sid.is_null() {
        return None;
    }
    let count = unsafe { *sid.add(1) } as usize;
    Some(unsafe { std::slice::from_raw_parts(sid, 8 + 4 * count) }.into())
}

fn lookup_account(sid: &[u8]) -> Option<String> {
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
    let mut kind = Default::default();
    let ok = unsafe {
        LookupAccountSidW(
            None,
            PSID(sid.as_ptr() as *mut _),
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    };
    if !ok.as_bool() {
        return None;
    }
    let name = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    Some(if domain.is_empty() { name } else { format!("{domain}\\{name}") })
}

fn uac_virtualization(allowed: Option<bool>, enabled: Option<bool>) -> UacVirtualization {
    match (allowed, enabled) {
        (Some(false), _) => UacVirtualization::NotAllowed,
        (Some(true), Some(true)) => UacVirtualization::Enabled,
        (Some(true), Some(false)) => UacVirtualization::Disabled,
        _ => UacVirtualization::Unknown,
    }
}

fn isolation(app_container: Option<bool>, packaged: bool) -> Isolation {
    match app_container {
        Some(true) if packaged => Isolation::Uwp,
        Some(true) => Isolation::AppContainer,
        Some(false) => Isolation::None,
        None => Isolation::Unknown,
    }
}

#[repr(C)]
#[derive(Default)]
struct MachineInformation {
    process_machine: u16,
    reserved: u16,
    attributes: u32,
}

fn architecture(process: HANDLE) -> Architecture {
    let (mut wow, mut native) = (0u16, 0u16);
    if unsafe { IsWow64Process2(process, &mut wow, Some(&mut native)) }.as_bool()
        && wow != IMAGE_FILE_MACHINE_UNKNOWN
    {
        return machine(wow);
    }
    let mut info = MachineInformation::default();
    let read = unsafe {
        GetProcessInformation(
            process,
            ProcessMachineTypeInfo,
            (&mut info as *mut MachineInformation).cast(),
            size_of::<MachineInformation>() as u32,
        )
    };
    if read.as_bool() {
        machine(info.process_machine)
    } else {
        machine(native)
    }
}

fn machine(image_machine: u16) -> Architecture {
    match image_machine {
        IMAGE_FILE_MACHINE_I386 => Architecture::X86,
        IMAGE_FILE_MACHINE_AMD64 => Architecture::X64,
        IMAGE_FILE_MACHINE_ARMNT => Architecture::Arm,
        IMAGE_FILE_MACHINE_ARM64 => Architecture::Arm64,
        _ => Architecture::Unknown,
    }
}

fn dpi_awareness(process: HANDLE) -> DpiAwareness {
    let context = unsafe { GetDpiAwarenessContextForProcess(process) };
    if context.0.is_null() {
        return DpiAwareness::Unknown;
    }
    let is = |known: DPI_AWARENESS_CONTEXT| unsafe { AreDpiAwarenessContextsEqual(context, known) }.as_bool();
    [
        (DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED, DpiAwareness::UnawareGdiScaled),
        (DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, DpiAwareness::PerMonitorV2),
        (DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE, DpiAwareness::PerMonitor),
        (DPI_AWARENESS_CONTEXT_SYSTEM_AWARE, DpiAwareness::System),
        (DPI_AWARENESS_CONTEXT_UNAWARE, DpiAwareness::Unaware),
    ]
    .into_iter()
    .find(|(known, _)| is(*known))
    .map_or(DpiAwareness::Unknown, |(_, awareness)| awareness)
}

fn policy_flags(process: HANDLE, policy: i32, size: usize) -> Option<u32> {
    let mut buf = [0u32; 2];
    unsafe { GetProcessMitigationPolicy(process, policy, buf.as_mut_ptr().cast(), size) }
        .as_bool()
        .then_some(buf[0])
}

fn mitigations(process: HANDLE, architecture: Architecture) -> Option<Mitigations> {
    let always_dep = matches!(architecture, Architecture::X64 | Architecture::Arm64);
    let dep = policy_flags(process, ProcessDEPPolicy, 8).or(always_dep.then_some(DEP_ENABLE));
    let cfg = policy_flags(process, ProcessControlFlowGuardPolicy, 4);
    let shadow = policy_flags(process, ProcessUserShadowStackPolicy, 4);
    if dep.is_none() && cfg.is_none() && shadow.is_none() {
        return None;
    }
    Some(Mitigations {
        dep: dep.map(|flags| flags & DEP_ENABLE != 0),
        stack_protection: shadow.map_or(StackProtection::Unknown, stack_protection),
        extended_cfg: cfg.map_or(ExtendedCfg::Unknown, extended_cfg),
    })
}

fn stack_protection(flags: u32) -> StackProtection {
    let strict = flags & SHADOW_STACK_STRICT != 0;
    match (flags & SHADOW_STACK_ENABLE != 0, flags & SHADOW_STACK_AUDIT != 0, strict) {
        (true, _, true) => StackProtection::Strict,
        (true, _, false) => StackProtection::Compatible,
        (false, true, true) => StackProtection::StrictAudit,
        (false, true, false) => StackProtection::CompatibleAudit,
        (false, false, _) => StackProtection::Off,
    }
}

fn extended_cfg(flags: u32) -> ExtendedCfg {
    if flags & CFG_ENABLE_XFG != 0 {
        ExtendedCfg::On
    } else if flags & CFG_ENABLE_XFG_AUDIT != 0 {
        ExtendedCfg::Audit
    } else {
        ExtendedCfg::Off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_reads_back_as_itself() {
        let mut names = SidNames::default();
        let passport = probe(Some(unsafe { windows::Win32::GetCurrentProcess() }), None, false, &mut names);
        let expected = if cfg!(target_arch = "x86_64") { Architecture::X64 } else { passport.architecture };
        assert_eq!(passport.architecture, expected);
        assert!(passport.user.contains('\\'), "{:?}", passport.user);
        assert!(passport.elevated.is_some());
        assert_eq!(passport.isolation, Isolation::None);
        assert_ne!(passport.uac_virtualization, UacVirtualization::Unknown);
        let mitigations = passport.mitigations.expect("mitigations");
        assert_eq!(mitigations.dep, Some(true), "64-bit processes always run with DEP");
    }

    #[test]
    fn a_gone_process_is_unknown_but_keeps_a_known_user() {
        let mut names = SidNames::default();
        let system = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let passport = probe(None, Some(&system), false, &mut names);
        assert!(passport.user.ends_with("SYSTEM"), "{:?}", passport.user);
        assert_eq!(passport.architecture, Architecture::Unknown);
        assert_eq!(passport.mitigations, None);
    }

    #[test]
    fn uac_virtualization_follows_task_manager() {
        assert_eq!(uac_virtualization(Some(false), Some(false)), UacVirtualization::NotAllowed);
        assert_eq!(uac_virtualization(Some(true), Some(false)), UacVirtualization::Disabled);
        assert_eq!(uac_virtualization(Some(true), Some(true)), UacVirtualization::Enabled);
        assert_eq!(uac_virtualization(None, None), UacVirtualization::Unknown);
    }

    #[test]
    fn a_packaged_app_container_is_uwp() {
        assert_eq!(isolation(Some(true), true), Isolation::Uwp);
        assert_eq!(isolation(Some(true), false), Isolation::AppContainer);
        assert_eq!(isolation(Some(false), true), Isolation::None);
    }

    #[test]
    fn stack_protection_reads_the_shadow_stack_flags() {
        assert_eq!(stack_protection(0), StackProtection::Off);
        assert_eq!(stack_protection(SHADOW_STACK_ENABLE), StackProtection::Compatible);
        assert_eq!(stack_protection(SHADOW_STACK_ENABLE | SHADOW_STACK_STRICT), StackProtection::Strict);
        assert_eq!(stack_protection(SHADOW_STACK_AUDIT), StackProtection::CompatibleAudit);
        assert_eq!(stack_protection(SHADOW_STACK_AUDIT | SHADOW_STACK_STRICT), StackProtection::StrictAudit);
    }

    #[test]
    fn extended_cfg_reads_the_xfg_flags() {
        assert_eq!(extended_cfg(1), ExtendedCfg::Off, "plain CFG is not XFG");
        assert_eq!(extended_cfg(1 | CFG_ENABLE_XFG), ExtendedCfg::On);
        assert_eq!(extended_cfg(CFG_ENABLE_XFG_AUDIT), ExtendedCfg::Audit);
    }
}
