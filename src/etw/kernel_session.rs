use crate::etw::consumer::TraceConsumer;
use crate::etw::session::{EtwSession, SessionMode};
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use windows::core::w;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
pub struct KernelSessionRouter {
    session: EtwSession,
    consumer: TraceConsumer,
    handlers: Arc<Mutex<Vec<Box<dyn Fn(&EVENT_RECORD) + Send + Sync>>>>,
}

impl KernelSessionRouter {
    pub fn start(flags: u32) -> anyhow::Result<Arc<Self>> {
        let handlers: Arc<Mutex<Vec<Box<dyn Fn(&EVENT_RECORD) + Send + Sync>>>> =
            Arc::new(Mutex::new(Vec::new()));

        let handlers_cb = Arc::clone(&handlers);
        unsafe { enable_profile_privilege()? };
        let session = EtwSession::start("Uniproc-Kernel", flags, SessionMode::SystemLogger)?;
        let consumer = TraceConsumer::open("Uniproc-Kernel", move |record| {
            for handler in handlers_cb.lock().iter() {
                handler(record);
            }
        })?;
        let running = Arc::new(AtomicBool::new(true));
        consumer.spawn_pump(running);

        Ok(Arc::new(Self {
            session,
            consumer,
            handlers,
        }))
    }

    pub fn register<F>(&self, handler: F)
    where
        F: Fn(&EVENT_RECORD) + Send + Sync + 'static,
    {
        self.handlers.lock().push(Box::new(handler));
    }
}

unsafe fn enable_profile_privilege() -> anyhow::Result<()> {
    let mut token = HANDLE::default();
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)?;

    let mut luid = Default::default();
    LookupPrivilegeValueW(None, w!("SeSystemProfilePrivilege"), &mut luid)?;

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)?;
    Ok(())
}
