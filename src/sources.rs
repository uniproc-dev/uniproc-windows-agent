use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender};
use uniproc_agent_kit::{Collector, Monitor, Waker, Wakes, Why};
use uniproc_windows_core::{Demand, Diff, Provider, Supervisor, SupervisorConfig};

use crate::feed::Change;
use crate::scm::{ServiceControl, Services};

/// The fewest milliseconds between two ticks of the core.
const SPACING: Duration = Duration::from_millis(50);

/// Everything that learns about the machine: the core on its monitor
/// thread, and the services. Each tells the picture through `changes`.
/// Stops when dropped.
pub(crate) struct Sources {
    _monitor: Monitor,
    services: Services,
}

struct Core {
    supervisor: Supervisor,
    changes: Sender<Change>,
    spares: Receiver<Diff>,
}

impl Collector for Core {
    fn tick(&mut self, _: Why) -> Instant {
        let mut diff = self.spares.try_recv().unwrap_or_default();
        self.supervisor.tick(&mut diff);
        let _ = self.changes.send(Change::Core(diff, self.supervisor.health()));
        self.supervisor.due()
    }
}

impl Sources {
    /// The core samples what `demand` asks for and ticks when `wakes` says
    /// so; `spares` hands back the diffs the picture emptied. `extra` are
    /// providers fed from the core's sessions beside its own.
    pub fn start(
        config: SupervisorConfig,
        demand: Demand,
        (waker, wakes): (Waker, Wakes),
        changes: Sender<Change>,
        spares: Receiver<Diff>,
        extra: Vec<Box<dyn Provider>>,
    ) -> anyhow::Result<Self> {
        let supervisor = Supervisor::start(config, demand, extra, move || waker.wake())?;
        let services = Services::start({
            let changes = changes.clone();
            move |event| {
                let _ = changes.send(Change::Services(event));
            }
        })?;
        let monitor = Monitor::start(
            "core",
            SPACING,
            wakes,
            Core {
                supervisor,
                changes,
                spares,
            },
        )?;
        Ok(Self {
            _monitor: monitor,
            services,
        })
    }

    pub fn control(&self) -> ServiceControl {
        self.services.control()
    }
}
