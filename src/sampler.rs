use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use parking_lot::Mutex;
use uniproc_agent_kit::Monitor;
use uniproc_windows_core::Demand;

use crate::api::{MetricSpec, Sample};
use crate::feed::Feed;

/// The live subscriptions: their union is what the core samples, at the
/// shortest interval any of them asks for.
pub(crate) struct Subscriptions {
    demand: Demand,
    live: Mutex<Live>,
    monitor: Mutex<Weak<Monitor>>,
}

#[derive(Default)]
struct Live {
    next: u64,
    specs: BTreeMap<u64, MetricSpec>,
}

impl Subscriptions {
    pub fn new(demand: Demand) -> Arc<Self> {
        Arc::new(Self {
            demand,
            live: Mutex::new(Live::default()),
            monitor: Mutex::new(Weak::new()),
        })
    }

    /// The monitor whose period follows the union.
    pub fn drive(&self, monitor: &Arc<Monitor>) {
        *self.monitor.lock() = Arc::downgrade(monitor);
        self.retune();
    }

    /// How often the core samples while nobody subscribes.
    pub fn set_idle(&self, idle: Duration) {
        self.demand.set_idle(idle);
        self.retune();
    }

    fn add(self: &Arc<Self>, spec: MetricSpec) -> Subscription {
        let id = {
            let mut live = self.live.lock();
            live.next += 1;
            let id = live.next;
            live.specs.insert(id, spec);
            id
        };
        self.retune();
        Subscription {
            id,
            subscriptions: self.clone(),
        }
    }

    fn remove(&self, id: u64) {
        self.live.lock().specs.remove(&id);
        self.retune();
    }

    fn retune(&self) {
        let union = self.live.lock().specs.values().copied().reduce(MetricSpec::union);
        self.demand.set_wanted(union);
        if let Some(monitor) = self.monitor.lock().upgrade() {
            monitor.set_period(self.demand.period());
        }
    }

    #[cfg(test)]
    fn count(&self) -> usize {
        self.live.lock().specs.len()
    }
}

/// Leaves the union when dropped.
struct Subscription {
    id: u64,
    subscriptions: Arc<Subscriptions>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.subscriptions.remove(self.id);
    }
}

/// One subscription to the agent running in this process. The core samples
/// while it lives; dropping it stops that, unless someone else wants the same.
pub struct LocalSampler {
    feed: Arc<Feed>,
    spec: MetricSpec,
    current: Mutex<Option<Arc<Sample>>>,
    _subscription: Subscription,
}

impl LocalSampler {
    pub(crate) fn new(feed: Arc<Feed>, subscriptions: &Arc<Subscriptions>, spec: MetricSpec) -> Self {
        Self {
            feed,
            spec,
            current: Mutex::new(None),
            _subscription: subscriptions.add(spec),
        }
    }

    pub fn spec(&self) -> MetricSpec {
        self.spec
    }

    /// The latest sample this subscription is due, with only its own metrics;
    /// `None` before the first one that covers them.
    pub fn latest(&self) -> Option<Sample> {
        self.pick(self.feed.latest().sample.clone())
            .map(|held| held.project(&self.spec))
    }

    /// The latest sample unless its snapshot is `if_none_match`; then the
    /// next one, once the agent has taken it. Dropping the future stops the wait.
    pub async fn sample(&self, if_none_match: u64) -> Sample {
        loop {
            let generation = self.feed.generation();
            if let Some(held) = self.pick(self.feed.latest().sample.clone())
                && held.snapshot != if_none_match
            {
                return held.project(&self.spec);
            }
            self.feed.published(generation).await;
        }
    }

    /// The sample to answer with: the latest one that covers this
    /// subscription, but no sooner than its own interval after the last.
    fn pick(&self, latest: Arc<Sample>) -> Option<Arc<Sample>> {
        let mut current = self.current.lock();
        let takes = latest.wanted.covers(&self.spec)
            && current.as_ref().is_none_or(|held| {
                held.snapshot != latest.snapshot
                    && latest.sampled_at >= held.sampled_at + self.due_after(&latest)
            });
        if takes {
            *current = Some(latest);
        }
        current.clone()
    }

    fn due_after(&self, latest: &Sample) -> u64 {
        let interval = self.spec.period();
        let slack = interval.min(latest.period) / 2;
        ((interval - slack).as_nanos() / 100) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use uniproc_windows_core::{ProcessMetric, ProcessMetrics, ProcessState, Report, Tagged};

    use crate::api::MachineMetrics;

    fn spec(ms: u64, metrics: &[ProcessMetric]) -> MetricSpec {
        MetricSpec {
            interval: Duration::from_millis(ms),
            processes: metrics.iter().copied().collect(),
            machine: MachineMetrics::NONE,
        }
    }

    fn publish(feed: &Feed, snapshot: u64, at_ms: u64, wanted: MetricSpec) {
        feed.report(Arc::new(Report {
            processes: Tagged {
                etag: 1,
                value: Arc::from([]),
            },
            states: Arc::<[ProcessState]>::from([]),
            sample: Arc::new(Sample {
                snapshot,
                sampled_at: at_ms * 10_000,
                period: wanted.period(),
                wanted,
                ..Default::default()
            }),
            dropped_by_sink: 0,
            sessions: Vec::new(),
            costs: Vec::new(),
            taken_at: Instant::now(),
        }));
    }

    fn setup() -> (Arc<Feed>, Arc<Subscriptions>, Demand) {
        let demand = Demand::new(Duration::from_secs(2));
        (Arc::new(Feed::new()), Subscriptions::new(demand.clone()), demand)
    }

    #[test]
    fn the_core_samples_the_union_at_the_shortest_interval() {
        let (feed, subscriptions, demand) = setup();
        let a = LocalSampler::new(feed.clone(), &subscriptions, spec(1000, &[ProcessMetric::Handles]));
        let b = LocalSampler::new(feed, &subscriptions, spec(250, &[ProcessMetric::Threads]));
        let now = demand.now();
        assert_eq!(now.interval, Duration::from_millis(250));
        assert!(now.processes.contains(ProcessMetric::Handles) && now.processes.contains(ProcessMetric::Threads));

        drop(b);
        assert_eq!(demand.now().interval, Duration::from_secs(1));
        drop(a);
        assert_eq!(demand.now().processes, ProcessMetrics::NONE);
        assert_eq!(demand.period(), Duration::from_secs(2), "back to the idle period");
        assert_eq!(subscriptions.count(), 0);
    }

    #[test]
    fn a_sample_taken_before_the_subscription_widened_the_union_is_not_answered() {
        let (feed, subscriptions, _) = setup();
        publish(&feed, 1, 0, spec(1000, &[]));
        let sampler = LocalSampler::new(feed.clone(), &subscriptions, spec(1000, &[ProcessMetric::Handles]));
        assert!(sampler.latest().is_none());
        publish(&feed, 2, 100, spec(1000, &[ProcessMetric::Handles]));
        assert_eq!(sampler.latest().unwrap().snapshot, 2);
    }

    #[test]
    fn a_slower_subscriber_sees_every_few_samples_of_a_faster_union() {
        let (feed, subscriptions, _) = setup();
        let wanted = spec(1000, &[ProcessMetric::Handles]);
        let sampler = LocalSampler::new(feed.clone(), &subscriptions, wanted);
        let union = MetricSpec {
            interval: Duration::from_millis(250),
            ..wanted
        };
        let mut seen = Vec::new();
        for n in 0..9 {
            publish(&feed, n + 1, n * 250, union);
            seen.push(sampler.latest().unwrap().snapshot);
        }
        seen.dedup();
        assert_eq!(seen, [1, 5, 9]);
    }

    #[test]
    fn a_long_poll_waits_for_the_next_snapshot() {
        let (feed, subscriptions, _) = setup();
        let wanted = spec(100, &[ProcessMetric::Handles]);
        publish(&feed, 1, 0, wanted);
        let sampler = Arc::new(LocalSampler::new(feed.clone(), &subscriptions, wanted));
        let first = futures::executor::block_on(sampler.sample(0));
        assert_eq!(first.snapshot, 1);

        let waiter = {
            let sampler = sampler.clone();
            std::thread::spawn(move || futures::executor::block_on(sampler.sample(1)).snapshot)
        };
        std::thread::sleep(Duration::from_millis(50));
        publish(&feed, 2, 100, wanted);
        assert_eq!(waiter.join().unwrap(), 2);
    }

    #[test]
    fn a_sampler_gets_only_its_own_columns() {
        let (feed, subscriptions, _) = setup();
        let sampler = LocalSampler::new(feed.clone(), &subscriptions, spec(1000, &[ProcessMetric::Handles]));
        feed.report(Arc::new(Report {
            processes: Tagged {
                etag: 1,
                value: Arc::from([]),
            },
            states: Arc::<[ProcessState]>::from([]),
            sample: Arc::new(Sample {
                snapshot: 1,
                wanted: MetricSpec {
                    interval: Duration::from_secs(1),
                    processes: ProcessMetrics::all(),
                    machine: MachineMetrics::NONE,
                },
                columns: uniproc_windows_core::Columns {
                    handles: Some(Arc::from([1u32])),
                    threads: Some(Arc::from([2u32])),
                    ..Default::default()
                },
                ..Default::default()
            }),
            dropped_by_sink: 0,
            sessions: Vec::new(),
            costs: Vec::new(),
            taken_at: Instant::now(),
        }));
        let sample = sampler.latest().unwrap();
        assert!(sample.columns.handles.is_some());
        assert!(sample.columns.threads.is_none());
    }
}
