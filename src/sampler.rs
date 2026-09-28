use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::Sender;
use parking_lot::Mutex;
use uniproc_agent_kit::Notify;
use uniproc_windows_core::Demand;

use crate::api::{MetricSpec, Sample};
use crate::feed::Published;

/// What a subscriber asks of the painter.
pub(crate) enum Request {
    Subscribe(MetricSpec, Arc<Slot>),
    Unsubscribe(Arc<Slot>),
    /// How often the core samples while nobody subscribes.
    Idle(Duration),
}

/// Where the painter puts a subscriber's next sample, with the lists it was
/// taken against; the subscriber takes the latest there, whole, however many
/// it missed.
pub(crate) struct Slot {
    latest: Mutex<Option<Arc<Published>>>,
    delivered: Notify,
}

impl Slot {
    fn new() -> Self {
        Self {
            latest: Mutex::new(None),
            delivered: Notify::new(),
        }
    }

    fn put(&self, published: Arc<Published>) {
        *self.latest.lock() = Some(published);
        self.delivered.notify();
    }

    fn latest(&self) -> Option<Arc<Published>> {
        self.latest.lock().clone()
    }
}

/// The live subscriptions, kept by the painter: their union is what the
/// core samples, at the shortest interval any of them asks for, and each
/// gets the samples it is due, at its own interval.
pub(crate) struct Subscriptions {
    demand: Demand,
    idle: Duration,
    subscribers: Vec<Subscriber>,
    wake: Box<dyn Fn() + Send>,
}

struct Subscriber {
    spec: MetricSpec,
    slot: Arc<Slot>,
    delivered: Option<Arc<Sample>>,
}

impl Subscriber {
    /// Takes `published` when its sample covers this subscription, but no
    /// sooner than its own interval after the last one delivered.
    fn deliver(&mut self, published: &Arc<Published>) {
        let sample = &published.sample;
        let takes = sample.wanted.covers(&self.spec)
            && self.delivered.as_ref().is_none_or(|held| {
                held.snapshot != sample.snapshot && sample.sampled_at >= held.sampled_at + self.due_after(sample)
            });
        if takes {
            self.delivered = Some(sample.clone());
            self.slot.put(published.clone());
        }
    }

    fn due_after(&self, sample: &Sample) -> u64 {
        let interval = self.spec.period();
        let slack = interval.min(sample.period) / 2;
        ((interval - slack).as_nanos() / 100) as u64
    }
}

impl Subscriptions {
    /// Nobody subscribes yet: the demand is passports and states every
    /// `idle`. `wake` makes the core look at the demand again at once.
    pub fn new(idle: Duration, wake: impl Fn() + Send + 'static) -> Self {
        Self {
            demand: Demand::new(MetricSpec::idle(idle)),
            idle,
            subscribers: Vec::new(),
            wake: Box::new(wake),
        }
    }

    /// What the core samples; these subscriptions set it.
    pub fn demand(&self) -> Demand {
        self.demand.clone()
    }

    /// A new subscriber gets `latest` at once when it covers what it asks.
    pub fn handle(&mut self, request: Request, latest: &Arc<Published>) {
        match request {
            Request::Subscribe(spec, slot) => {
                let mut subscriber = Subscriber {
                    spec,
                    slot,
                    delivered: None,
                };
                subscriber.deliver(latest);
                self.subscribers.push(subscriber);
            }
            Request::Unsubscribe(slot) => self.subscribers.retain(|s| !Arc::ptr_eq(&s.slot, &slot)),
            Request::Idle(idle) => self.idle = idle,
        }
        self.demand.set(self.wanted());
        (self.wake)();
    }

    pub fn deliver(&mut self, published: &Arc<Published>) {
        for subscriber in &mut self.subscribers {
            subscriber.deliver(published);
        }
    }

    fn wanted(&self) -> MetricSpec {
        self.subscribers
            .iter()
            .map(|s| s.spec)
            .reduce(MetricSpec::union)
            .unwrap_or(MetricSpec::idle(self.idle))
    }
}

/// One subscription to the agent running in this process. The core samples
/// while it lives; dropping it stops that, unless someone else wants the same.
pub struct LocalSampler {
    spec: MetricSpec,
    slot: Arc<Slot>,
    requests: Sender<Request>,
}

impl LocalSampler {
    pub(crate) fn subscribe(requests: &Sender<Request>, spec: MetricSpec) -> Self {
        let slot = Arc::new(Slot::new());
        let _ = requests.send(Request::Subscribe(spec, slot.clone()));
        Self {
            spec,
            slot,
            requests: requests.clone(),
        }
    }

    pub fn spec(&self) -> MetricSpec {
        self.spec
    }

    /// The latest sample the agent delivered to this subscription, with only
    /// its own metrics; `None` before the first one that covers them.
    pub fn latest(&self) -> Option<Sample> {
        self.slot.latest().map(|held| held.sample.project(&self.spec))
    }

    /// The latest sample unless its snapshot is `if_none_match`; then the
    /// next one the agent delivers. Dropping the future stops the wait.
    pub async fn sample(&self, if_none_match: u64) -> Sample {
        self.published(if_none_match).await.sample.project(&self.spec)
    }

    /// What the agent published with the latest sample it delivered, unless
    /// that sample is `if_none_match`; then with the next one.
    pub(crate) async fn published(&self, if_none_match: u64) -> Arc<Published> {
        loop {
            let generation = self.slot.delivered.generation();
            if let Some(held) = self.slot.latest()
                && held.sample.snapshot != if_none_match
            {
                return held;
            }
            self.slot.delivered.changed(generation).await;
        }
    }
}

impl Drop for LocalSampler {
    fn drop(&mut self) {
        let _ = self.requests.send(Request::Unsubscribe(self.slot.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::Receiver;
    use uniproc_windows_core::{ProcessMetric, ProcessMetrics};

    use crate::api::MachineMetrics;

    fn spec(ms: u64, metrics: &[ProcessMetric]) -> MetricSpec {
        MetricSpec {
            interval: Duration::from_millis(ms),
            processes: metrics.iter().copied().collect(),
            machine: MachineMetrics::empty(),
        }
    }

    struct Painted {
        subscriptions: Subscriptions,
        requests: Sender<Request>,
        inbox: Receiver<Request>,
        latest: Arc<Published>,
    }

    impl Painted {
        fn new() -> Self {
            let (requests, inbox) = crossbeam_channel::unbounded();
            Self {
                subscriptions: Subscriptions::new(Duration::from_secs(2), || {}),
                requests,
                inbox,
                latest: Arc::new(Published::with(Sample::default())),
            }
        }

        fn subscribe(&mut self, spec: MetricSpec) -> LocalSampler {
            let sampler = LocalSampler::subscribe(&self.requests, spec);
            self.pump();
            sampler
        }

        fn pump(&mut self) {
            for request in self.inbox.try_iter() {
                self.subscriptions.handle(request, &self.latest);
            }
        }

        fn taken(&mut self, sample: Sample) {
            self.latest = Arc::new(Published::with(sample));
            self.subscriptions.deliver(&self.latest);
        }

        fn publish(&mut self, snapshot: u64, at_ms: u64, wanted: MetricSpec) {
            self.taken(Sample {
                snapshot,
                sampled_at: at_ms * 10_000,
                period: wanted.period(),
                wanted,
                ..Default::default()
            });
        }
    }

    #[test]
    fn with_nobody_subscribed_the_core_reads_only_passports_and_states_at_the_idle_period() {
        let mut painted = Painted::new();
        let demand = painted.subscriptions.demand();
        assert_eq!(demand.get(), MetricSpec::idle(Duration::from_secs(2)));
        painted.requests.send(Request::Idle(Duration::from_secs(1))).unwrap();
        painted.pump();
        assert_eq!(demand.get(), MetricSpec::idle(Duration::from_secs(1)));
    }

    #[test]
    fn the_core_samples_the_union_at_the_shortest_interval() {
        let mut painted = Painted::new();
        let demand = painted.subscriptions.demand();
        let a = painted.subscribe(spec(1000, &[ProcessMetric::Handles]));
        let b = painted.subscribe(spec(250, &[ProcessMetric::Threads]));
        let now = demand.get();
        assert_eq!(now.interval, Duration::from_millis(250));
        assert_eq!(now.processes, ProcessMetric::Handles | ProcessMetric::Threads);

        drop(b);
        painted.pump();
        assert_eq!(demand.get().interval, Duration::from_secs(1));
        drop(a);
        painted.pump();
        assert_eq!(demand.get(), MetricSpec::idle(Duration::from_secs(2)), "back to the idle period");
        assert!(painted.subscriptions.subscribers.is_empty());
    }

    #[test]
    fn every_change_wakes_the_core_after_the_demand_is_set() {
        let demand = Arc::new(std::sync::OnceLock::<Demand>::new());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut subscriptions = Subscriptions::new(Duration::from_secs(2), {
            let (demand, seen) = (demand.clone(), seen.clone());
            move || seen.lock().push(demand.get().unwrap().get().interval)
        });
        let _ = demand.set(subscriptions.demand());
        let (requests, inbox) = crossbeam_channel::unbounded();
        let sampler = LocalSampler::subscribe(&requests, spec(250, &[ProcessMetric::Handles]));
        requests.send(Request::Idle(Duration::from_secs(1))).unwrap();
        drop(sampler);
        for request in inbox.try_iter() {
            subscriptions.handle(request, &Arc::new(Published::with(Sample::default())));
        }
        assert_eq!(
            *seen.lock(),
            [Duration::from_millis(250), Duration::from_millis(250), Duration::from_secs(1)]
        );
    }

    #[test]
    fn a_new_subscriber_gets_the_latest_sample_at_once_when_it_covers_it() {
        let mut painted = Painted::new();
        painted.publish(1, 0, spec(1000, &[ProcessMetric::Handles]));
        let sampler = painted.subscribe(spec(1000, &[ProcessMetric::Handles]));
        assert_eq!(sampler.latest().unwrap().snapshot, 1);
    }

    #[test]
    fn a_sample_taken_before_the_subscription_widened_the_union_is_not_delivered() {
        let mut painted = Painted::new();
        painted.publish(1, 0, spec(1000, &[]));
        let sampler = painted.subscribe(spec(1000, &[ProcessMetric::Handles]));
        assert!(sampler.latest().is_none());
        painted.publish(2, 100, spec(1000, &[ProcessMetric::Handles]));
        assert_eq!(sampler.latest().unwrap().snapshot, 2);
    }

    #[test]
    fn a_slower_subscriber_gets_every_few_samples_of_a_faster_union() {
        let mut painted = Painted::new();
        let wanted = spec(1000, &[ProcessMetric::Handles]);
        let sampler = painted.subscribe(wanted);
        let union = MetricSpec {
            interval: Duration::from_millis(250),
            ..wanted
        };
        let mut seen = Vec::new();
        for n in 0..9 {
            painted.publish(n + 1, n * 250, union);
            seen.push(sampler.latest().unwrap().snapshot);
        }
        seen.dedup();
        assert_eq!(seen, [1, 5, 9]);
    }

    #[test]
    fn a_long_poll_waits_for_the_next_delivery() {
        let mut painted = Painted::new();
        let wanted = spec(100, &[ProcessMetric::Handles]);
        painted.publish(1, 0, wanted);
        let sampler = Arc::new(painted.subscribe(wanted));
        let first = futures::executor::block_on(sampler.sample(0));
        assert_eq!(first.snapshot, 1);

        let waiter = {
            let sampler = sampler.clone();
            std::thread::spawn(move || futures::executor::block_on(sampler.sample(1)).snapshot)
        };
        std::thread::sleep(Duration::from_millis(50));
        painted.publish(2, 100, wanted);
        assert_eq!(waiter.join().unwrap(), 2);
    }

    #[test]
    fn a_sampler_gets_only_its_own_columns() {
        let mut painted = Painted::new();
        let sampler = painted.subscribe(spec(1000, &[ProcessMetric::Handles]));
        painted.taken(Sample {
            snapshot: 1,
            wanted: MetricSpec {
                interval: Duration::from_secs(1),
                processes: ProcessMetrics::all(),
                machine: MachineMetrics::empty(),
            },
            columns: uniproc_windows_core::Columns {
                handles: Some(Arc::from([1u32])),
                threads: Some(Arc::from([2u32])),
                ..Default::default()
            },
            ..Default::default()
        });
        let sample = sampler.latest().unwrap();
        assert!(sample.columns.handles.is_some());
        assert!(sample.columns.threads.is_none());
    }
}
