use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tracing::Subscriber;
use tracing::span::{Attributes, Id};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::{LookupSpan, Registry};
use tracing_subscriber::{EnvFilter, Layer, reload};

/// What the state API shows of the agent's tracing, and the log filter it
/// can change while the agent runs.
pub struct Telemetry {
    pub spans: Spans,
    pub filter: reload::Handle<EnvFilter, Registry>,
}

/// A layer that keeps how long each span stays entered, by name, over
/// every time it ran.
#[derive(Clone, Default)]
pub struct Spans(Arc<Mutex<BTreeMap<&'static str, Cost>>>);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    pub runs: u64,
    pub last: Duration,
    pub mean: Duration,
    pub max: Duration,
}

impl Cost {
    fn record(&mut self, took: Duration) {
        self.runs += 1;
        self.last = took;
        self.max = self.max.max(took);
        let total = self.mean.as_nanos() * (self.runs as u128 - 1) + took.as_nanos();
        self.mean = Duration::from_nanos((total / self.runs as u128) as u64);
    }
}

struct Busy {
    entered: Option<Instant>,
    busy: Duration,
}

impl Spans {
    pub fn costs(&self) -> Vec<(&'static str, Cost)> {
        let costs = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        costs.iter().map(|(&name, &cost)| (name, cost)).collect()
    }
}

impl<S> Layer<S> for Spans
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, _: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(Busy {
                entered: None,
                busy: Duration::ZERO,
            });
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(busy) = span.extensions_mut().get_mut::<Busy>()
        {
            busy.entered = Some(Instant::now());
        }
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(busy) = span.extensions_mut().get_mut::<Busy>()
            && let Some(entered) = busy.entered.take()
        {
            busy.busy += entered.elapsed();
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let Some(took) = span.extensions().get::<Busy>().map(|b| b.busy) else { return };
        let mut costs = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        costs.entry(span.name()).or_default().record(took);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn a_span_costs_the_time_it_was_entered_and_not_the_time_between() {
        let spans = Spans::default();
        let subscriber = tracing_subscriber::registry().with(spans.clone());
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..2 {
                let span = tracing::info_span!("probe");
                span.in_scope(|| std::thread::sleep(Duration::from_millis(20)));
                std::thread::sleep(Duration::from_millis(50));
                span.in_scope(|| std::thread::sleep(Duration::from_millis(20)));
            }
        });
        let costs = spans.costs();
        let [("probe", cost)] = costs[..] else { panic!("{costs:?}") };
        assert_eq!(cost.runs, 2);
        assert!(cost.last >= Duration::from_millis(40), "{cost:?}");
        assert!(cost.max < Duration::from_millis(90), "{cost:?}");
    }

    #[test]
    fn a_cost_keeps_its_mean_and_worst() {
        let mut cost = Cost::default();
        for ms in [10, 20, 30] {
            cost.record(Duration::from_millis(ms));
        }
        assert_eq!((cost.runs, cost.last, cost.max), (3, Duration::from_millis(30), Duration::from_millis(30)));
        assert_eq!(cost.mean, Duration::from_millis(20));
    }
}
