//! Fake client that hunts for transport desyncs and etag mistakes against a
//! running agent:
//!   cargo run --release --example pingpong -- [rounds] [seconds] [pingers] [refreshers]
//!
//! Each round connects, keeps `pingers` pings and `refreshers` UI-style
//! refreshes (getMachine, conditional getServices and getProcesses,
//! getProcessMetrics) in flight on one session for `seconds`, checking every
//! reply, then fires a burst and drops the session in the middle of it. The
//! next round's connect is the check that the agent survived the drop. Every
//! violation is printed with the request and reply it concerns; nothing is
//! retried silently. Exits non-zero if anything was violated.

use std::cell::Cell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::{Duration, Instant};

use ogurpchik::auth::handshake::{HandshakeMode, SchemaId};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::{RpcSession, connect_session};
use uniproc_protocol::meta_capnp::{ResponseStatus, response_meta};
use uniproc_protocol::windows_capnp::windows_agent;
use uniproc_protocol::{APP_NAME, WINDOWS_AGENT_SERVICE, WINDOWS_SCHEMA_ID};

const RECONNECT_DEADLINE: Duration = Duration::from_secs(10);

struct ClientStub;
impl windows_agent::Server for ClientStub {}

#[derive(Default)]
struct Tally {
    pings: Cell<u64>,
    refreshes: Cell<u64>,
    not_modified: Cell<u64>,
    refetches: Cell<u64>,
    unverifiable: Cell<u64>,
    violations: Cell<u64>,
    seq: Cell<u64>,
}

impl Tally {
    fn next_seq(&self) -> u64 {
        let n = self.seq.get() + 1;
        self.seq.set(n);
        n
    }

    fn bump(cell: &Cell<u64>) {
        cell.set(cell.get() + 1);
    }
}

#[derive(Default)]
struct Seen {
    epoch: Cell<u32>,
    processes: Cell<u32>,
    services: Cell<u32>,
}

impl Seen {
    fn check(&self, etag: u64, floor: u32, which: &Cell<u32>) -> Result<(), String> {
        if etag == 0 {
            return Err("a conditional resource answered tag 0".to_string());
        }
        let epoch = (etag >> 32) as u32;
        let generation = etag as u32;
        match self.epoch.get() {
            0 => self.epoch.set(epoch),
            known if known != epoch => {
                return Err(format!(
                    "epoch changed from {known:#x} to {epoch:#x}; only an agent restart may do that"
                ));
            }
            _ => {}
        }
        if generation < floor {
            return Err(format!(
                "generation went back from {floor} to {generation} within epoch {epoch:#x}"
            ));
        }
        which.set(which.get().max(generation));
        Ok(())
    }
}

struct Sent {
    method: &'static str,
    seq: u64,
    detail: String,
    at: Instant,
}

impl Sent {
    fn new(tally: &Tally, method: &'static str, detail: String) -> Self {
        Self {
            method,
            seq: tally.next_seq(),
            detail,
            at: Instant::now(),
        }
    }
}

fn violation(tally: &Tally, origin: Instant, what: &str, sent: &Sent) {
    Tally::bump(&tally.violations);
    println!(
        "VIOLATION: {what}\n  request: {} #{} ({}) sent at {:.3} s, answered after {:.3} ms",
        sent.method,
        sent.seq,
        sent.detail,
        sent.at.duration_since(origin).as_secs_f64(),
        sent.at.elapsed().as_secs_f64() * 1000.0,
    );
}

fn describe_meta(meta: response_meta::Reader) -> String {
    match meta.get_status() {
        Ok(status) => format!("etag {:#x} status {status:?}", meta.get_etag()),
        Err(e) => format!("etag {:#x} status unreadable ({e})", meta.get_etag()),
    }
}

fn check_unconditional(meta: response_meta::Reader) -> Result<(), String> {
    match meta.get_status() {
        Ok(ResponseStatus::Ok) if meta.get_etag() == 0 => Ok(()),
        _ => Err(format!(
            "an unconditional method must answer etag 0 and status ok, got {}",
            describe_meta(meta)
        )),
    }
}

fn check_conditional(meta: response_meta::Reader, if_none_match: u64, has_body: bool) -> Result<bool, String> {
    let etag = meta.get_etag();
    let matched = if_none_match != 0 && if_none_match == etag;
    match meta.get_status() {
        Ok(ResponseStatus::NotModified) if !matched => Err(format!(
            "notModified although ifNoneMatch {if_none_match:#x} is not the current tag; {}",
            describe_meta(meta)
        )),
        Ok(ResponseStatus::NotModified) if has_body => Err(format!(
            "notModified came with a body; {}",
            describe_meta(meta)
        )),
        Ok(ResponseStatus::NotModified) => Ok(false),
        Ok(ResponseStatus::Ok) if matched => Err(format!(
            "full answer although ifNoneMatch {if_none_match:#x} names the current tag; {}",
            describe_meta(meta)
        )),
        Ok(ResponseStatus::Ok) => Ok(true),
        Err(e) => Err(format!("status unreadable: {e}")),
    }
}

#[derive(Default)]
struct View {
    services_etag: u64,
    processes_etag: u64,
    pids: HashSet<u32>,
}

struct Ctx {
    client: windows_agent::Client,
    tally: Rc<Tally>,
    seen: Rc<Seen>,
    origin: Instant,
}

impl Ctx {
    async fn ping(&self) {
        let sent = Sent::new(&self.tally, "ping", String::new());
        let mut req = self.client.ping_request();
        req.get().set_nonce(sent.seq);
        let outcome = match req.send().promise.await {
            Ok(reply) => (|| {
                let r = reply.get().map_err(|e| format!("results unreadable: {e}"))?;
                check_unconditional(r.get_meta().map_err(|e| format!("meta unreadable: {e}"))?)?;
                match r.get_nonce() {
                    n if n == sent.seq => Ok(()),
                    n => Err(format!("nonce {n} answers another call")),
                }
            })(),
            Err(e) => Err(format!("call failed: {e}")),
        };
        match outcome {
            Ok(()) => Tally::bump(&self.tally.pings),
            Err(what) => violation(&self.tally, self.origin, &what, &sent),
        }
    }

    async fn machine(&self) -> bool {
        let sent = Sent::new(&self.tally, "getMachine", String::new());
        let outcome = match self.client.get_machine_request().send().promise.await {
            Ok(reply) => (|| {
                let r = reply.get().map_err(|e| format!("results unreadable: {e}"))?;
                check_unconditional(r.get_meta().map_err(|e| format!("meta unreadable: {e}"))?)?;
                let machine = r.get_machine().map_err(|e| format!("machine unreadable: {e}"))?;
                if machine.get_total_physical_kb() == 0 {
                    return Err("machine stats missing, likely another call's reply".to_string());
                }
                Ok(())
            })(),
            Err(e) => Err(format!("call failed: {e}")),
        };
        outcome
            .map_err(|what| violation(&self.tally, self.origin, &what, &sent))
            .is_ok()
    }

    async fn services(&self, view: &mut View) -> bool {
        let if_none_match = view.services_etag;
        let floor = self.seen.services.get();
        let sent = Sent::new(&self.tally, "getServices", format!("ifNoneMatch {if_none_match:#x}"));
        let mut req = self.client.get_services_request();
        req.get().init_meta().set_if_none_match(if_none_match);
        let outcome = match req.send().promise.await {
            Ok(reply) => (|| {
                let r = reply.get().map_err(|e| format!("results unreadable: {e}"))?;
                let meta = r.get_meta().map_err(|e| format!("meta unreadable: {e}"))?;
                let fresh = check_conditional(meta, if_none_match, r.has_services())?;
                self.seen.check(meta.get_etag(), floor, &self.seen.services)?;
                if fresh {
                    let services = r.get_services().map_err(|e| format!("services unreadable: {e}"))?;
                    if services.is_empty() {
                        return Err(format!("empty service list; {}", describe_meta(meta)));
                    }
                } else {
                    Tally::bump(&self.tally.not_modified);
                }
                Ok(meta.get_etag())
            })(),
            Err(e) => Err(format!("call failed: {e}")),
        };
        match outcome {
            Ok(etag) => {
                view.services_etag = etag;
                true
            }
            Err(what) => {
                violation(&self.tally, self.origin, &what, &sent);
                false
            }
        }
    }

    async fn processes(&self, view: &mut View) -> bool {
        let if_none_match = view.processes_etag;
        let floor = self.seen.processes.get();
        let sent = Sent::new(&self.tally, "getProcesses", format!("ifNoneMatch {if_none_match:#x}"));
        let mut req = self.client.get_processes_request();
        req.get().init_meta().set_if_none_match(if_none_match);
        let outcome = match req.send().promise.await {
            Ok(reply) => (|| {
                let r = reply.get().map_err(|e| format!("results unreadable: {e}"))?;
                let meta = r.get_meta().map_err(|e| format!("meta unreadable: {e}"))?;
                let fresh = check_conditional(meta, if_none_match, r.has_processes())?;
                self.seen.check(meta.get_etag(), floor, &self.seen.processes)?;
                if !fresh {
                    Tally::bump(&self.tally.not_modified);
                    return Ok((meta.get_etag(), None));
                }
                let processes = r.get_processes().map_err(|e| format!("processes unreadable: {e}"))?;
                let mut pids = HashSet::with_capacity(processes.len() as usize);
                for p in processes.iter() {
                    if !pids.insert(p.get_pid()) {
                        return Err(format!("pid {} listed twice; {}", p.get_pid(), describe_meta(meta)));
                    }
                }
                if !pids.contains(&4) {
                    return Err(format!(
                        "System (pid 4) missing from {} processes; {}",
                        pids.len(),
                        describe_meta(meta)
                    ));
                }
                Ok((meta.get_etag(), Some(pids)))
            })(),
            Err(e) => Err(format!("call failed: {e}")),
        };
        match outcome {
            Ok((etag, pids)) => {
                view.processes_etag = etag;
                if let Some(pids) = pids {
                    view.pids = pids;
                }
                true
            }
            Err(what) => {
                violation(&self.tally, self.origin, &what, &sent);
                false
            }
        }
    }

    async fn metrics(&self, view: &mut View) -> bool {
        let floor = self.seen.processes.get();
        let sent = Sent::new(
            &self.tally,
            "getProcessMetrics",
            format!("holding processes {:#x}", view.processes_etag),
        );
        let outcome = match self.client.get_process_metrics_request().send().promise.await {
            Ok(reply) => (|| {
                let r = reply.get().map_err(|e| format!("results unreadable: {e}"))?;
                check_unconditional(r.get_meta().map_err(|e| format!("meta unreadable: {e}"))?)?;
                let tag = r.get_processes_etag();
                self.seen.check(tag, floor, &self.seen.processes)?;
                let metrics = r.get_metrics().map_err(|e| format!("metrics unreadable: {e}"))?;
                let mut pids = HashSet::with_capacity(metrics.len() as usize);
                for m in metrics.iter() {
                    if !pids.insert(m.get_pid()) {
                        return Err(format!("metrics list pid {} twice under {tag:#x}", m.get_pid()));
                    }
                }
                Ok((tag, pids))
            })(),
            Err(e) => Err(format!("call failed: {e}")),
        };
        let (tag, pids) = match outcome {
            Ok(ok) => ok,
            Err(what) => {
                violation(&self.tally, self.origin, &what, &sent);
                return false;
            }
        };

        if tag != view.processes_etag {
            Tally::bump(&self.tally.refetches);
            if !self.processes(view).await {
                return false;
            }
            if tag != view.processes_etag {
                Tally::bump(&self.tally.unverifiable);
                return true;
            }
        }

        if pids != view.pids {
            let extra: Vec<_> = pids.difference(&view.pids).take(5).collect();
            let missing: Vec<_> = view.pids.difference(&pids).take(5).collect();
            violation(
                &self.tally,
                self.origin,
                &format!(
                    "metrics under {tag:#x} cover {} pids, the process list under the same tag {}; extra {extra:?}, missing {missing:?}",
                    pids.len(),
                    view.pids.len()
                ),
                &sent,
            );
            return false;
        }
        true
    }

    async fn refresh(&self, view: &mut View) {
        let ok = self.machine().await
            && self.services(view).await
            && self.processes(view).await
            && self.metrics(view).await;
        if ok {
            Tally::bump(&self.tally.refreshes);
        }
    }
}

async fn connect() -> Result<(RpcSession<windows_agent::Client>, u32, Duration), String> {
    let endpoint = Endpoint::for_service(APP_NAME, WINDOWS_AGENT_SERVICE).map_err(|e| format!("{e:?}"))?;
    let started = Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        match connect_session::<windows_agent::Client, _>(
            &endpoint,
            &HandshakeMode::version_only(),
            SchemaId(WINDOWS_SCHEMA_ID),
            ClientStub,
        )
        .await
        {
            Ok(session) => return Ok((session, attempts, started.elapsed())),
            Err(e) if started.elapsed() >= RECONNECT_DEADLINE => {
                return Err(format!(
                    "agent accepted no session within {RECONNECT_DEADLINE:?} ({attempts} attempts), last error: {e:?}"
                ));
            }
            Err(_) => compio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n.max(1)
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut next = |default: u64| args.next().map_or(default, |s| s.parse().expect("a number"));
    let rounds = next(10);
    let seconds = next(3);
    let pingers = next(32) as usize;
    let refreshers = next(4) as usize;

    let violations = compio::runtime::Runtime::new()
        .unwrap()
        .block_on(run(rounds, Duration::from_secs(seconds), pingers, refreshers));
    std::process::exit(if violations == 0 { 0 } else { 1 });
}

fn spawn_worker(ctx: Rc<Ctx>, pinger: bool, until: Option<Instant>) -> compio::runtime::JoinHandle<()> {
    compio::runtime::spawn(async move {
        let mut view = View::default();
        loop {
            if pinger {
                ctx.ping().await;
            } else {
                ctx.refresh(&mut view).await;
            }
            match until {
                Some(deadline) if Instant::now() < deadline => {}
                _ => break,
            }
        }
    })
}

async fn run(rounds: u64, length: Duration, pingers: usize, refreshers: usize) -> u64 {
    let origin = Instant::now();
    let tally = Rc::new(Tally::default());
    let seen = Rc::new(Seen::default());
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let mut rng = Rng((seed ^ 0x9E37_79B9_7F4A_7C15) | 1);

    for round in 1..=rounds {
        let (session, attempts, took) = match connect().await {
            Ok(connected) => connected,
            Err(what) => {
                Tally::bump(&tally.violations);
                println!("VIOLATION: round {round}: {what}");
                break;
            }
        };
        let ctx = Rc::new(Ctx {
            client: session.remote().clone(),
            tally: tally.clone(),
            seen: seen.clone(),
            origin,
        });

        ctx.refresh(&mut View::default()).await;

        let deadline = Instant::now() + length;
        let steady: Vec<_> = (0..pingers + refreshers)
            .map(|i| spawn_worker(ctx.clone(), i < pingers, Some(deadline)))
            .collect();
        for worker in steady {
            let _ = worker.await;
        }

        let burst: Vec<_> = (0..pingers + refreshers)
            .map(|i| spawn_worker(ctx.clone(), i < pingers, None))
            .collect();
        let cut_after = Duration::from_micros(rng.below(15_000));
        compio::time::sleep(cut_after).await;
        drop(burst);
        drop(ctx);
        drop(session);

        println!(
            "round {round}: connected after {attempts} attempt(s) in {:.1} ms; totals {} pings, {} refreshes ({} notModified, {} refetches, {} unverifiable), {} violations; cut {:.1} ms into a burst",
            took.as_secs_f64() * 1000.0,
            tally.pings.get(),
            tally.refreshes.get(),
            tally.not_modified.get(),
            tally.refetches.get(),
            tally.unverifiable.get(),
            tally.violations.get(),
            cut_after.as_secs_f64() * 1000.0,
        );
    }

    match connect().await {
        Ok((session, attempts, took)) => {
            let ctx = Ctx {
                client: session.remote().clone(),
                tally: tally.clone(),
                seen: seen.clone(),
                origin,
            };
            ctx.refresh(&mut View::default()).await;
            println!(
                "after the last cut: connected after {attempts} attempt(s) in {:.1} ms, state checked",
                took.as_secs_f64() * 1000.0
            );
        }
        Err(what) => {
            Tally::bump(&tally.violations);
            println!("VIOLATION: after the last cut: {what}");
        }
    }

    println!(
        "done: {} pings, {} refreshes ({} notModified, {} refetches, {} unverifiable), {} violations; epoch {:#x}",
        tally.pings.get(),
        tally.refreshes.get(),
        tally.not_modified.get(),
        tally.refetches.get(),
        tally.unverifiable.get(),
        tally.violations.get(),
        seen.epoch.get(),
    );
    tally.violations.get()
}
