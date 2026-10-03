use std::cell::{Cell, RefCell};
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use capnp::capability::Response;
use futures::channel::{mpsc, oneshot};
use futures::{Stream, StreamExt};
use ogurpchik::auth::handshake::{HandshakeMode, authenticate_client};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::{RpcSession, Side, spawn_session};
use uniproc_protocol::meta_capnp::{ResponseStatus, response_meta};
use uniproc_protocol::windows_capnp::{
    agent_listener, process_event_listener, sampler, service_watcher, windows_agent,
};
use uniproc_protocol::{APP_NAME, WINDOWS_AGENT_SERVICE};

use crate::api::{
    Changes, Command, CommandResult, MetricSpec, ProcessEventBatch, ProcessInfo, ProcessStates, Sample,
    ServiceStats, ServiceStatus, Snapshot, Tagged, Update,
};
use crate::wire::{self, PROTOCOL, decode, encode};

pub use ogurpchik::auth::handshake::Version;

const CALL_TIMEOUT: Duration = Duration::from_secs(45);
const JOIN_ATTEMPTS: usize = 3;

enum Request {
    Ping,
    Snapshot,
    Subscribe {
        spec: MetricSpec,
        calls: mpsc::UnboundedReceiver<SampleCall>,
    },
    Run(Command),
    Watch {
        name: String,
        statuses: mpsc::UnboundedSender<ServiceStatus>,
        released: oneshot::Receiver<()>,
    },
    WatchAgent {
        spec: MetricSpec,
        updates: mpsc::UnboundedSender<Delivery<Update>>,
        released: oneshot::Receiver<()>,
    },
    WatchProcessEvents {
        batches: mpsc::UnboundedSender<Delivery<ProcessEventBatch>>,
        released: oneshot::Receiver<()>,
    },
}

/// One push for a watch's reader; the agent hears back once it is taken.
struct Delivery<T> {
    pushed: Result<T>,
    taken: oneshot::Sender<()>,
}

/// What a watch's reader takes next: the push the agent made, or why the watch is over.
async fn take<T>(rx: &mut mpsc::UnboundedReceiver<Delivery<T>>) -> Result<T> {
    let delivery = rx.next().await.ok_or_else(|| anyhow!("the agent watch ended"))?;
    let _ = delivery.taken.send(());
    delivery.pushed
}

/// Hands `pushed` to the watch's reader and waits until it is taken.
async fn deliver<T>(rx: &mpsc::UnboundedSender<Delivery<T>>, pushed: Result<T>) -> Result<(), capnp::Error> {
    let (taken, answer) = oneshot::channel();
    rx.unbounded_send(Delivery { pushed, taken })
        .map_err(|_| capnp::Error::failed("nobody watches the agent any more".into()))?;
    answer
        .await
        .map_err(|_| capnp::Error::failed("nobody watches the agent any more".into()))
}

enum Reply {
    Pong,
    Snapshot(Option<Snapshot>),
    Subscribed,
    Code(CommandResult),
    Watching,
}

struct SampleCall {
    if_none_match: u64,
    reply: oneshot::Sender<Result<Sample>>,
}

struct Envelope {
    request: Request,
    reply: oneshot::Sender<Result<Reply>>,
}

/// A connection to the agent service. Clones share it; it closes when the last one is dropped.
///
/// Every session lives on one I/O thread with its own compio runtime,
/// started on the first connect and kept for the process, so the calls
/// work from any executor. A call that fails means the session is gone:
/// connect again.
#[derive(Clone)]
pub struct Remote {
    tx: mpsc::UnboundedSender<Envelope>,
    agent: Version,
}

impl Remote {
    /// The windows schema version the agent said it speaks in the handshake.
    pub fn agent_version(&self) -> Version {
        self.agent
    }

    /// Whether the agent has `watch`; one older than windows 2.2 has only
    /// `subscribe`.
    pub fn can_watch(&self) -> bool {
        wire::takes_watch(self.agent)
    }

    /// Connects to the service, waiting up to `give_up_after` for its pipe to appear.
    pub async fn connect(give_up_after: Duration) -> Result<Self> {
        Self::connect_to(WINDOWS_AGENT_SERVICE, give_up_after).await
    }

    /// Connects to an agent serving under another pipe name.
    pub async fn connect_to(service: &str, give_up_after: Duration) -> Result<Self> {
        let service = service.to_string();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (tx, rx) = mpsc::unbounded();

        submit(Box::new(move || {
            compio::runtime::spawn(serve(service, give_up_after, ready_tx, rx)).detach();
        }))?;

        let agent = ready_rx
            .await
            .map_err(|_| anyhow!("the agent I/O thread stopped before connecting"))??;
        Ok(Self { tx, agent })
    }

    async fn call(&self, request: Request) -> Result<Reply> {
        let (reply, answer) = oneshot::channel();
        self.tx
            .unbounded_send(Envelope { request, reply })
            .map_err(|_| anyhow!("the agent connection is closed"))?;
        answer
            .await
            .map_err(|_| anyhow!("the agent connection dropped the call"))?
    }

    pub async fn ping(&self) -> Result<()> {
        match self.call(Request::Ping).await? {
            Reply::Pong => Ok(()),
            _ => bail!("a ping answered with something else"),
        }
    }

    /// None when the process list kept changing under the states for every attempt to join them.
    pub async fn snapshot(&self) -> Result<Option<Snapshot>> {
        match self.call(Request::Snapshot).await? {
            Reply::Snapshot(snapshot) => Ok(snapshot),
            _ => bail!("a snapshot answered with something else"),
        }
    }

    /// The agent samples for it until the sampler is dropped.
    pub async fn subscribe(&self, spec: MetricSpec) -> Result<RemoteSampler> {
        let (tx, calls) = mpsc::unbounded();
        let spec = wire::known_to(self.agent, spec);
        match self.call(Request::Subscribe { spec, calls }).await? {
            Reply::Subscribed => Ok(RemoteSampler { calls: tx }),
            _ => bail!("a subscribe answered with something else"),
        }
    }

    pub async fn run(&self, command: Command) -> Result<CommandResult> {
        match self.call(Request::Run(command)).await? {
            Reply::Code(code) => Ok(code),
            _ => bail!("a command answered with something else"),
        }
    }

    /// The service's status now, then every change; ends when the service
    /// is gone, cannot be opened, or the session ends.
    pub async fn watch_service(&self, name: &str) -> Result<impl Stream<Item = ServiceStatus> + Send + Unpin + 'static> {
        let (statuses, rx) = mpsc::unbounded();
        let (release, released) = oneshot::channel();
        let request = Request::Watch {
            name: name.to_string(),
            statuses,
            released,
        };
        match self.call(request).await? {
            Reply::Watching => Ok(Watch { rx, _release: release }),
            _ => bail!("a watch answered with something else"),
        }
    }

    /// The agent pushes every sample `spec` is due, with the lists it was
    /// taken against, until the watch is dropped. An agent that cannot
    /// watch ([`Remote::can_watch`]) is refused here, before anything is sent.
    pub async fn watch(&self, spec: MetricSpec) -> Result<RemoteWatch> {
        if !self.can_watch() {
            bail!("the agent speaks windows {}; watch needs 2.2", self.agent);
        }
        let (updates, rx) = mpsc::unbounded();
        let (release, released) = oneshot::channel();
        let request = Request::WatchAgent {
            spec: wire::known_to(self.agent, spec),
            updates,
            released,
        };
        match self.call(request).await? {
            Reply::Watching => Ok(RemoteWatch { rx, _release: release }),
            _ => bail!("a watch answered with something else"),
        }
    }

    /// Whether the agent has `watchProcessEvents`, which came in windows 2.8.
    pub fn can_watch_process_events(&self) -> bool {
        wire::takes_process_events(self.agent)
    }

    /// The process starts and exits the agent holds, about the last hour,
    /// then each one as it happens, until the watch is dropped. An agent
    /// that cannot tell them is refused here, before anything is sent.
    pub async fn watch_process_events(&self) -> Result<RemoteProcessEvents> {
        if !self.can_watch_process_events() {
            bail!("the agent speaks windows {}; watchProcessEvents needs 2.8", self.agent);
        }
        let (batches, rx) = mpsc::unbounded();
        let (release, released) = oneshot::channel();
        match self.call(Request::WatchProcessEvents { batches, released }).await? {
            Reply::Watching => Ok(RemoteProcessEvents { rx, _release: release }),
            _ => bail!("a watch answered with something else"),
        }
    }
}

/// A watch over the pipe; the agent stops pushing when this is dropped.
pub struct RemoteWatch {
    rx: mpsc::UnboundedReceiver<Delivery<Update>>,
    _release: oneshot::Sender<()>,
}

impl RemoteWatch {
    /// The next update the agent pushed; the first carries everything. An
    /// error means the watch is over: the agent stopped or the session ended.
    pub async fn next(&mut self) -> Result<Update> {
        take(&mut self.rx).await
    }
}

/// The process starts and exits over the pipe; the agent stops telling them when this is dropped.
pub struct RemoteProcessEvents {
    rx: mpsc::UnboundedReceiver<Delivery<ProcessEventBatch>>,
    _release: oneshot::Sender<()>,
}

impl RemoteProcessEvents {
    /// The next batch the agent told; the first carries `history_from`. An
    /// error means the watch is over: the agent stopped or the session ended.
    pub async fn next(&mut self) -> Result<ProcessEventBatch> {
        take(&mut self.rx).await
    }
}

/// One subscription over the pipe; the agent releases it when this is dropped.
pub struct RemoteSampler {
    calls: mpsc::UnboundedSender<SampleCall>,
}

impl RemoteSampler {
    /// The latest sample, or the next one when the latest is `if_none_match`.
    pub async fn sample(&self, if_none_match: u64) -> Result<Sample> {
        let (reply, answer) = oneshot::channel();
        self.calls
            .unbounded_send(SampleCall { if_none_match, reply })
            .map_err(|_| anyhow!("the agent connection is closed"))?;
        answer
            .await
            .map_err(|_| anyhow!("the agent connection dropped the call"))?
    }
}

struct Watch {
    rx: mpsc::UnboundedReceiver<ServiceStatus>,
    _release: oneshot::Sender<()>,
}

impl Stream for Watch {
    type Item = ServiceStatus;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<ServiceStatus>> {
        Pin::new(&mut self.rx).poll_next(cx)
    }
}

type Job = Box<dyn FnOnce() + Send>;

static IO: Mutex<Option<mpsc::UnboundedSender<Job>>> = Mutex::new(None);

/// Runs `job` on the one thread whose compio runtime holds every session, starting it on first use.
fn submit(job: Job) -> Result<()> {
    let mut io = IO.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let job = match io.as_ref() {
        Some(jobs) => match jobs.unbounded_send(job) {
            Ok(()) => return Ok(()),
            Err(refused) => refused.into_inner(),
        },
        None => job,
    };

    let (jobs, queue) = mpsc::unbounded::<Job>();
    std::thread::Builder::new()
        .name("agent-remote-io".into())
        .spawn(move || run_io(queue))?;
    jobs.unbounded_send(job)
        .map_err(|_| anyhow!("the agent I/O thread stopped at once"))?;
    *io = Some(jobs);
    Ok(())
}

fn run_io(mut queue: mpsc::UnboundedReceiver<Job>) {
    let runtime = match compio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => return tracing::error!(%error, "the agent I/O thread has no compio runtime"),
    };
    runtime.block_on(async move {
        while let Some(job) = queue.next().await {
            job();
        }
    });
}

async fn serve(
    service: String,
    give_up_after: Duration,
    ready: oneshot::Sender<Result<Version>>,
    mut rx: mpsc::UnboundedReceiver<Envelope>,
) {
    let (session, agent) = match Session::connect(&service, give_up_after).await {
        Ok((session, agent)) => (Rc::new(session), agent),
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready.send(Ok(agent)).is_err() {
        return;
    }

    while let Some(envelope) = rx.next().await {
        let session = session.clone();
        compio::runtime::spawn(async move {
            let result = compio::time::timeout(CALL_TIMEOUT, session.dispatch(envelope.request))
                .await
                .unwrap_or_else(|_| Err(anyhow!("no reply from the agent within {CALL_TIMEOUT:?}")));
            let _ = envelope.reply.send(result);
        })
        .detach();
    }
}

async fn answer_samples(
    sampler: sampler::Client,
    spec: MetricSpec,
    mut calls: mpsc::UnboundedReceiver<SampleCall>,
) {
    let timeout = spec.period() + CALL_TIMEOUT;
    while let Some(call) = calls.next().await {
        let result = compio::time::timeout(timeout, fetch_sample(&sampler, spec, call.if_none_match))
            .await
            .unwrap_or_else(|_| Err(anyhow!("no sample from the agent within {timeout:?}")));
        let _ = call.reply.send(result);
    }
}

async fn fetch_sample(sampler: &sampler::Client, spec: MetricSpec, if_none_match: u64) -> Result<Sample> {
    let mut request = sampler.sample_request();
    request.get().init_meta().set_if_none_match(if_none_match);
    let reply = request.send().promise.await?;
    let reply = reply.get()?;
    Ok(decode::sample(reply.get_processes()?, reply.get_machine()?, spec)?)
}

struct ClientStub;
impl windows_agent::Server for ClientStub {}

struct WatcherImpl {
    statuses: RefCell<Option<mpsc::UnboundedSender<ServiceStatus>>>,
}

impl service_watcher::Server for WatcherImpl {
    async fn changed(
        self: Rc<Self>,
        params: service_watcher::ChangedParams,
        _: service_watcher::ChangedResults,
    ) -> Result<(), capnp::Error> {
        let status = decode::service_status(params.get()?.get_status()?);
        let delivered = self
            .statuses
            .borrow()
            .as_ref()
            .is_some_and(|statuses| statuses.unbounded_send(status).is_ok());
        if delivered {
            Ok(())
        } else {
            Err(capnp::Error::failed("nobody watches this service any more".into()))
        }
    }

    async fn ended(
        self: Rc<Self>,
        _: service_watcher::EndedParams,
        _: service_watcher::EndedResults,
    ) -> Result<(), capnp::Error> {
        self.statuses.borrow_mut().take();
        Ok(())
    }
}

struct ListenerImpl {
    spec: MetricSpec,
    snapshot: RefCell<Option<Snapshot>>,
    updates: mpsc::UnboundedSender<Delivery<Update>>,
    session: Weak<Session>,
}

impl ListenerImpl {
    /// None when the lists came in a form this client does not know.
    fn decode(&self, params: &agent_listener::UpdateParams) -> Result<Option<Update>> {
        let params = params.get()?;
        let Some((snapshot, changes)) = decode::lists(self.snapshot.borrow().as_ref(), params.get_lists()?)? else {
            return Ok(None);
        };
        let sample = decode::sample(params.get_processes()?, params.get_machine()?, self.spec)?;
        *self.snapshot.borrow_mut() = Some(snapshot.clone());
        Ok(Some(Update {
            snapshot,
            sample,
            changes,
        }))
    }

    /// The update with the lists read afresh through the session, all of
    /// them counted as new.
    async fn resync(&self, params: &agent_listener::UpdateParams) -> Result<Update> {
        let sample = {
            let params = params.get()?;
            decode::sample(params.get_processes()?, params.get_machine()?, self.spec)?
        };
        let session = self.session.upgrade().ok_or_else(|| anyhow!("the agent session ended"))?;
        let snapshot = session
            .snapshot()
            .await?
            .ok_or_else(|| anyhow!("the lists kept changing while they were read afresh"))?;
        *self.snapshot.borrow_mut() = Some(snapshot.clone());
        Ok(Update {
            snapshot,
            sample,
            changes: Changes {
                full: true,
                ..Changes::default()
            },
        })
    }

    async fn deliver(&self, update: Result<Update>) -> Result<(), capnp::Error> {
        deliver(&self.updates, update).await
    }
}

impl agent_listener::Server for ListenerImpl {
    async fn update(
        self: Rc<Self>,
        params: agent_listener::UpdateParams,
        _: agent_listener::UpdateResults,
    ) -> Result<(), capnp::Error> {
        let update = match self.decode(&params) {
            Ok(Some(update)) => Ok(update),
            Ok(None) => self.resync(&params).await,
            Err(e) => Err(e),
        };
        let failed = update.as_ref().err().map(|e| capnp::Error::failed(format!("{e:#}")));
        self.deliver(update).await?;
        failed.map_or(Ok(()), Err)
    }

    async fn ended(
        self: Rc<Self>,
        _: agent_listener::EndedParams,
        _: agent_listener::EndedResults,
    ) -> Result<(), capnp::Error> {
        let _ = self.deliver(Err(anyhow!("the agent stopped"))).await;
        Ok(())
    }
}

struct ProcessEventListenerImpl {
    batches: mpsc::UnboundedSender<Delivery<ProcessEventBatch>>,
}

impl process_event_listener::Server for ProcessEventListenerImpl {
    async fn events(
        self: Rc<Self>,
        params: process_event_listener::EventsParams,
        _: process_event_listener::EventsResults,
    ) -> Result<(), capnp::Error> {
        let batch = decode::process_event_batch(params.get()?.get_batch()?).map_err(anyhow::Error::from);
        let failed = batch.as_ref().err().map(|e| capnp::Error::failed(format!("{e:#}")));
        deliver(&self.batches, batch).await?;
        failed.map_or(Ok(()), Err)
    }

    async fn ended(
        self: Rc<Self>,
        _: process_event_listener::EndedParams,
        _: process_event_listener::EndedResults,
    ) -> Result<(), capnp::Error> {
        let _ = deliver(&self.batches, Err(anyhow!("the agent stopped"))).await;
        Ok(())
    }
}

#[derive(Default)]
struct Cache {
    services: Option<Tagged<Arc<[ServiceStats]>>>,
    processes: Option<Tagged<Arc<[ProcessInfo]>>>,
    states: Option<Tagged<ProcessStates>>,
}

fn etag<T>(held: &Option<Tagged<T>>) -> u64 {
    held.as_ref().map_or(0, |t| t.etag)
}

/// Whether the agent left the payload out because the caller's tag still
/// holds. A status this client does not know is an error, so nothing is
/// kept under its etag.
fn not_modified(meta: response_meta::Reader<'_>) -> Result<bool> {
    match meta.get_status() {
        Ok(ResponseStatus::Ok) => Ok(false),
        Ok(ResponseStatus::NotModified) => Ok(true),
        Err(capnp::NotInSchema(status)) => bail!("the agent answered with status {status}, which this client does not know"),
    }
}

struct Session {
    rpc: RpcSession<windows_agent::Client>,
    cache: RefCell<Cache>,
    nonce: Cell<u64>,
}

impl Session {
    async fn connect(service: &str, give_up_after: Duration) -> Result<(Self, Version)> {
        let endpoint = Endpoint::for_service(APP_NAME, service).map_err(|e| anyhow!("{e:?}"))?;
        let mut conn = endpoint
            .connect_ready(give_up_after)
            .await
            .map_err(|e| anyhow!("{e:?}"))?;
        let agent = authenticate_client(&mut conn, &HandshakeMode::version_only(), PROTOCOL)
            .await
            .map_err(|e| anyhow!("{e:?}"))?
            .ok_or_else(|| anyhow!("the agent did not say its version"))?;
        let session = Self {
            rpc: spawn_session(conn, Side::Client, ClientStub),
            cache: RefCell::new(Cache::default()),
            nonce: Cell::new(0),
        };
        Ok((session, agent))
    }

    fn client(&self) -> &windows_agent::Client {
        self.rpc.remote()
    }

    async fn dispatch(self: Rc<Self>, request: Request) -> Result<Reply> {
        match request {
            Request::Ping => self.ping().await.map(|()| Reply::Pong),
            Request::Snapshot => self.snapshot().await.map(Reply::Snapshot),
            Request::Subscribe { spec, calls } => {
                let mut request = self.client().subscribe_request();
                encode::metric_spec(&spec, request.get().init_spec());
                let sampler = request.send().promise.await?.get()?.get_sampler()?;
                compio::runtime::spawn(answer_samples(sampler, spec, calls)).detach();
                Ok(Reply::Subscribed)
            }
            Request::Run(command) => self.run(command).await.map(Reply::Code),
            Request::Watch {
                name,
                statuses,
                released,
            } => {
                let watcher = WatcherImpl {
                    statuses: RefCell::new(Some(statuses)),
                };
                let mut request = self.client().watch_service_request();
                request.get().set_name(&name);
                request.get().set_watcher(capnp_rpc::new_client(watcher));
                let handle = request.send().promise.await?.get()?.get_handle()?;
                compio::runtime::spawn(async move {
                    let _handle = handle;
                    let _ = released.await;
                })
                .detach();
                Ok(Reply::Watching)
            }
            Request::WatchAgent { spec, updates, released } => {
                let listener = ListenerImpl {
                    spec,
                    snapshot: RefCell::new(None),
                    updates,
                    session: Rc::downgrade(&self),
                };
                let mut request = self.client().watch_request();
                encode::metric_spec(&spec, request.get().init_spec());
                request.get().set_listener(capnp_rpc::new_client(listener));
                let handle = request.send().promise.await?.get()?.get_handle()?;
                compio::runtime::spawn(async move {
                    let _handle = handle;
                    let _ = released.await;
                })
                .detach();
                Ok(Reply::Watching)
            }
            Request::WatchProcessEvents { batches, released } => {
                let mut request = self.client().watch_process_events_request();
                request
                    .get()
                    .set_listener(capnp_rpc::new_client(ProcessEventListenerImpl { batches }));
                let handle = request.send().promise.await?.get()?.get_handle()?;
                compio::runtime::spawn(async move {
                    let _handle = handle;
                    let _ = released.await;
                })
                .detach();
                Ok(Reply::Watching)
            }
        }
    }

    async fn ping(&self) -> Result<()> {
        let nonce = self.nonce.get().wrapping_add(1);
        self.nonce.set(nonce);
        let mut request = self.client().ping_request();
        request.get().set_nonce(nonce);
        let echoed = request.send().promise.await?.get()?.get_nonce();
        if echoed != nonce {
            bail!("the agent echoed nonce {echoed} to ping {nonce}");
        }
        Ok(())
    }

    async fn fetch_processes(
        &self,
        if_none_match: u64,
    ) -> Result<Response<windows_agent::get_processes_results::Owned>> {
        let mut request = self.client().get_processes_request();
        request.get().init_meta().set_if_none_match(if_none_match);
        Ok(request.send().promise.await?)
    }

    fn keep_processes(&self, reply: &Response<windows_agent::get_processes_results::Owned>) -> Result<()> {
        let reply = reply.get()?;
        let meta = reply.get_meta()?;
        if !not_modified(meta)? {
            self.cache.borrow_mut().processes = Some(Tagged {
                etag: meta.get_etag(),
                value: decode::processes(reply.get_processes()?)?,
            });
        }
        Ok(())
    }

    fn keep_services(&self, reply: &Response<windows_agent::get_services_results::Owned>) -> Result<()> {
        let reply = reply.get()?;
        let meta = reply.get_meta()?;
        if !not_modified(meta)? {
            self.cache.borrow_mut().services = Some(Tagged {
                etag: meta.get_etag(),
                value: decode::services(reply.get_services()?)?,
            });
        }
        Ok(())
    }

    async fn fetch_states(
        &self,
        if_none_match: u64,
    ) -> Result<Response<windows_agent::get_process_states_results::Owned>> {
        let mut request = self.client().get_process_states_request();
        request.get().init_meta().set_if_none_match(if_none_match);
        Ok(request.send().promise.await?)
    }

    fn keep_states(&self, reply: &Response<windows_agent::get_process_states_results::Owned>) -> Result<()> {
        let reply = reply.get()?;
        let meta = reply.get_meta()?;
        if !not_modified(meta)? {
            self.cache.borrow_mut().states = Some(Tagged {
                etag: meta.get_etag(),
                value: ProcessStates {
                    passport_etag: reply.get_passport_etag(),
                    states: decode::process_states(reply.get_states()?),
                },
            });
        }
        Ok(())
    }

    fn joined(&self) -> Option<u64> {
        let cache = self.cache.borrow();
        let passport_etag = cache.states.as_ref()?.value.passport_etag;
        (etag(&cache.processes) == passport_etag).then_some(passport_etag)
    }

    async fn snapshot(&self) -> Result<Option<Snapshot>> {
        let (services_etag, processes_etag, states_etag) = {
            let cache = self.cache.borrow();
            (etag(&cache.services), etag(&cache.processes), etag(&cache.states))
        };

        let mut services = self.client().get_services_request();
        services.get().init_meta().set_if_none_match(services_etag);
        let services = services.send().promise;
        let processes = self.fetch_processes(processes_etag);
        let states = self.fetch_states(states_etag);
        let (services, processes, states) = futures::join!(services, processes, states);

        self.keep_services(&services?)?;
        self.keep_processes(&processes?)?;
        self.keep_states(&states?)?;

        for _ in 0..JOIN_ATTEMPTS {
            if self.joined().is_some() {
                break;
            }
            let held = etag(&self.cache.borrow().processes);
            self.keep_processes(&self.fetch_processes(held).await?)?;
            if self.joined().is_some() {
                break;
            }
            let held = etag(&self.cache.borrow().states);
            self.keep_states(&self.fetch_states(held).await?)?;
        }

        if self.joined().is_none() {
            return Ok(None);
        }
        let cache = self.cache.borrow();
        let (Some(services), Some(processes), Some(states)) =
            (cache.services.clone(), cache.processes.clone(), cache.states.clone())
        else {
            return Ok(None);
        };
        Ok(Some(Snapshot {
            services,
            processes,
            states,
        }))
    }

    async fn run(&self, command: Command) -> Result<CommandResult> {
        let client = self.client();
        macro_rules! by_pid {
            ($request:ident, $pid:expr) => {{
                let mut request = client.$request();
                request.get().set_pid($pid);
                request.send().promise.await?.get()?.get_code()
            }};
        }
        macro_rules! by_name {
            ($request:ident, $name:expr) => {{
                let mut request = client.$request();
                request.get().set_name(&$name);
                request.send().promise.await?.get()?.get_code()
            }};
        }

        let code = match command {
            Command::Kill { pid } => by_pid!(kill_request, pid),
            Command::Suspend { pid } => by_pid!(suspend_request, pid),
            Command::Resume { pid } => by_pid!(resume_request, pid),
            Command::SetPriority { pid, priority } => {
                let mut request = client.set_priority_request();
                request.get().set_pid(pid);
                request.get().set_priority(encode::priority(priority));
                request.send().promise.await?.get()?.get_code()
            }
            Command::SetAffinity { pid, mask } => {
                let mut request = client.set_affinity_request();
                request.get().set_pid(pid);
                request.get().set_mask(mask);
                request.send().promise.await?.get()?.get_code()
            }
            Command::ServiceStart { name } => by_name!(service_start_request, name),
            Command::ServiceStop { name } => by_name!(service_stop_request, name),
            Command::ServicePause { name } => by_name!(service_pause_request, name),
            Command::ServiceResume { name } => by_name!(service_resume_request, name),
            Command::ServiceRestart { name } => by_name!(service_restart_request, name),
        };
        Ok(if code == 0 { Ok(()) } else { Err(code) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniproc_protocol::windows_capnp::watch_handle;

    fn io_thread() -> std::thread::ThreadId {
        let (tx, rx) = std::sync::mpsc::channel();
        submit(Box::new(move || {
            let _ = tx.send(std::thread::current().id());
        }))
        .unwrap();
        rx.recv_timeout(Duration::from_secs(5)).expect("the job ran")
    }

    #[test]
    fn every_connection_shares_one_io_thread() {
        let first = io_thread();
        assert_ne!(first, std::thread::current().id());
        assert_eq!(io_thread(), first);
    }

    #[test]
    fn a_pipe_nobody_serves_is_an_error_every_time() {
        assert!(Endpoint::for_service(APP_NAME, "uniproc-no-agent-serves-this").is_ok());
        for _ in 0..2 {
            let connected = futures::executor::block_on(Remote::connect_to(
                "uniproc-no-agent-serves-this",
                Duration::from_millis(200),
            ));
            assert!(connected.is_err());
        }
    }

    fn meta_with_status(status: u16) -> Vec<u8> {
        let mut words = Vec::new();
        words.extend_from_slice(&0x0000_0002_0000_0000u64.to_le_bytes());
        words.extend_from_slice(&7u64.to_le_bytes());
        words.extend_from_slice(&(status as u64).to_le_bytes());
        words
    }

    #[test]
    fn a_status_this_client_does_not_know_is_an_error() {
        let read = |status: u16| {
            let words = meta_with_status(status);
            let segments: &[&[u8]] = &[&words];
            let message = capnp::message::Reader::new(capnp::message::SegmentArray::new(segments), Default::default());
            let meta = message.get_root::<response_meta::Reader>().unwrap();
            assert_eq!(meta.get_etag(), 7);
            not_modified(meta).map_err(|e| e.to_string())
        };
        assert_eq!(read(0), Ok(false));
        assert_eq!(read(1), Ok(true));
        assert!(read(2).is_err_and(|e| e.contains("status 2")));
    }

    #[derive(Clone)]
    struct Answering;

    impl windows_agent::Server for Answering {}

    /// Tells its one batch to whoever watches process events, then that it stopped.
    #[derive(Clone)]
    struct Telling(ProcessEventBatch);

    struct Released;

    impl watch_handle::Server for Released {}

    impl windows_agent::Server for Telling {
        async fn watch_process_events(
            self: Rc<Self>,
            params: windows_agent::WatchProcessEventsParams,
            mut results: windows_agent::WatchProcessEventsResults,
        ) -> Result<(), capnp::Error> {
            let listener = params.get()?.get_listener()?;
            let batch = self.0.clone();
            compio::runtime::spawn(async move {
                let mut request = listener.events_request();
                request.get().init_meta();
                encode::process_event_batch(&batch, request.get().init_batch());
                if request.send().promise.await.is_ok() {
                    let mut request = listener.ended_request();
                    request.get().init_meta();
                    let _ = request.send().promise.await;
                }
            })
            .detach();
            results.get().init_meta();
            results.get().set_handle(capnp_rpc::new_client(Released));
            Ok(())
        }
    }

    #[test]
    fn a_batch_the_agent_tells_comes_out_of_the_watch_then_its_end() {
        use crate::api::{ProcessEvent, ProcessEventKind, ProcessExited};

        let batch = ProcessEventBatch {
            history_from: 5,
            events: vec![Arc::new(ProcessEvent {
                pid: 4,
                sequence_number: 9,
                time: 7,
                kind: ProcessEventKind::Exited(ProcessExited {
                    exit_code: 1,
                    ..Default::default()
                }),
            })],
            lost: 2,
        };
        serve_as("uniproc-test-agent-process-events", PROTOCOL.version.minor, Telling(batch.clone()));
        let told = futures::executor::block_on(async {
            let remote = Remote::connect_to("uniproc-test-agent-process-events", Duration::from_secs(5)).await?;
            let mut events = remote.watch_process_events().await?;
            let first = events.next().await?;
            let after = events.next().await.map_err(|e| e.to_string());
            anyhow::Ok((first, after))
        })
        .map_err(|e| format!("{e:#}"));
        assert_eq!(told, Ok((batch, Err("the agent stopped".to_string()))));
    }

    #[test]
    fn an_agent_older_than_2_8_is_not_asked_for_process_events() {
        serve_as("uniproc-test-agent-2-7", 7, Answering);
        let remote = futures::executor::block_on(Remote::connect_to("uniproc-test-agent-2-7", Duration::from_secs(5)))
            .expect("connect");
        assert!(!remote.can_watch_process_events());
        let refused = futures::executor::block_on(remote.watch_process_events()).err().expect("refused");
        assert!(refused.to_string().contains("watchProcessEvents needs 2.8"), "{refused:#}");
    }

    /// Serves `name` on the I/O thread as an agent of windows 2.`minor`
    /// that answers with `server`.
    fn serve_as<S: windows_agent::Server + Clone + Send + 'static>(name: &'static str, minor: u32, server: S) {
        use ogurpchik::auth::handshake::Protocol;
        use ogurpchik::rpc::SessionAcceptor;

        let (up, listening) = std::sync::mpsc::channel();
        submit(Box::new(move || {
            compio::runtime::spawn(async move {
                let endpoint = Endpoint::for_service(APP_NAME, name).expect("pipe name");
                let listener = endpoint.listen().await.expect("listen");
                let _ = up.send(());
                let protocol = Protocol::new(PROTOCOL.id, PROTOCOL.version.major, minor, 0);
                let mut acceptor = SessionAcceptor::new(&listener, HandshakeMode::version_only(), protocol);
                while let Ok(session) = acceptor.next::<windows_agent::Client, _>(server.clone()).await {
                    compio::runtime::spawn(async move {
                        let _ = session.wait().await;
                    })
                    .detach();
                }
            })
            .detach();
        }))
        .unwrap();
        listening.recv_timeout(Duration::from_secs(5)).expect("the agent listens");
    }

    #[test]
    fn an_agent_older_than_2_2_says_so_and_is_not_asked_to_watch() {
        serve_as("uniproc-test-agent-2-1", 1, Answering);
        let remote = futures::executor::block_on(Remote::connect_to("uniproc-test-agent-2-1", Duration::from_secs(5)))
            .expect("connect");
        let agent = remote.agent_version();
        assert_eq!((agent.major, agent.minor), (PROTOCOL.version.major, 1));
        assert!(!remote.can_watch());
        let refused = futures::executor::block_on(remote.watch(MetricSpec::default())).err().expect("refused");
        assert!(refused.to_string().contains("watch needs 2.2"), "{refused:#}");
    }

    #[test]
    fn this_agent_can_watch() {
        serve_as("uniproc-test-agent-current", PROTOCOL.version.minor, Answering);
        let remote =
            futures::executor::block_on(Remote::connect_to("uniproc-test-agent-current", Duration::from_secs(5)))
                .expect("connect");
        let agent = remote.agent_version();
        assert_eq!((agent.major, agent.minor), (PROTOCOL.version.major, PROTOCOL.version.minor));
        assert!(remote.can_watch());
        assert!(remote.can_watch_process_events());
    }
}
