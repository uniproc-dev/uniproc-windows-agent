use std::cell::{Cell, RefCell};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use capnp::capability::Response;
use futures::channel::{mpsc, oneshot};
use futures::{Stream, StreamExt};
use ogurpchik::auth::handshake::{HandshakeMode, SchemaId, authenticate_client};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::{RpcSession, Side, spawn_session};
use uniproc_protocol::meta_capnp::{ResponseStatus, response_meta};
use uniproc_protocol::windows_capnp::{service_watcher, windows_agent};
use uniproc_protocol::{APP_NAME, WINDOWS_AGENT_SERVICE, WINDOWS_SCHEMA_ID};

use crate::api::{
    Command, CommandResult, ProcessInfo, ServiceStats, ServiceStatus, Snapshot, Tagged,
};
use crate::wire::{decode, encode};

const CALL_TIMEOUT: Duration = Duration::from_secs(45);
const JOIN_ATTEMPTS: usize = 3;

enum Request {
    Ping,
    Snapshot,
    SetIntervals { memory_ms: u64, cpu_ms: u64 },
    Run(Command),
    Watch {
        name: String,
        statuses: mpsc::UnboundedSender<ServiceStatus>,
        released: oneshot::Receiver<()>,
    },
}

enum Reply {
    Pong,
    Snapshot(Option<Snapshot>),
    Done,
    Code(CommandResult),
    Watching,
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
}

impl Remote {
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

        ready_rx
            .await
            .map_err(|_| anyhow!("the agent I/O thread stopped before connecting"))??;
        Ok(Self { tx })
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

    /// None when the process list kept changing under the metrics for every attempt to join them.
    pub async fn snapshot(&self) -> Result<Option<Snapshot>> {
        match self.call(Request::Snapshot).await? {
            Reply::Snapshot(snapshot) => Ok(snapshot),
            _ => bail!("a snapshot answered with something else"),
        }
    }

    /// `None` leaves that interval as it is.
    pub async fn set_intervals(&self, memory: Option<Duration>, cpu: Option<Duration>) -> Result<()> {
        let ms = |d: Option<Duration>| d.map_or(0, |d| (d.as_millis() as u64).max(1));
        let request = Request::SetIntervals {
            memory_ms: ms(memory),
            cpu_ms: ms(cpu),
        };
        match self.call(request).await? {
            Reply::Done => Ok(()),
            _ => bail!("set_intervals answered with something else"),
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
    ready: oneshot::Sender<Result<()>>,
    mut rx: mpsc::UnboundedReceiver<Envelope>,
) {
    let session = match Session::connect(&service, give_up_after).await {
        Ok(session) => Rc::new(session),
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready.send(Ok(())).is_err() {
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

#[derive(Default)]
struct Cache {
    services: Option<Tagged<Arc<[ServiceStats]>>>,
    processes: Option<Tagged<Arc<[ProcessInfo]>>>,
}

fn etag<T>(held: &Option<Tagged<T>>) -> u64 {
    held.as_ref().map_or(0, |t| t.etag)
}

fn not_modified(meta: response_meta::Reader<'_>) -> bool {
    matches!(meta.get_status(), Ok(ResponseStatus::NotModified))
}

struct Session {
    rpc: RpcSession<windows_agent::Client>,
    cache: RefCell<Cache>,
    nonce: Cell<u64>,
}

impl Session {
    async fn connect(service: &str, give_up_after: Duration) -> Result<Self> {
        let endpoint = Endpoint::for_service(APP_NAME, service).map_err(|e| anyhow!("{e:?}"))?;
        let mut conn = endpoint
            .connect_ready(give_up_after)
            .await
            .map_err(|e| anyhow!("{e:?}"))?;
        authenticate_client(&mut conn, &HandshakeMode::version_only(), SchemaId(WINDOWS_SCHEMA_ID))
            .await
            .map_err(|e| anyhow!("{e:?}"))?;
        Ok(Self {
            rpc: spawn_session(conn, Side::Client, ClientStub),
            cache: RefCell::new(Cache::default()),
            nonce: Cell::new(0),
        })
    }

    fn client(&self) -> &windows_agent::Client {
        self.rpc.remote()
    }

    async fn dispatch(&self, request: Request) -> Result<Reply> {
        match request {
            Request::Ping => self.ping().await.map(|()| Reply::Pong),
            Request::Snapshot => self.snapshot().await.map(Reply::Snapshot),
            Request::SetIntervals { memory_ms, cpu_ms } => {
                let mut request = self.client().set_config_request();
                request.get().set_memory_interval_ms(memory_ms);
                request.get().set_cpu_interval_ms(cpu_ms);
                request.send().promise.await?;
                Ok(Reply::Done)
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
        if !not_modified(meta) {
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
        if !not_modified(meta) {
            self.cache.borrow_mut().services = Some(Tagged {
                etag: meta.get_etag(),
                value: decode::services(reply.get_services()?)?,
            });
        }
        Ok(())
    }

    async fn snapshot(&self) -> Result<Option<Snapshot>> {
        let (services_etag, processes_etag) = {
            let cache = self.cache.borrow();
            (etag(&cache.services), etag(&cache.processes))
        };

        let client = self.client();
        let machine = client.get_machine_request().send().promise;
        let mut services = client.get_services_request();
        services.get().init_meta().set_if_none_match(services_etag);
        let services = services.send().promise;
        let processes = self.fetch_processes(processes_etag);
        let metrics = client.get_process_metrics_request().send().promise;
        let (machine, services, processes, metrics) =
            futures::join!(machine, services, processes, metrics);

        let machine = decode::machine(machine?.get()?.get_machine()?);
        self.keep_services(&services?)?;
        self.keep_processes(&processes?)?;

        let mut metrics = metrics?;
        for _ in 0..JOIN_ATTEMPTS {
            let wanted = metrics.get()?.get_processes_etag();
            let held = etag(&self.cache.borrow().processes);
            if held == wanted {
                break;
            }
            self.keep_processes(&self.fetch_processes(held).await?)?;
            if etag(&self.cache.borrow().processes) == wanted {
                break;
            }
            metrics = client.get_process_metrics_request().send().promise.await?;
        }

        let metrics = metrics.get()?;
        let wanted = metrics.get_processes_etag();
        let cache = self.cache.borrow();
        let (Some(processes), Some(services)) = (
            cache.processes.clone().filter(|p| p.etag == wanted),
            cache.services.clone(),
        ) else {
            return Ok(None);
        };
        Ok(Some(Snapshot {
            machine,
            services,
            processes,
            metrics: decode::metrics(metrics.get_metrics()?),
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
        for _ in 0..2 {
            let connected = futures::executor::block_on(Remote::connect_to(
                "uniproc.no-agent-serves-this",
                Duration::from_millis(200),
            ));
            assert!(connected.is_err());
        }
    }
}
