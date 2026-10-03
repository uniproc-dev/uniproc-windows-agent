//! Restarts the agent's service, as an app would, and prints every status
//! the SCM tells on the way, with the progress a bar would show:
//!   cargo run --example service_restart
//!
//! Needs no elevation when the service lets interactive users control it.

use std::time::{Duration, Instant};

use uniproc_windows_agent::agent_service;

fn main() {
    let restarting = std::thread::spawn(agent_service::restart);
    let began = Instant::now();
    let mut last = None;
    loop {
        let status = agent_service::status();
        let seen = status.map(|s| (s.state, s.checkpoint, s.wait_hint_ms));
        if last != Some(seen) {
            last = Some(seen);
            let progress = status.ok().and_then(|s| agent_service::progress(&s));
            println!("{:>7.3}s {seen:?} progress={progress:?}", began.elapsed().as_secs_f64());
        }
        if restarting.is_finished() && matches!(seen, Ok((uniproc_windows_agent::api::ServiceState::Running, _, _))) {
            break;
        }
        if began.elapsed() > Duration::from_secs(120) {
            println!("gave up after two minutes");
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    println!("restart answered {:?}", restarting.join().expect("the restart panicked"));
}
