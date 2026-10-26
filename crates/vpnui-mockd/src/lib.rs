//! In-process mock of the privileged vpnui daemon. Simulates tunnel, kill-switch, and settings
//! state over the real wire protocol; never touches the network stack.

#![forbid(unsafe_code)]

mod catalog;
mod client;
mod daemon;
mod rng;

use std::time::Duration;

use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, warn};

use crate::daemon::Daemon;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    Calm,
    /// Drops an established tunnel every 30-60s and fails more reconnect attempts.
    Flaky,
}

impl Scenario {
    fn retry_failure_rate(self) -> f64 {
        match self {
            Self::Calm => 0.10,
            Self::Flaky => 0.35,
        }
    }
}

const CONNECT_FAILURE_RATE: f64 = 0.10;

/// Operator fault injection, delivered over [`Config::control`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Drop an established tunnel as if the peer went away.
    Drop,
    /// Make the next handshake fail.
    FailNext,
    /// Put the kill switch into `Error` until [`Control::KillSwitchClear`].
    KillSwitchError,
    KillSwitchClear,
}

#[derive(Debug)]
pub struct Config {
    pub seed: u64,
    pub scenario: Scenario,
    /// Multiplies every simulated delay; tests use small values to run quickly.
    pub time_scale: f64,
    /// When false, handshakes only fail on [`Control::FailNext`].
    pub random_faults: bool,
    pub control: Option<mpsc::Receiver<Control>>,
}

impl Config {
    pub fn new(seed: u64, scenario: Scenario) -> Self {
        Self {
            seed,
            scenario,
            time_scale: 1.0,
            random_faults: true,
            control: None,
        }
    }

    pub fn without_random_faults(mut self) -> Self {
        self.random_faults = false;
        self
    }

    pub fn with_control(mut self, control: mpsc::Receiver<Control>) -> Self {
        self.control = Some(control);
        self
    }

    pub fn with_time_scale(mut self, scale: f64) -> Self {
        self.time_scale = scale.max(0.001);
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("daemon state task stopped unexpectedly")]
    ActorStopped,
}

/// Accepts clients on `listener` until the returned future is dropped.
///
/// All state and every client connection live inside this future; dropping or aborting it
/// closes every socket at once.
pub async fn serve(listener: UnixListener, config: Config) -> Result<(), ServeError> {
    let (actor_tx, actor_rx) = mpsc::channel(64);
    let (connect_failure_rate, retry_failure_rate) = if config.random_faults {
        (CONNECT_FAILURE_RATE, config.scenario.retry_failure_rate())
    } else {
        (0.0, 0.0)
    };
    let actor = Daemon::new(daemon::Params {
        seed: config.seed,
        scenario: config.scenario,
        time_scale: config.time_scale,
        connect_failure_rate,
        retry_failure_rate,
    })
    .run(actor_rx, config.control);
    tokio::pin!(actor);

    let mut clients = JoinSet::new();
    let mut next_client = 0u64;
    loop {
        tokio::select! {
            () = &mut actor => return Err(ServeError::ActorStopped),
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    next_client += 1;
                    clients.spawn(client::handle_client(stream, actor_tx.clone(), next_client));
                }
                Err(err) => {
                    warn!(%err, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            Some(finished) = clients.join_next() => {
                if let Err(err) = finished
                    && err.is_panic()
                {
                    error!(%err, "client task panicked");
                }
            }
        }
    }
}
