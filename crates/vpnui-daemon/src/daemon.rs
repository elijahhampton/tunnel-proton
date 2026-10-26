//! Assembly: engine startup (fail-closed policy and recovery), then the socket, then serving.

use std::sync::Arc;
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;

use tracing::error;

use crate::engine::engine::{Engine, EngineOptions, Input};
use crate::platform::{Platform, PlatformError};
use crate::server::{self, ServerConfig};
use crate::shared::Shared;

pub struct Daemon {
    inbox: Sender<Input>,
    engine: Option<JoinHandle<()>>,
    server: tokio::task::JoinHandle<()>,
    shared: Arc<Shared>,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("binding the control socket: {0}")]
    Bind(PlatformError),
    #[error("control socket: {0}")]
    Socket(std::io::Error),
}

/// Starts the daemon. Must be called inside a tokio runtime. The socket is bound only after
/// the engine has loaded the kill-switch policy and finished recovery.
pub fn start<P: Platform>(
    platform: P,
    engine: EngineOptions,
    server: ServerConfig,
) -> Result<Daemon, DaemonError> {
    let shared = Shared::new();
    let engine = Engine::start(platform, Arc::clone(&shared), engine);
    let listener = engine.bind_socket().map_err(DaemonError::Bind)?;
    listener
        .set_nonblocking(true)
        .map_err(DaemonError::Socket)?;
    let listener = tokio::net::UnixListener::from_std(listener).map_err(DaemonError::Socket)?;

    let (inbox, rx) = mpsc::channel();
    let engine = std::thread::Builder::new()
        .name("vpnuid-engine".into())
        .spawn(move || crate::engine::engine::run(engine, rx))
        .map_err(DaemonError::Socket)?;
    let server = tokio::spawn(server::serve(
        listener,
        Arc::clone(&shared),
        inbox.clone(),
        server,
    ));
    Ok(Daemon {
        inbox,
        engine: Some(engine),
        server,
        shared,
    })
}

impl Daemon {
    pub fn inbox(&self) -> Sender<Input> {
        self.inbox.clone()
    }

    pub fn shared(&self) -> Arc<Shared> {
        Arc::clone(&self.shared)
    }

    /// Stops serving. `graceful` tears the tunnel down (leaving an armed policy in place);
    /// otherwise the engine stops mid-flight, as a crash would.
    pub async fn stop(mut self, graceful: bool) {
        self.server.abort();
        let (done, wait) = mpsc::channel();
        let _ = self.inbox.send(Input::Stop {
            graceful,
            done: Some(done),
        });
        if let Some(engine) = self.engine.take() {
            let joined = tokio::task::spawn_blocking(move || {
                let _ = wait.recv();
                engine.join()
            })
            .await;
            if !matches!(joined, Ok(Ok(()))) {
                error!("engine thread did not stop cleanly");
            }
        }
    }
}
