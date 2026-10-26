//! Owns the daemon socket. Reconnects with exponential backoff and reports everything it sees as
//! [`Event`]s; holds no protocol state of its own.

use std::path::PathBuf;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};
use vpnui_proto::{DaemonMessage, Request, codec, decode, encode};

use crate::app::{Event, LinkEvent};

pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(10);

/// Runs until either channel closes.
pub async fn run(
    path: PathBuf,
    mut commands: mpsc::UnboundedReceiver<Request>,
    events: mpsc::Sender<Event>,
) {
    let mut backoff = BACKOFF_INITIAL;
    loop {
        let reason = match UnixStream::connect(&path).await {
            Ok(stream) => {
                info!(path = %path.display(), "daemon socket connected");
                backoff = BACKOFF_INITIAL;
                if !fail_queued(&mut commands, &events).await
                    || events
                        .send(Event::Link(LinkEvent::Connected))
                        .await
                        .is_err()
                {
                    return;
                }
                match session(stream, &mut commands, &events).await {
                    Some(reason) => reason,
                    None => return,
                }
            }
            Err(err) => format!("cannot reach {}: {err}", path.display()),
        };
        debug!(%reason, ?backoff, "daemon link down");
        let down = LinkEvent::Down {
            reason,
            retry_in: backoff,
        };
        if events.send(Event::Link(down)).await.is_err() {
            return;
        }
        if !wait(backoff, &mut commands, &events).await {
            return;
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// Pumps one connection. Returns why it ended, or `None` if the app has gone away.
async fn session(
    stream: UnixStream,
    commands: &mut mpsc::UnboundedReceiver<Request>,
    events: &mpsc::Sender<Event>,
) -> Option<String> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, codec());
    let mut writer = FramedWrite::new(write_half, codec());
    loop {
        tokio::select! {
            line = reader.next() => {
                let event = match line {
                    Some(Ok(line)) => match decode::<DaemonMessage>(&line) {
                        Ok(msg) => Event::Daemon(Box::new(msg)),
                        Err(err) => Event::Link(LinkEvent::Malformed(err.to_string())),
                    },
                    Some(Err(err)) => return Some(format!("read failed: {err}")),
                    None => return Some("daemon closed the connection".to_owned()),
                };
                events.send(event).await.ok()?;
            }
            request = commands.recv() => {
                let request = request?;
                let id = request.id;
                let written = match encode(&request) {
                    Ok(line) => writer.send(line).await.map_err(|err| err.to_string()),
                    Err(err) => Err(err.to_string()),
                };
                if let Err(err) = written {
                    warn!(%err, %id, "send failed");
                    events.send(Event::Link(LinkEvent::SendFailed(id))).await.ok()?;
                    return Some(format!("write failed: {err}"));
                }
            }
        }
    }
}

/// Sleeps for `delay`, failing any command sent meanwhile. Returns false if the app is gone.
async fn wait(
    delay: Duration,
    commands: &mut mpsc::UnboundedReceiver<Request>,
    events: &mpsc::Sender<Event>,
) -> bool {
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            () = &mut sleep => return true,
            request = commands.recv() => {
                let Some(request) = request else { return false };
                let failed = Event::Link(LinkEvent::SendFailed(request.id));
                if events.send(failed).await.is_err() {
                    return false;
                }
            }
        }
    }
}

/// Fails commands queued while no connection was open.
async fn fail_queued(
    commands: &mut mpsc::UnboundedReceiver<Request>,
    events: &mpsc::Sender<Event>,
) -> bool {
    while let Ok(request) = commands.try_recv() {
        let failed = Event::Link(LinkEvent::SendFailed(request.id));
        if events.send(failed).await.is_err() {
            return false;
        }
    }
    true
}
