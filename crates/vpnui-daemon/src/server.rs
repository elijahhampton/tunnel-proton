//! The control socket. Every connection is authenticated by its peer credentials before a byte
//! is read; commands are forwarded to the engine thread and events fanned out from [`Shared`].

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::mpsc::Sender;

use futures::{SinkExt, StreamExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, broadcast, oneshot};
use tokio::task::JoinSet;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};
use vpnui_proto::{
    Command, DaemonMessage, ErrorCode, Event, PROTOCOL_VERSION, Request, RequestId, Response,
    codec, decode, encode,
};

use crate::engine::engine::{Action, Input};
use crate::shared::Shared;

pub const MAX_CLIENTS: usize = 8;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// uid 0 is always allowed.
    pub allowed_uids: BTreeSet<u32>,
    pub max_clients: usize,
}

impl ServerConfig {
    pub fn allows(&self, uid: u32) -> bool {
        uid == 0 || self.allowed_uids.contains(&uid)
    }
}

pub async fn serve(
    listener: UnixListener,
    shared: Arc<Shared>,
    inbox: Sender<Input>,
    config: ServerConfig,
) {
    let slots = Arc::new(Semaphore::new(config.max_clients));
    let mut clients = JoinSet::new();
    let mut next = 0u64;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                };
                next += 1;
                let uid = stream.peer_cred().map(|c| c.uid()).ok();
                match uid {
                    Some(uid) if config.allows(uid) => {}
                    other => {
                        warn!(client = next, uid = ?other, "refusing connection from an unauthorized user");
                        refuse(stream, ErrorCode::Unauthorized, "this user may not control vpnuid").await;
                        continue;
                    }
                }
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    warn!(client = next, "refusing connection: too many clients");
                    refuse(stream, ErrorCode::Busy, "too many clients are connected").await;
                    continue;
                };
                let shared = Arc::clone(&shared);
                let inbox = inbox.clone();
                let id = next;
                clients.spawn(async move {
                    handle(stream, shared, inbox, id).await;
                    drop(permit);
                });
            }
            Some(_) = clients.join_next() => {}
        }
    }
}

async fn refuse(stream: UnixStream, code: ErrorCode, message: &str) {
    let (_, write) = stream.into_split();
    let mut writer = FramedWrite::new(write, codec());
    if let Ok(line) = encode(&DaemonMessage::Response(Response::err(
        RequestId(0),
        code,
        message,
    ))) {
        let _ = writer.send(line).await;
    }
}

async fn handle(stream: UnixStream, shared: Arc<Shared>, inbox: Sender<Input>, client: u64) {
    info!(client, "client connected");
    let (read, write) = stream.into_split();
    let mut reader = FramedRead::new(read, codec());
    let mut writer = FramedWrite::new(write, codec());
    let mut events: Option<broadcast::Receiver<Event>> = None;

    loop {
        let outgoing: Vec<DaemonMessage> = tokio::select! {
            line = reader.next() => match line {
                Some(Ok(line)) => request(&line, &shared, &inbox, &mut events).await,
                Some(Err(e)) => {
                    warn!(client, %e, "closing client after unreadable input");
                    break;
                }
                None => break,
            },
            event = next_event(&mut events) => match event {
                Ok(event) => vec![DaemonMessage::Event { event }],
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    warn!(client, missed, "client fell behind; resending a snapshot");
                    vec![subscribe(&shared, &mut events)]
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
        };
        for msg in outgoing {
            match encode(&msg) {
                Ok(line) => {
                    if writer.send(line).await.is_err() {
                        return;
                    }
                }
                Err(e) => warn!(client, %e, "dropping unencodable message"),
            }
        }
    }
    info!(client, "client disconnected");
}

fn subscribe(shared: &Shared, events: &mut Option<broadcast::Receiver<Event>>) -> DaemonMessage {
    let (snapshot, rx) = shared.subscribe();
    *events = Some(rx);
    DaemonMessage::Event {
        event: Event::Snapshot(Box::new(snapshot)),
    }
}

async fn request(
    line: &str,
    shared: &Shared,
    inbox: &Sender<Input>,
    events: &mut Option<broadcast::Receiver<Event>>,
) -> Vec<DaemonMessage> {
    let request: Request = match decode(line) {
        Ok(r) => r,
        Err(e) => {
            let id = serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| v.get("id")?.as_u64());
            return match id {
                Some(id) => vec![DaemonMessage::Response(Response::err(
                    RequestId(id),
                    ErrorCode::BadRequest,
                    e.to_string(),
                ))],
                None => Vec::new(),
            };
        }
    };
    let id = request.id;
    let action = match request.cmd {
        Command::Hello {
            protocol_version, ..
        } => {
            let response = if protocol_version == PROTOCOL_VERSION {
                Response::ok(id)
            } else {
                Response::err(
                    id,
                    ErrorCode::VersionMismatch,
                    format!(
                        "vpnuid speaks protocol {PROTOCOL_VERSION}, client sent {protocol_version}"
                    ),
                )
            };
            return vec![DaemonMessage::Response(
                response.with_protocol_version(PROTOCOL_VERSION),
            )];
        }
        Command::Subscribe => {
            return vec![
                DaemonMessage::Response(Response::ok(id)),
                subscribe(shared, events),
            ];
        }
        Command::Unknown => {
            return vec![DaemonMessage::Response(Response::err(
                id,
                ErrorCode::BadRequest,
                "unknown command",
            ))];
        }
        Command::Connect { server_id } => Action::Connect(server_id.as_str().to_owned()),
        Command::QuickConnect => Action::QuickConnect,
        Command::Disconnect => Action::Disconnect,
        Command::SetKillSwitch { armed } => Action::SetKillSwitch(armed),
        Command::SetSettings(patch) => Action::SetSettings(patch),
        Command::ReloadProfiles => Action::ReloadProfiles,
    };
    debug!(?action, "command");
    let (reply, rx) = oneshot::channel();
    if inbox
        .send(Input::Command {
            action,
            reply: Some(reply),
        })
        .is_err()
    {
        return vec![internal(id)];
    }
    let response = match rx.await {
        Ok(Ok(())) => Response::ok(id),
        Ok(Err(body)) => Response::err(id, body.code, body.message),
        Err(_) => return vec![internal(id)],
    };
    vec![DaemonMessage::Response(response)]
}

async fn next_event(
    events: &mut Option<broadcast::Receiver<Event>>,
) -> Result<Event, broadcast::error::RecvError> {
    match events {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

fn internal(id: RequestId) -> DaemonMessage {
    DaemonMessage::Response(Response::err(
        id,
        ErrorCode::Internal,
        "vpnuid is shutting down",
    ))
}
