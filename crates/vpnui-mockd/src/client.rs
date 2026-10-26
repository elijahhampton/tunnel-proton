use futures::{SinkExt, StreamExt};
use tokio::net::UnixStream;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, warn};
use vpnui_proto::{
    Command, DaemonMessage, ErrorCode, Event, PROTOCOL_VERSION, ProtoError, Request, RequestId,
    Response, codec, decode, encode,
};

use crate::daemon::{Action, ActorMsg, Subscription};

pub(crate) async fn handle_client(stream: UnixStream, actor: mpsc::Sender<ActorMsg>, client: u64) {
    info!(client, "client connected");
    let (read_half, write_half) = stream.into_split();
    let mut reader = FramedRead::new(read_half, codec());
    let mut writer = FramedWrite::new(write_half, codec());
    let mut events: Option<broadcast::Receiver<Event>> = None;

    loop {
        let outgoing = tokio::select! {
            line = reader.next() => match line {
                Some(Ok(line)) => handle_line(&line, &actor, &mut events).await,
                Some(Err(error)) => {
                    warn!(client, %error, "closing client after unreadable input");
                    break;
                }
                None => break,
            },
            event = next_event(&mut events) => match event {
                Ok(event) => vec![DaemonMessage::Event { event }],
                Err(RecvError::Lagged(missed)) => {
                    warn!(client, missed, "client fell behind; resyncing with a snapshot");
                    match subscribe(&actor).await {
                        Some(sub) => vec![snapshot_message(sub, &mut events)],
                        None => break,
                    }
                }
                Err(RecvError::Closed) => break,
            },
        };

        for msg in outgoing {
            match encode(&msg) {
                Ok(line) => {
                    if let Err(error) = writer.send(line).await {
                        debug!(client, %error, "write failed");
                        return;
                    }
                }
                Err(error) => warn!(client, %error, "dropping unencodable message"),
            }
        }
    }
    info!(client, "client disconnected");
}

async fn handle_line(
    line: &str,
    actor: &mpsc::Sender<ActorMsg>,
    events: &mut Option<broadcast::Receiver<Event>>,
) -> Vec<DaemonMessage> {
    let request: Request = match decode(line) {
        Ok(request) => request,
        Err(error) => return reject_malformed(line, &error).into_iter().collect(),
    };
    let id = request.id;
    let action = match request.cmd {
        Command::Hello {
            client_version,
            protocol_version,
        } => {
            info!(%client_version, %protocol_version, "hello");
            let response = if protocol_version == PROTOCOL_VERSION {
                Response::ok(id)
            } else {
                Response::err(
                    id,
                    ErrorCode::VersionMismatch,
                    format!(
                        "daemon speaks protocol {PROTOCOL_VERSION}, client sent {protocol_version}"
                    ),
                )
            };
            return vec![DaemonMessage::Response(
                response.with_protocol_version(PROTOCOL_VERSION),
            )];
        }
        Command::Subscribe => {
            return match subscribe(actor).await {
                Some(sub) => vec![
                    DaemonMessage::Response(Response::ok(id)),
                    snapshot_message(sub, events),
                ],
                None => vec![internal_error(id)],
            };
        }
        Command::Unknown => {
            return vec![DaemonMessage::Response(Response::err(
                id,
                ErrorCode::BadRequest,
                "unknown command",
            ))];
        }
        Command::Connect { server_id } => Action::Connect(server_id),
        Command::QuickConnect => Action::QuickConnect,
        Command::Disconnect => Action::Disconnect,
        Command::SetKillSwitch { armed } => Action::SetKillSwitch(armed),
        Command::SetSettings(patch) => Action::SetSettings(patch),
        Command::ReloadProfiles => Action::ReloadProfiles,
    };

    let (reply, rx) = oneshot::channel();
    if actor.send(ActorMsg::Act { action, reply }).await.is_err() {
        return vec![internal_error(id)];
    }
    let response = match rx.await {
        Ok(Ok(())) => Response::ok(id),
        Ok(Err(body)) => Response::err(id, body.code, body.message),
        Err(_) => return vec![internal_error(id)],
    };
    vec![DaemonMessage::Response(response)]
}

/// Replies `bad_request` when the line still carries a usable `id`; otherwise the line is dropped.
fn reject_malformed(line: &str, error: &ProtoError) -> Option<DaemonMessage> {
    let id = serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| value.get("id")?.as_u64());
    match id {
        Some(id) => Some(DaemonMessage::Response(Response::err(
            RequestId(id),
            ErrorCode::BadRequest,
            error.to_string(),
        ))),
        None => {
            warn!(%error, "dropping malformed request without an id");
            None
        }
    }
}

fn snapshot_message(
    sub: Subscription,
    events: &mut Option<broadcast::Receiver<Event>>,
) -> DaemonMessage {
    *events = Some(sub.events);
    DaemonMessage::Event {
        event: Event::Snapshot(Box::new(sub.snapshot)),
    }
}

async fn subscribe(actor: &mpsc::Sender<ActorMsg>) -> Option<Subscription> {
    let (reply, rx) = oneshot::channel();
    actor.send(ActorMsg::Subscribe { reply }).await.ok()?;
    rx.await.ok()
}

async fn next_event(events: &mut Option<broadcast::Receiver<Event>>) -> Result<Event, RecvError> {
    match events {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

fn internal_error(id: RequestId) -> DaemonMessage {
    DaemonMessage::Response(Response::err(
        id,
        ErrorCode::Internal,
        "daemon is shutting down",
    ))
}
