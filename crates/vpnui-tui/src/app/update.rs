use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Position;
use vpnui_proto::{
    DaemonMessage, ErrorBody, ErrorCode, Event as DaemonEvent, IpInfo, KillSwitchState, LogLevel,
    PROTOCOL_VERSION, ProtocolVersion, Request, RequestId, Response, Server, ServerId, Settings,
    Snapshot, Stats, TunnelState, UnixMillis,
};

use super::keymap::{self, Action};
use super::{
    AppState, Choice, ConfirmKind, DaemonLink, Effect, Event, Intent, LinkEvent, LogEntry, Modal,
    PENDING_TIMEOUT, PendingRequest, PrimaryAction, Projection, RECENTS_SHOWN, SettingKey,
    SettingRow, Severity, Slot, TOAST_TTL, Toast, VersionMismatch, View,
};
use crate::browser::NodeKey;
use crate::errors;
use crate::layout::{self, AppLayout};

/// Applies one event. Pure: reads nothing but `state` and `event`, and returns side effects for
/// the runtime to perform.
pub fn update(state: &mut AppState, event: Event) -> Vec<Effect> {
    let effects = match event {
        Event::Tick(now) => on_tick(state, now),
        Event::Key(key) => match keymap::action_for(state, key) {
            Some(action) => apply(state, action),
            None => Vec::new(),
        },
        Event::Mouse(mouse) => on_mouse(state, mouse),
        Event::Resize(width, height) => {
            state.width = width;
            state.height = height;
            Vec::new()
        }
        Event::Link(link) => on_link(state, link),
        Event::Daemon(message) => match *message {
            DaemonMessage::Response(response) => on_response(state, response),
            DaemonMessage::Event { event } => on_daemon_event(state, event),
        },
        Event::Shutdown => quit(state),
    };
    clamp_ui(state);
    effects
}

// ---------------------------------------------------------------------------------------------
// Time

fn on_tick(state: &mut AppState, now: UnixMillis) -> Vec<Effect> {
    state.now = now;
    if state.toast.as_ref().is_some_and(|t| now >= t.expires_at) {
        state.toast = None;
    }
    let (expired, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut state.in_flight)
        .into_iter()
        .partition(|p| now.since(p.sent_at) >= PENDING_TIMEOUT);
    state.in_flight = waiting;

    let mut effects = Vec::new();
    for pending in expired {
        let what = pending.intent.describe(state.daemon.as_ref());
        let text = format!(
            "No confirmation from the daemon for {what} after {}s",
            PENDING_TIMEOUT.as_secs()
        );
        effects.push(Effect::Log(Severity::Error, text.clone()));
        notify(state, Severity::Error, text);
    }
    effects
}

// ---------------------------------------------------------------------------------------------
// Daemon link

fn on_link(state: &mut AppState, event: LinkEvent) -> Vec<Effect> {
    match event {
        LinkEvent::Connected => {
            state.daemon = None;
            state.version_mismatch = None;
            state.link = DaemonLink::Connecting;
            drop_in_flight(state);
            record(
                state,
                Severity::Info,
                "Daemon socket open; waiting for snapshot",
            );
            send(state, Intent::Hello)
        }
        LinkEvent::Down { reason, retry_in } => {
            let was_live = state.link == DaemonLink::Live;
            let since = state.lost_since.unwrap_or(state.now);
            state.lost_since = Some(since);
            state.link = DaemonLink::Lost {
                since,
                next_retry_at: state.now.plus(retry_in),
            };
            drop_in_flight(state);
            if was_live {
                notify(
                    state,
                    Severity::Error,
                    format!("Lost the daemon link ({reason}); showing last known state"),
                );
            }
            vec![Effect::Log(
                Severity::Warn,
                format!("daemon link down: {reason}"),
            )]
        }
        LinkEvent::SendFailed(id) => {
            if let Some(pending) = take_pending(state, id) {
                let what = pending.intent.describe(state.daemon.as_ref());
                notify(
                    state,
                    Severity::Error,
                    format!("Could not send {what}: link is down"),
                );
            }
            Vec::new()
        }
        LinkEvent::Malformed(error) => {
            record(
                state,
                Severity::Warn,
                format!("Ignored malformed daemon message: {error}"),
            );
            vec![Effect::Log(
                Severity::Warn,
                format!("malformed daemon message: {error}"),
            )]
        }
    }
}

/// Clears requests sent on a socket that has closed; no response for them can arrive.
fn drop_in_flight(state: &mut AppState) {
    let dropped = std::mem::take(&mut state.in_flight)
        .into_iter()
        .filter(|p| !p.intent.is_handshake())
        .count();
    if dropped > 0 {
        notify(
            state,
            Severity::Warn,
            format!("Daemon link reset; {dropped} pending action(s) were not confirmed"),
        );
    }
}

fn on_response(state: &mut AppState, response: Response) -> Vec<Effect> {
    let Some(pending) = take_pending(state, response.id) else {
        return unsolicited_response(state, &response);
    };
    match pending.intent {
        Intent::Hello => {
            if let Some(daemon) = response.protocol_version
                && daemon != PROTOCOL_VERSION
            {
                return version_mismatch(state, Some(daemon));
            }
            if let Some(error) = response.error {
                if error.code == ErrorCode::VersionMismatch {
                    return version_mismatch(state, response.protocol_version);
                }
                notify(
                    state,
                    Severity::Error,
                    format!("Daemon refused hello: {}", errors::describe(&error)),
                );
                record_detail(state, &error);
                return Vec::new();
            }
            send(state, Intent::Subscribe)
        }
        Intent::Subscribe => {
            match response.error {
                Some(error) => {
                    notify(
                        state,
                        Severity::Error,
                        format!("Daemon refused subscribe: {}", errors::describe(&error)),
                    );
                    record_detail(state, &error);
                }
                None => state.in_flight.push(PendingRequest {
                    acked: true,
                    ..pending
                }),
            }
            Vec::new()
        }
        Intent::Connect(_)
        | Intent::QuickConnect
        | Intent::Disconnect
        | Intent::SetKillSwitch(_)
        | Intent::SetSetting(..) => {
            match response.error {
                Some(error) => {
                    let what = pending.intent.describe(state.daemon.as_ref());
                    notify(
                        state,
                        Severity::Error,
                        format!("Daemon rejected {what}: {}", errors::describe(&error)),
                    );
                    record_detail(state, &error);
                }
                None => state.in_flight.push(PendingRequest {
                    acked: true,
                    ..pending
                }),
            }
            Vec::new()
        }
    }
}

/// A response that matches no request. The daemon sends one with id 0 when it refuses a
/// connection (`unauthorized`, `busy`) right before closing it.
fn unsolicited_response(state: &mut AppState, response: &Response) -> Vec<Effect> {
    let refusal = response
        .error
        .as_ref()
        .filter(|e| matches!(e.code, ErrorCode::Unauthorized | ErrorCode::Busy));
    match refusal {
        Some(error) => {
            notify(
                state,
                Severity::Error,
                format!("Daemon refused the connection: {}", errors::describe(error)),
            );
            record_detail(state, error);
            vec![Effect::Log(
                Severity::Error,
                format!("daemon refused the connection: {}", error.message),
            )]
        }
        None => vec![Effect::Log(
            Severity::Info,
            format!("response for unknown request {}", response.id),
        )],
    }
}

fn record_detail(state: &mut AppState, error: &ErrorBody) {
    if !error.message.is_empty() {
        record(
            state,
            Severity::Info,
            format!("daemon detail ({}): {}", error.code.as_str(), error.message),
        );
    }
}

fn version_mismatch(state: &mut AppState, daemon: Option<ProtocolVersion>) -> Vec<Effect> {
    state.version_mismatch = Some(VersionMismatch {
        client: PROTOCOL_VERSION,
        daemon,
    });
    state.in_flight.clear();
    let daemon = daemon.map_or_else(|| "an unknown version".to_owned(), |v| v.to_string());
    let text =
        format!("Protocol mismatch: client speaks {PROTOCOL_VERSION}, daemon speaks {daemon}");
    record(state, Severity::Error, text.clone());
    vec![Effect::Log(Severity::Error, text)]
}

fn on_daemon_event(state: &mut AppState, event: DaemonEvent) -> Vec<Effect> {
    if let DaemonEvent::Snapshot(snapshot) = event {
        return on_snapshot(state, *snapshot);
    }
    if state.live().is_none() {
        return vec![Effect::Log(
            Severity::Info,
            format!("ignoring {} before snapshot", event.name()),
        )];
    }
    match event {
        DaemonEvent::Snapshot(_) => Vec::new(),
        DaemonEvent::TunnelChanged { tunnel } => on_tunnel(state, tunnel),
        DaemonEvent::KillSwitchChanged { kill_switch } => on_kill_switch(state, kill_switch),
        DaemonEvent::SettingsChanged { settings } => on_settings(state, settings),
        DaemonEvent::Stats(stats) => on_stats(state, stats),
        DaemonEvent::ServersUpdated { servers } => on_servers(state, servers),
        DaemonEvent::PublicIpChanged { public_ip } => on_public_ip(state, public_ip),
        DaemonEvent::Log { level, message } => {
            record(state, severity_of(level), format!("daemon: {message}"));
            Vec::new()
        }
        DaemonEvent::Unknown => vec![Effect::Log(
            Severity::Warn,
            "skipping daemon event of unknown type".to_owned(),
        )],
    }
}

fn on_snapshot(state: &mut AppState, snapshot: Snapshot) -> Vec<Effect> {
    if snapshot.protocol_version != PROTOCOL_VERSION {
        return version_mismatch(state, Some(snapshot.protocol_version));
    }
    let mut effects = Vec::new();
    if snapshot.tunnel == TunnelState::Unknown {
        effects.push(Effect::Log(
            Severity::Warn,
            "snapshot has a tunnel state this client does not know".to_owned(),
        ));
    }
    let projection = Projection::from_snapshot(snapshot);
    if !projection.tunnel.is_connected() && has_location(projection.public_ip.as_ref()) {
        state.origin.clone_from(&projection.public_ip);
    }
    state.daemon = Some(projection);
    state.link = DaemonLink::Live;
    state.lost_since = None;
    state.traffic.reset();
    state
        .in_flight
        .retain(|p| !matches!(p.intent, Intent::Subscribe));
    if state.ever_live {
        notify(state, Severity::Success, "Reconnected to the daemon");
    } else {
        record(state, Severity::Info, "Connected to the daemon");
    }
    state.ever_live = true;
    effects
}

fn on_tunnel(state: &mut AppState, tunnel: TunnelState) -> Vec<Effect> {
    if tunnel == TunnelState::Unknown {
        return vec![Effect::Log(
            Severity::Warn,
            "skipping tunnel_changed with an unknown state".to_owned(),
        )];
    }
    let Some(projection) = state.daemon.as_mut() else {
        return Vec::new();
    };
    let previous = std::mem::replace(&mut projection.tunnel, tunnel.clone());
    let armed = projection.kill_switch == KillSwitchState::Armed;
    let name = tunnel.server_id().map(|id| projection.server_name(id));
    if let TunnelState::Connected { server_id, .. } = &tunnel {
        let id = server_id.clone();
        projection.recents.retain(|r| *r != id);
        projection.recents.insert(0, id);
    }

    resolve(state, |intent| intent.confirmed_by_tunnel(&tunnel));
    if previous == tunnel {
        return Vec::new();
    }

    let new_session = match &tunnel {
        TunnelState::Connected { since_ms, .. } => !matches!(
            previous,
            TunnelState::Connected { since_ms: before, .. } if before == *since_ms
        ),
        TunnelState::Disconnected { .. }
        | TunnelState::Connecting { .. }
        | TunnelState::Reconnecting { .. }
        | TunnelState::Disconnecting
        | TunnelState::Unknown => false,
    };
    if new_session {
        state.traffic.reset();
    }

    let name = name.unwrap_or_default();
    match &tunnel {
        TunnelState::Connected { .. } => {
            notify(state, Severity::Success, format!("Connected to {name}"));
        }
        TunnelState::Disconnected {
            last_error: Some(error),
        } => {
            let error = errors::explain_last_error(error);
            let text = if armed {
                format!("Connection failed: {error}. Kill switch is blocking traffic")
            } else {
                format!("Connection failed: {error}. Traffic is unprotected")
            };
            notify(state, Severity::Error, text);
        }
        TunnelState::Disconnected { last_error: None } => {
            notify(state, Severity::Info, "Disconnected");
        }
        TunnelState::Reconnecting {
            attempt, reason, ..
        } => {
            if previous.is_connected() {
                notify(
                    state,
                    Severity::Warn,
                    format!("Tunnel dropped ({reason}); reconnecting"),
                );
            } else if !matches!(previous, TunnelState::Reconnecting { attempt: a, .. } if a == *attempt)
            {
                record(
                    state,
                    Severity::Info,
                    format!("Reconnect attempt {attempt} to {name}"),
                );
            }
        }
        TunnelState::Connecting { phase, .. } => {
            record(
                state,
                Severity::Info,
                format!("Connecting to {name}: {}", phase.label()),
            );
        }
        TunnelState::Disconnecting => record(state, Severity::Info, "Disconnecting"),
        TunnelState::Unknown => {}
    }
    Vec::new()
}

fn on_kill_switch(state: &mut AppState, kill_switch: KillSwitchState) -> Vec<Effect> {
    if kill_switch == KillSwitchState::Unknown {
        return vec![Effect::Log(
            Severity::Warn,
            "skipping kill_switch_changed with an unknown state".to_owned(),
        )];
    }
    let Some(projection) = state.daemon.as_mut() else {
        return Vec::new();
    };
    let previous = std::mem::replace(&mut projection.kill_switch, kill_switch.clone());
    let was_requested = state.pending(Slot::KillSwitch).is_some();
    resolve(state, Intent::confirmed_by_kill_switch);
    if previous == kill_switch && !was_requested {
        return Vec::new();
    }
    match kill_switch {
        KillSwitchState::Armed => notify(state, Severity::Success, "Kill switch armed"),
        KillSwitchState::Off => notify(state, Severity::Info, "Kill switch off"),
        KillSwitchState::Error { message } => {
            notify(
                state,
                Severity::Error,
                format!("Kill switch failed: {message}"),
            );
        }
        KillSwitchState::Unknown => {}
    }
    Vec::new()
}

fn on_settings(state: &mut AppState, settings: Settings) -> Vec<Effect> {
    let Some(projection) = state.daemon.as_mut() else {
        return Vec::new();
    };
    let previous = std::mem::replace(&mut projection.settings, settings);
    resolve(state, |intent| intent.confirmed_by_settings(&settings));
    for key in [
        SettingKey::AllowLan,
        SettingKey::BlockIpv6,
        SettingKey::AutoReconnect,
    ] {
        if key.get(&previous) != key.get(&settings) {
            let value = if key.get(&settings) { "on" } else { "off" };
            notify(
                state,
                Severity::Info,
                format!("Setting {}: {value}", key.label()),
            );
        }
    }
    Vec::new()
}

fn on_stats(state: &mut AppState, stats: Stats) -> Vec<Effect> {
    if let Some(projection) = state.daemon.as_mut() {
        projection.stats = Some(stats);
        state.traffic.record(stats);
    }
    Vec::new()
}

fn on_servers(state: &mut AppState, servers: Vec<Server>) -> Vec<Effect> {
    if let Some(projection) = state.daemon.as_mut() {
        projection.profiles_count = u32::try_from(servers.len()).unwrap_or(u32::MAX);
        projection.servers = servers;
    }
    Vec::new()
}

fn on_public_ip(state: &mut AppState, public_ip: Option<IpInfo>) -> Vec<Effect> {
    let Some(projection) = state.daemon.as_mut() else {
        return Vec::new();
    };
    if !projection.tunnel.is_connected() && has_location(public_ip.as_ref()) {
        state.origin.clone_from(&public_ip);
    }
    projection.public_ip = public_ip;
    Vec::new()
}

/// Only an address with coordinates can place the user on the map.
fn has_location(ip: Option<&IpInfo>) -> bool {
    ip.is_some_and(|ip| ip.lat.is_some() && ip.lon.is_some())
}

fn severity_of(level: LogLevel) -> Severity {
    match level {
        LogLevel::Debug | LogLevel::Info | LogLevel::Unknown => Severity::Info,
        LogLevel::Warn => Severity::Warn,
        LogLevel::Error => Severity::Error,
    }
}

// ---------------------------------------------------------------------------------------------
// Pending requests

fn take_pending(state: &mut AppState, id: RequestId) -> Option<PendingRequest> {
    let index = state.in_flight.iter().position(|p| p.id == id)?;
    Some(state.in_flight.remove(index))
}

fn resolve(state: &mut AppState, confirmed: impl Fn(&Intent) -> bool) {
    state.in_flight.retain(|p| !confirmed(&p.intent));
}

/// Sends `intent` unless its slot already has a request in flight.
fn send(state: &mut AppState, intent: Intent) -> Vec<Effect> {
    if let Some(pending) = state.pending(intent.slot()) {
        let what = pending.intent.describe(state.daemon.as_ref());
        return hint(
            state,
            format!("Still waiting for the daemon to confirm {what}"),
        );
    }
    let id = RequestId(state.next_request_id);
    state.next_request_id += 1;
    let cmd = intent.command();
    state.in_flight.push(PendingRequest {
        id,
        intent,
        sent_at: state.now,
        acked: false,
    });
    vec![Effect::Send(Request { id, cmd })]
}

/// Why actions are unavailable right now, if they are.
fn unavailable(state: &AppState) -> Option<&'static str> {
    if state.version_mismatch.is_some() {
        return Some("Protocol mismatch with the daemon");
    }
    match state.link {
        DaemonLink::Live => None,
        DaemonLink::Connecting => Some("Still connecting to the daemon"),
        DaemonLink::Lost { .. } => Some("Daemon unreachable; actions resume when it reconnects"),
    }
}

/// Checks the link and the slot before an action that would open a confirm dialog.
fn check_ready(state: &mut AppState, slot: Slot) -> Result<(), Vec<Effect>> {
    if let Some(reason) = unavailable(state) {
        return Err(hint(state, reason));
    }
    if let Some(pending) = state.pending(slot) {
        let what = pending.intent.describe(state.daemon.as_ref());
        return Err(hint(
            state,
            format!("Still waiting for the daemon to confirm {what}"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Messages

fn notify(state: &mut AppState, severity: Severity, text: impl Into<String>) {
    let text = text.into();
    state.toast = Some(Toast {
        text: text.clone(),
        severity,
        expires_at: state.now.plus(TOAST_TTL),
    });
    record(state, severity, text);
}

fn record(state: &mut AppState, severity: Severity, text: impl Into<String>) {
    state.log.push(LogEntry {
        at: state.now,
        severity,
        text: text.into(),
    });
}

fn hint(state: &mut AppState, text: impl Into<String>) -> Vec<Effect> {
    notify(state, Severity::Info, text);
    Vec::new()
}

fn quit(state: &mut AppState) -> Vec<Effect> {
    state.quitting = true;
    vec![Effect::Quit]
}

// ---------------------------------------------------------------------------------------------
// User actions

fn apply(state: &mut AppState, action: Action) -> Vec<Effect> {
    match action {
        Action::Quit => quit(state),
        Action::Help => {
            state.ui.modal = Some(Modal::Help { scroll: 0 });
            Vec::new()
        }
        Action::CloseModal => {
            state.ui.modal = None;
            Vec::new()
        }
        Action::HelpScroll(delta) => {
            if let Some(Modal::Help { scroll }) = &mut state.ui.modal {
                *scroll = scroll.saturating_add_signed(delta);
            }
            Vec::new()
        }
        Action::ChoicePrev => {
            cycle_choice(state, -1);
            Vec::new()
        }
        Action::ChoiceNext => {
            cycle_choice(state, 1);
            Vec::new()
        }
        Action::Choose => {
            let choice = match &state.ui.modal {
                Some(Modal::Confirm { kind, selected }) => kind
                    .choices()
                    .get(*selected)
                    .copied()
                    .unwrap_or(Choice::Cancel),
                Some(Modal::Help { .. }) | None => return Vec::new(),
            };
            state.ui.modal = None;
            choose(state, choice)
        }
        Action::Escape => escape(state),
        Action::NextView => goto(state, state.ui.view.next()),
        Action::PrevView => goto(state, state.ui.view.prev()),
        Action::Goto(view) => goto(state, view),
        Action::Move(delta) => {
            move_selection(state, delta);
            Vec::new()
        }
        Action::Top => {
            move_selection(state, isize::MIN / 2);
            Vec::new()
        }
        Action::Bottom => {
            move_selection(state, isize::MAX / 2);
            Vec::new()
        }
        Action::Collapse => in_servers(state, |state| {
            let servers = state
                .daemon
                .as_ref()
                .map(|p| p.servers.as_slice())
                .unwrap_or(&[]);
            state.ui.browser.collapse(servers);
        }),
        Action::Expand => in_servers(state, |state| {
            let servers = state
                .daemon
                .as_ref()
                .map(|p| p.servers.as_slice())
                .unwrap_or(&[]);
            state.ui.browser.expand(servers);
        }),
        Action::Activate => activate(state),
        Action::QuickConnect => quick_connect(state),
        Action::Disconnect => disconnect(state),
        Action::ToggleKillSwitch => toggle_kill_switch(state),
        Action::ReconnectNow => reconnect_now(state),
        Action::StartSearch => {
            state.ui.view = View::Servers;
            state.ui.browser.typing = true;
            Vec::new()
        }
        Action::CycleSort => cycle_sort(state),
        Action::SearchChar(c) => {
            state.ui.browser.query.push(c);
            Vec::new()
        }
        Action::SearchBackspace => {
            state.ui.browser.query.pop();
            Vec::new()
        }
        Action::SearchCommit => {
            state.ui.browser.typing = false;
            Vec::new()
        }
        Action::SearchCancel => {
            state.ui.browser.typing = false;
            state.ui.browser.query.clear();
            Vec::new()
        }
    }
}

fn cycle_sort(state: &mut AppState) -> Vec<Effect> {
    if state.ui.view != View::Servers {
        return hint(state, "That key works in the Servers view (press 2)");
    }
    let servers = state
        .daemon
        .as_ref()
        .map(|p| p.servers.as_slice())
        .unwrap_or(&[]);
    let current = state.ui.browser.sort;
    let next = current.next_available(servers);
    if next == current {
        return hint(state, "Sorted by name: no load or latency data to sort by");
    }
    state.ui.browser.sort = next;
    Vec::new()
}

fn cycle_choice(state: &mut AppState, delta: isize) {
    if let Some(Modal::Confirm { kind, selected }) = &mut state.ui.modal {
        let count = kind.choices().len();
        *selected = (*selected + count).saturating_add_signed(delta) % count;
    }
}

fn in_servers(state: &mut AppState, f: impl FnOnce(&mut AppState)) -> Vec<Effect> {
    if state.ui.view == View::Servers {
        f(state);
        Vec::new()
    } else {
        hint(state, "That key works in the Servers view (press 2)")
    }
}

fn goto(state: &mut AppState, view: View) -> Vec<Effect> {
    state.ui.view = view;
    Vec::new()
}

fn move_selection(state: &mut AppState, delta: isize) {
    match state.ui.view {
        View::Home => {
            let count = state
                .daemon
                .as_ref()
                .map_or(0, |p| p.recent_servers().count());
            state.ui.recents_cursor = step(state.ui.recents_cursor, delta, count);
        }
        View::Servers => {
            let servers = state
                .daemon
                .as_ref()
                .map(|p| p.servers.as_slice())
                .unwrap_or(&[]);
            state.ui.browser.move_by(servers, delta);
        }
        View::Stats => {
            state.ui.log_offset = step(state.ui.log_offset, delta, state.log.len());
        }
        View::Settings => {
            state.ui.settings_cursor = step(state.ui.settings_cursor, delta, SettingRow::ALL.len());
        }
    }
}

fn step(current: usize, delta: isize, count: usize) -> usize {
    current
        .saturating_add_signed(delta)
        .min(count.saturating_sub(1))
}

fn escape(state: &mut AppState) -> Vec<Effect> {
    if state.ui.browser.searching() {
        state.ui.browser.query.clear();
        state.ui.browser.typing = false;
        return Vec::new();
    }
    let connecting = state
        .live()
        .is_some_and(|p| matches!(p.tunnel, TunnelState::Connecting { .. }));
    if connecting {
        return send(state, Intent::Disconnect);
    }
    Vec::new()
}

fn activate(state: &mut AppState) -> Vec<Effect> {
    match state.ui.view {
        View::Home => {
            let target = state
                .daemon
                .as_ref()
                .and_then(|p| p.recent_servers().nth(state.ui.recents_cursor).cloned());
            match target {
                Some(id) => connect_to(state, id),
                None => hint(state, "No recent servers yet; press c to quick connect"),
            }
        }
        View::Servers => {
            let Some(key) = state.ui.browser.selected.clone() else {
                return Vec::new();
            };
            match key {
                NodeKey::Server(id) => connect_to(state, id),
                NodeKey::Country(_) | NodeKey::City { .. } => {
                    state.ui.browser.toggle(&key);
                    Vec::new()
                }
            }
        }
        View::Settings => {
            let row = SettingRow::ALL
                .get(state.ui.settings_cursor)
                .copied()
                .unwrap_or(SettingRow::KillSwitch);
            toggle_setting(state, row)
        }
        View::Stats => Vec::new(),
    }
}

fn connect_to(state: &mut AppState, id: ServerId) -> Vec<Effect> {
    if let Some(reason) = unavailable(state) {
        return hint(state, reason);
    }
    let Some(projection) = state.live() else {
        return Vec::new();
    };
    let name = projection.server_name(&id);
    match &projection.tunnel {
        TunnelState::Connected { server_id, .. } if *server_id == id => {
            hint(state, format!("Already connected to {name}"))
        }
        TunnelState::Connecting { server_id, .. } if *server_id == id => {
            hint(state, format!("Already connecting to {name}"))
        }
        TunnelState::Disconnecting => hint(state, "Wait for the disconnect to finish"),
        TunnelState::Disconnected { .. }
        | TunnelState::Connecting { .. }
        | TunnelState::Connected { .. }
        | TunnelState::Reconnecting { .. }
        | TunnelState::Unknown => send(state, Intent::Connect(id)),
    }
}

fn quick_connect(state: &mut AppState) -> Vec<Effect> {
    if let Some(reason) = unavailable(state) {
        return hint(state, reason);
    }
    let Some(projection) = state.live() else {
        return Vec::new();
    };
    match projection.tunnel {
        TunnelState::Disconnected { .. } | TunnelState::Reconnecting { .. } => {
            send(state, Intent::QuickConnect)
        }
        TunnelState::Connecting { .. } => hint(state, "Already connecting; Esc cancels"),
        TunnelState::Connected { .. } => hint(
            state,
            "Already connected; press d to disconnect or pick a server to switch",
        ),
        TunnelState::Disconnecting => hint(state, "Wait for the disconnect to finish"),
        TunnelState::Unknown => hint(state, "Tunnel state unknown; waiting for the daemon"),
    }
}

fn disconnect(state: &mut AppState) -> Vec<Effect> {
    if let Some(reason) = unavailable(state) {
        return hint(state, reason);
    }
    let Some(projection) = state.live() else {
        return Vec::new();
    };
    let armed = projection.kill_switch == KillSwitchState::Armed;
    match projection.tunnel {
        TunnelState::Connected { .. } if armed => {
            if let Err(effects) = check_ready(state, Slot::Tunnel) {
                return effects;
            }
            open_confirm(state, ConfirmKind::DisconnectWhileArmed)
        }
        TunnelState::Connected { .. }
        | TunnelState::Connecting { .. }
        | TunnelState::Reconnecting { .. }
        | TunnelState::Unknown => send(state, Intent::Disconnect),
        TunnelState::Disconnected { .. } => hint(state, "Not connected"),
        TunnelState::Disconnecting => hint(state, "Already disconnecting"),
    }
}

fn reconnect_now(state: &mut AppState) -> Vec<Effect> {
    if let Some(reason) = unavailable(state) {
        return hint(state, reason);
    }
    let Some(projection) = state.live() else {
        return Vec::new();
    };
    match &projection.tunnel {
        TunnelState::Reconnecting { server_id, .. } => {
            let id = server_id.clone();
            send(state, Intent::Connect(id))
        }
        TunnelState::Disconnected { .. } => match projection.recents.first().cloned() {
            Some(id) => send(state, Intent::Connect(id)),
            None => hint(
                state,
                "No recent server to reconnect to; press c to quick connect",
            ),
        },
        TunnelState::Connected { .. } => hint(state, "Already connected"),
        TunnelState::Connecting { .. } => hint(state, "Already connecting; Esc cancels"),
        TunnelState::Disconnecting => hint(state, "Wait for the disconnect to finish"),
        TunnelState::Unknown => hint(state, "Tunnel state unknown; waiting for the daemon"),
    }
}

fn toggle_kill_switch(state: &mut AppState) -> Vec<Effect> {
    if let Err(effects) = check_ready(state, Slot::KillSwitch) {
        return effects;
    }
    let Some(projection) = state.live() else {
        return Vec::new();
    };
    match &projection.kill_switch {
        KillSwitchState::Off => send(state, Intent::SetKillSwitch(true)),
        KillSwitchState::Armed => open_confirm(state, ConfirmKind::Disarm),
        KillSwitchState::Error { message } => {
            let message = message.clone();
            open_confirm(state, ConfirmKind::KillSwitchFailed { message })
        }
        KillSwitchState::Unknown => hint(state, "Kill-switch state unknown"),
    }
}

fn toggle_setting(state: &mut AppState, row: SettingRow) -> Vec<Effect> {
    let Some(key) = row.setting_key() else {
        return toggle_kill_switch(state);
    };
    if let Err(effects) = check_ready(state, Slot::Setting(key)) {
        return effects;
    }
    let Some(projection) = state.live() else {
        return Vec::new();
    };
    let current = key.get(&projection.settings);
    match (key, current) {
        (SettingKey::AllowLan, false) => open_confirm(state, ConfirmKind::AllowLan),
        (SettingKey::BlockIpv6, true) => open_confirm(state, ConfirmKind::DisableBlockIpv6),
        (SettingKey::AllowLan | SettingKey::BlockIpv6 | SettingKey::AutoReconnect, _) => {
            send(state, Intent::SetSetting(key, !current))
        }
    }
}

fn open_confirm(state: &mut AppState, kind: ConfirmKind) -> Vec<Effect> {
    let selected = kind.choices().len() - 1;
    state.ui.modal = Some(Modal::Confirm { kind, selected });
    Vec::new()
}

fn choose(state: &mut AppState, choice: Choice) -> Vec<Effect> {
    match choice {
        Choice::Cancel => Vec::new(),
        Choice::DisconnectAndDisarm => {
            let mut effects = send(state, Intent::Disconnect);
            effects.extend(send(state, Intent::SetKillSwitch(false)));
            effects
        }
        Choice::DisconnectStayBlocked => send(state, Intent::Disconnect),
        Choice::Disarm | Choice::TurnOff => send(state, Intent::SetKillSwitch(false)),
        Choice::RetryArming => send(state, Intent::SetKillSwitch(true)),
        Choice::AllowLan => send(state, Intent::SetSetting(SettingKey::AllowLan, true)),
        Choice::DisableBlockIpv6 => send(state, Intent::SetSetting(SettingKey::BlockIpv6, false)),
    }
}

fn primary(state: &mut AppState) -> Vec<Effect> {
    let Some(action) = state.live().map(|p| PrimaryAction::for_tunnel(&p.tunnel)) else {
        return match unavailable(state) {
            Some(reason) => hint(state, reason),
            None => Vec::new(),
        };
    };
    match action {
        PrimaryAction::QuickConnect => quick_connect(state),
        PrimaryAction::Disconnect | PrimaryAction::Cancel => disconnect(state),
        PrimaryAction::ReconnectNow => reconnect_now(state),
        PrimaryAction::Wait => hint(state, "Wait for the disconnect to finish"),
    }
}

// ---------------------------------------------------------------------------------------------
// Mouse

fn on_mouse(state: &mut AppState, mouse: MouseEvent) -> Vec<Effect> {
    let layout = state.layout();
    let at = Position::new(mouse.column, mouse.row);
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => click(state, &layout, at),
        MouseEventKind::ScrollDown => {
            scroll(state, &layout, at, 3);
            Vec::new()
        }
        MouseEventKind::ScrollUp => {
            scroll(state, &layout, at, -3);
            Vec::new()
        }
        MouseEventKind::Down(_)
        | MouseEventKind::Up(_)
        | MouseEventKind::Drag(_)
        | MouseEventKind::Moved
        | MouseEventKind::ScrollLeft
        | MouseEventKind::ScrollRight => Vec::new(),
    }
}

fn click(state: &mut AppState, layout: &AppLayout, at: Position) -> Vec<Effect> {
    if layout.mode == layout::Mode::TooSmall || state.version_mismatch.is_some() {
        return Vec::new();
    }
    match &state.ui.modal {
        Some(Modal::Confirm { kind, .. }) => {
            let confirm = layout::confirm(layout.area, kind);
            let choice = confirm
                .choices
                .iter()
                .position(|r| r.contains(at))
                .and_then(|index| kind.choices().get(index).copied());
            return match choice {
                Some(choice) => {
                    state.ui.modal = None;
                    choose(state, choice)
                }
                None => Vec::new(),
            };
        }
        Some(Modal::Help { .. }) => {
            state.ui.modal = None;
            return Vec::new();
        }
        None => {}
    }

    if let Some((view, _)) = layout.tab_hits().into_iter().find(|(_, r)| r.contains(at)) {
        return goto(state, view);
    }
    if let Some(rail) = layout.rail {
        if rail.action.contains(at) {
            return primary(state);
        }
        if rail.kill_switch.contains(at) {
            return toggle_kill_switch(state);
        }
    }
    if let Some(list) = layout.recents_list()
        && list.contains(at)
    {
        let index = usize::from(at.y - list.y);
        let count = state
            .daemon
            .as_ref()
            .map_or(0, |p| p.recent_servers().count());
        if index < count {
            state.ui.recents_cursor = index;
            state.ui.view = View::Home;
        }
        return Vec::new();
    }
    if let Some(list) = layout.servers_list()
        && list.contains(at)
    {
        let index = state.ui.browser.offset + usize::from(at.y - list.y);
        let servers = state
            .daemon
            .as_ref()
            .map(|p| p.servers.as_slice())
            .unwrap_or(&[]);
        state.ui.browser.select_index(servers, index);
        return Vec::new();
    }
    if let Some(rows) = layout.settings_rows()
        && rows.contains(at)
    {
        let index = usize::from(at.y - rows.y);
        if index < SettingRow::ALL.len() {
            state.ui.settings_cursor = index;
        }
        return Vec::new();
    }
    if let Some(search) = layout.search_line()
        && search.contains(at)
    {
        state.ui.browser.typing = true;
    }
    Vec::new()
}

fn scroll(state: &mut AppState, layout: &AppLayout, at: Position, delta: isize) {
    if let Some(Modal::Help { scroll }) = &mut state.ui.modal {
        *scroll = scroll.saturating_add_signed(delta as i16);
        return;
    }
    let over = |rect: Option<ratatui::layout::Rect>| rect.is_some_and(|r| r.contains(at));
    if over(layout.servers_list()) || over(layout.log_list()) || over(layout.settings_rows()) {
        move_selection(state, delta);
    } else if over(layout.recents_list()) {
        let count = state
            .daemon
            .as_ref()
            .map_or(0, |p| p.recent_servers().count());
        state.ui.recents_cursor = step(state.ui.recents_cursor, delta, count);
    }
}

// ---------------------------------------------------------------------------------------------
// Invariants after every event

fn clamp_ui(state: &mut AppState) {
    let layout = state.layout();
    let servers = state
        .daemon
        .as_ref()
        .map(|p| p.servers.as_slice())
        .unwrap_or(&[]);
    state.ui.browser.reconcile(servers);
    let viewport = layout.servers_list().map_or(0, |r| usize::from(r.height));
    state.ui.browser.clamp_offset(servers, viewport);

    let recents = state
        .daemon
        .as_ref()
        .map_or(0, |p| p.recent_servers().count());
    state.ui.recents_cursor = state.ui.recents_cursor.min(recents.saturating_sub(1));
    state.ui.recents_cursor = state.ui.recents_cursor.min(RECENTS_SHOWN - 1);
    state.ui.settings_cursor = state.ui.settings_cursor.min(SettingRow::ALL.len() - 1);
    let log_viewport = layout
        .log_list()
        .map_or(1, |r| usize::from(r.height).max(1));
    state.ui.log_offset = state
        .ui
        .log_offset
        .min(state.log.len().saturating_sub(log_viewport));
}

#[cfg(test)]
mod tests;
