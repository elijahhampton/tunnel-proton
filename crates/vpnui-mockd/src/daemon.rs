use std::collections::VecDeque;
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior, interval, sleep_until};
use tracing::{debug, error, info, warn};
use vpnui_proto::{
    ConnectPhase, ErrorBody, ErrorCode, Event, IpInfo, KillSwitchState, LogLevel, PROTOCOL_VERSION,
    ServerId, Settings, SettingsPatch, Snapshot, Stats, TunnelState, UnixMillis,
};

use crate::catalog::{self, CatalogEntry, LATENCY_JITTER_MS};
use crate::rng::Rng;
use crate::{Control, Scenario};

const EVENT_BUFFER: usize = 256;
const MAX_RECENTS: usize = 8;
const REKEY_INTERVAL: Duration = Duration::from_secs(120);
const STATS_INTERVAL: Duration = Duration::from_secs(1);
const LOAD_INTERVAL: Duration = Duration::from_secs(5);
const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(15);
const KILL_SWITCH_APPLY_MS: u64 = 300;
const SETTINGS_APPLY_MS: u64 = 200;
const ROUTES_MS: u64 = 300;
const DISCONNECT_MS: u64 = 300;
const KILL_SWITCH_FAULT: &str = "failed to load packet filter rules (simulated)";
const BASELINE_RX_BYTES_PER_SEC: f64 = 250_000.0;

/// Commands that mutate daemon state. `hello` and `subscribe` are handled per connection.
#[derive(Debug)]
pub(crate) enum Action {
    Connect(ServerId),
    QuickConnect,
    Disconnect,
    SetKillSwitch(bool),
    SetSettings(SettingsPatch),
    ReloadProfiles,
}

pub(crate) enum ActorMsg {
    Act {
        action: Action,
        reply: oneshot::Sender<Result<(), ErrorBody>>,
    },
    Subscribe {
        reply: oneshot::Sender<Subscription>,
    },
}

/// A snapshot and a receiver created in the same actor step: no event falls between them.
pub(crate) struct Subscription {
    pub(crate) snapshot: Snapshot,
    pub(crate) events: broadcast::Receiver<Event>,
}

#[derive(Debug, Clone, Copy)]
enum TunnelStep {
    Handshake,
    Routes,
    Establish,
    Retry,
    RetryOutcome,
    FinishDisconnect,
}

struct Session {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_rate: f64,
    last_handshake: UnixMillis,
    next_rekey: Instant,
}

pub(crate) struct Params {
    pub(crate) seed: u64,
    pub(crate) scenario: Scenario,
    pub(crate) time_scale: f64,
    pub(crate) connect_failure_rate: f64,
    pub(crate) retry_failure_rate: f64,
}

/// Single owner of all simulated daemon state. Runs as one task; clients talk to it over
/// [`ActorMsg`] and receive broadcast [`Event`]s.
pub(crate) struct Daemon {
    scenario: Scenario,
    time_scale: f64,
    connect_failure_rate: f64,
    retry_failure_rate: f64,
    rng: Rng,
    catalog: Vec<CatalogEntry>,
    home: IpInfo,
    tunnel: TunnelState,
    kill_switch: KillSwitchState,
    settings: Settings,
    recents: VecDeque<ServerId>,
    public_ip: Option<IpInfo>,
    events: broadcast::Sender<Event>,
    tunnel_timer: Option<(Instant, TunnelStep)>,
    kill_switch_timer: Option<(Instant, bool)>,
    settings_timer: Option<(Instant, SettingsPatch)>,
    drop_at: Option<Instant>,
    session: Option<Session>,
    fail_next: bool,
    kill_switch_fault: bool,
}

impl Daemon {
    pub(crate) fn new(params: Params) -> Self {
        let Params {
            seed,
            scenario,
            time_scale,
            connect_failure_rate,
            retry_failure_rate,
        } = params;
        let mut rng = Rng::new(seed);
        let catalog = catalog::generate(&mut rng);
        let home = catalog::home_ip(&mut rng);
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        Self {
            scenario,
            time_scale,
            connect_failure_rate,
            retry_failure_rate,
            rng,
            catalog,
            public_ip: Some(home.clone()),
            home,
            tunnel: TunnelState::Disconnected { last_error: None },
            kill_switch: KillSwitchState::Off,
            settings: Settings {
                allow_lan: false,
                block_ipv6: true,
                auto_reconnect: true,
            },
            recents: VecDeque::new(),
            events,
            tunnel_timer: None,
            kill_switch_timer: None,
            settings_timer: None,
            drop_at: None,
            session: None,
            fail_next: false,
            kill_switch_fault: false,
        }
    }

    pub(crate) async fn run(
        mut self,
        mut inbox: mpsc::Receiver<ActorMsg>,
        mut control: Option<mpsc::Receiver<Control>>,
    ) {
        let mut stats = interval(self.scaled(STATS_INTERVAL));
        stats.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut loads = interval(self.scaled(LOAD_INTERVAL));
        loads.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loads.reset();

        loop {
            let tunnel_at = self.tunnel_timer.map(|(at, _)| at);
            let kill_switch_at = self.kill_switch_timer.map(|(at, _)| at);
            let settings_at = self.settings_timer.map(|(at, _)| at);
            let drop_at = self.drop_at;

            tokio::select! {
                msg = inbox.recv() => match msg {
                    Some(msg) => self.handle(msg),
                    None => return,
                },
                ctl = recv_control(&mut control) => match ctl {
                    Some(ctl) => self.control(ctl),
                    None => control = None,
                },
                () = sleep_opt(tunnel_at) => {
                    if let Some((_, step)) = self.tunnel_timer.take() {
                        self.advance_tunnel(step);
                    }
                }
                () = sleep_opt(kill_switch_at) => {
                    if let Some((_, armed)) = self.kill_switch_timer.take() {
                        self.apply_kill_switch(armed);
                    }
                }
                () = sleep_opt(settings_at) => {
                    if let Some((_, patch)) = self.settings_timer.take() {
                        self.apply_settings(patch);
                    }
                }
                () = sleep_opt(drop_at) => {
                    self.drop_at = None;
                    self.drop_tunnel("peer stopped responding");
                }
                _ = stats.tick() => self.emit_stats(),
                _ = loads.tick() => self.walk_loads(),
            }
        }
    }

    fn handle(&mut self, msg: ActorMsg) {
        match msg {
            ActorMsg::Act { action, reply } => {
                debug!(?action, "action");
                let result = self.act(action);
                // The client may have disconnected while waiting; the action still applies.
                let _ = reply.send(result);
            }
            ActorMsg::Subscribe { reply } => {
                let _ = reply.send(self.subscribe());
            }
        }
    }

    fn subscribe(&self) -> Subscription {
        Subscription {
            events: self.events.subscribe(),
            snapshot: Snapshot {
                protocol_version: PROTOCOL_VERSION,
                tunnel: self.tunnel.clone(),
                kill_switch: self.kill_switch.clone(),
                settings: self.settings,
                servers: self.servers(),
                recents: self.recents.iter().cloned().collect(),
                public_ip: self.public_ip.clone(),
                profiles_count: u32::try_from(self.catalog.len()).unwrap_or(u32::MAX),
            },
        }
    }

    fn act(&mut self, action: Action) -> Result<(), ErrorBody> {
        match action {
            Action::Connect(server_id) => self.connect(server_id),
            Action::QuickConnect => {
                let server_id = self.best_server().ok_or_else(|| ErrorBody {
                    code: ErrorCode::InvalidState,
                    message: "no servers available".into(),
                })?;
                self.connect(server_id)
            }
            Action::Disconnect => {
                self.disconnect();
                Ok(())
            }
            Action::SetKillSwitch(armed) => {
                self.kill_switch_timer = Some((self.after_ms(KILL_SWITCH_APPLY_MS), armed));
                Ok(())
            }
            Action::SetSettings(patch) => {
                if patch.is_empty() {
                    return Err(ErrorBody {
                        code: ErrorCode::BadRequest,
                        message: "set_settings needs at least one field".into(),
                    });
                }
                let queued = match self.settings_timer.take() {
                    Some((at, pending)) => (at, pending.merge(patch)),
                    None => (self.after_ms(SETTINGS_APPLY_MS), patch),
                };
                self.settings_timer = Some(queued);
                Ok(())
            }
            Action::ReloadProfiles => {
                self.broadcast(Event::ServersUpdated {
                    servers: self.servers(),
                });
                Ok(())
            }
        }
    }

    fn connect(&mut self, server_id: ServerId) -> Result<(), ErrorBody> {
        if self.entry(&server_id).is_none() {
            return Err(ErrorBody {
                code: ErrorCode::UnknownServer,
                message: format!("no server with id {server_id}"),
            });
        }
        let already_there = match &self.tunnel {
            TunnelState::Connected {
                server_id: current, ..
            }
            | TunnelState::Connecting {
                server_id: current, ..
            } => *current == server_id,
            TunnelState::Disconnected { .. }
            | TunnelState::Reconnecting { .. }
            | TunnelState::Disconnecting
            | TunnelState::Unknown => false,
        };
        if already_there {
            self.rebroadcast_tunnel();
            return Ok(());
        }

        self.leave_connected();
        self.tunnel_timer = Some((self.after_range(400, 800), TunnelStep::Handshake));
        self.set_tunnel(TunnelState::Connecting {
            server_id,
            phase: ConnectPhase::Resolving,
            started_at_ms: UnixMillis::now(),
        });
        self.set_public_ip(Some(self.home.clone()));
        Ok(())
    }

    fn disconnect(&mut self) {
        match &self.tunnel {
            TunnelState::Disconnected { .. } | TunnelState::Disconnecting => {
                self.rebroadcast_tunnel();
            }
            TunnelState::Connecting { .. }
            | TunnelState::Connected { .. }
            | TunnelState::Reconnecting { .. }
            | TunnelState::Unknown => {
                self.leave_connected();
                self.tunnel_timer =
                    Some((self.after_ms(DISCONNECT_MS), TunnelStep::FinishDisconnect));
                self.set_tunnel(TunnelState::Disconnecting);
                self.set_public_ip(Some(self.home.clone()));
            }
        }
    }

    fn advance_tunnel(&mut self, step: TunnelStep) {
        match step {
            TunnelStep::Handshake => {
                let TunnelState::Connecting {
                    server_id,
                    started_at_ms,
                    ..
                } = self.tunnel.clone()
                else {
                    return self.stale_timer(step);
                };
                self.tunnel_timer = Some((self.after_range(600, 1500), TunnelStep::Routes));
                self.set_tunnel(TunnelState::Connecting {
                    server_id,
                    phase: ConnectPhase::Handshaking,
                    started_at_ms,
                });
            }
            TunnelStep::Routes => {
                let TunnelState::Connecting {
                    server_id,
                    started_at_ms,
                    ..
                } = self.tunnel.clone()
                else {
                    return self.stale_timer(step);
                };
                if self.should_fail(self.connect_failure_rate) {
                    self.log(
                        LogLevel::Warn,
                        format!("handshake with {server_id} timed out"),
                    );
                    self.set_tunnel(TunnelState::Disconnected {
                        last_error: Some("handshake timed out".into()),
                    });
                } else {
                    self.tunnel_timer = Some((self.after_ms(ROUTES_MS), TunnelStep::Establish));
                    self.set_tunnel(TunnelState::Connecting {
                        server_id,
                        phase: ConnectPhase::ConfiguringRoutes,
                        started_at_ms,
                    });
                }
            }
            TunnelStep::Establish => {
                let TunnelState::Connecting { server_id, .. } = self.tunnel.clone() else {
                    return self.stale_timer(step);
                };
                self.establish(server_id);
            }
            TunnelStep::Retry => {
                let TunnelState::Reconnecting {
                    server_id,
                    attempt,
                    reason,
                    ..
                } = self.tunnel.clone()
                else {
                    return self.stale_timer(step);
                };
                self.tunnel_timer = Some((self.after_range(600, 1500), TunnelStep::RetryOutcome));
                self.set_tunnel(TunnelState::Reconnecting {
                    server_id,
                    attempt,
                    retry_at_ms: None,
                    reason,
                });
            }
            TunnelStep::RetryOutcome => {
                let TunnelState::Reconnecting {
                    server_id,
                    attempt,
                    reason,
                    ..
                } = self.tunnel.clone()
                else {
                    return self.stale_timer(step);
                };
                if self.should_fail(self.retry_failure_rate) {
                    self.log(
                        LogLevel::Warn,
                        format!("reconnect attempt {attempt} to {server_id} failed"),
                    );
                    self.schedule_retry(server_id, attempt.saturating_add(1), reason);
                } else {
                    self.establish(server_id);
                }
            }
            TunnelStep::FinishDisconnect => {
                if self.tunnel != TunnelState::Disconnecting {
                    return self.stale_timer(step);
                }
                self.set_tunnel(TunnelState::Disconnected { last_error: None });
            }
        }
    }

    fn stale_timer(&self, step: TunnelStep) {
        debug!(
            ?step,
            state = self.tunnel.name(),
            "ignoring stale tunnel timer"
        );
    }

    fn establish(&mut self, server_id: ServerId) {
        let Some(entry) = self.entry(&server_id).cloned() else {
            self.set_tunnel(TunnelState::Disconnected {
                last_error: Some(format!("server {server_id} is no longer available")),
            });
            return;
        };
        let now = UnixMillis::now();
        self.session = Some(Session {
            rx_bytes: 0,
            tx_bytes: 0,
            rx_rate: BASELINE_RX_BYTES_PER_SEC,
            last_handshake: now,
            next_rekey: Instant::now() + self.scaled(REKEY_INTERVAL),
        });
        if self.scenario == Scenario::Flaky {
            self.drop_at = Some(self.after_range(30_000, 60_000));
        }
        self.recents.retain(|id| *id != server_id);
        self.recents.push_front(server_id.clone());
        self.recents.truncate(MAX_RECENTS);

        self.set_tunnel(TunnelState::Connected {
            server_id,
            since_ms: now,
            endpoint: format!("{}:51820", entry.exit_ip),
            last_handshake_ms: Some(now),
        });
        self.set_public_ip(Some(entry.exit_info()));
        self.log(
            LogLevel::Info,
            format!("tunnel up via {}", entry.server.name),
        );
    }

    fn drop_tunnel(&mut self, reason: &str) {
        let TunnelState::Connected { server_id, .. } = &self.tunnel else {
            info!(
                state = self.tunnel.name(),
                "drop requested but tunnel is not up"
            );
            return;
        };
        let server_id = server_id.clone();
        self.leave_connected();
        self.log(LogLevel::Warn, format!("tunnel dropped: {reason}"));
        if self.settings.auto_reconnect {
            self.schedule_retry(server_id, 1, reason.to_owned());
        } else {
            self.set_tunnel(TunnelState::Disconnected {
                last_error: Some(format!("connection lost: {reason}")),
            });
        }
        self.set_public_ip(Some(self.home.clone()));
    }

    fn schedule_retry(&mut self, server_id: ServerId, attempt: u32, reason: String) {
        let delay = self.scaled(reconnect_backoff(attempt));
        self.tunnel_timer = Some((Instant::now() + delay, TunnelStep::Retry));
        self.set_tunnel(TunnelState::Reconnecting {
            server_id,
            attempt,
            retry_at_ms: Some(UnixMillis::now().plus(delay)),
            reason,
        });
    }

    fn leave_connected(&mut self) {
        self.session = None;
        self.drop_at = None;
    }

    fn apply_kill_switch(&mut self, armed: bool) {
        let state = if !armed {
            KillSwitchState::Off
        } else if self.kill_switch_fault {
            KillSwitchState::Error {
                message: KILL_SWITCH_FAULT.into(),
            }
        } else {
            KillSwitchState::Armed
        };
        self.set_kill_switch(state);
    }

    fn set_kill_switch(&mut self, state: KillSwitchState) {
        if let KillSwitchState::Error { message } = &state {
            self.log(LogLevel::Error, format!("kill switch: {message}"));
        }
        self.kill_switch = state.clone();
        self.broadcast(Event::KillSwitchChanged { kill_switch: state });
    }

    fn apply_settings(&mut self, patch: SettingsPatch) {
        patch.apply(&mut self.settings);
        self.broadcast(Event::SettingsChanged {
            settings: self.settings,
        });
    }

    fn control(&mut self, control: Control) {
        info!(?control, "operator control");
        match control {
            Control::Drop => self.drop_tunnel("peer stopped responding (forced drop)"),
            Control::FailNext => {
                self.fail_next = true;
                self.log(LogLevel::Info, "next handshake will fail (operator)".into());
            }
            Control::KillSwitchError => {
                self.kill_switch_fault = true;
                self.kill_switch_timer = None;
                self.set_kill_switch(KillSwitchState::Error {
                    message: KILL_SWITCH_FAULT.into(),
                });
            }
            Control::KillSwitchClear => {
                self.kill_switch_fault = false;
                if matches!(self.kill_switch, KillSwitchState::Error { .. }) {
                    self.kill_switch_timer = Some((self.after_ms(KILL_SWITCH_APPLY_MS), true));
                }
            }
        }
    }

    fn emit_stats(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let rng = &mut self.rng;
        let reverted = session.rx_rate + (BASELINE_RX_BYTES_PER_SEC - session.rx_rate) * 0.15;
        session.rx_rate = (reverted * (0.7 + rng.unit() * 0.6)).clamp(2_000.0, 40_000_000.0);
        let burst = if rng.chance(0.08) {
            3.0 + rng.unit() * 6.0
        } else {
            1.0
        };
        let rx = session.rx_rate * burst;
        let tx = rx * (0.05 + rng.unit() * 0.3);
        session.rx_bytes = session.rx_bytes.saturating_add(rx as u64);
        session.tx_bytes = session.tx_bytes.saturating_add(tx as u64);

        let now = Instant::now();
        if now >= session.next_rekey {
            session.last_handshake = UnixMillis::now();
            session.next_rekey = now + REKEY_INTERVAL.mul_f64(self.time_scale);
        }
        let stats = Stats {
            rx_bytes: session.rx_bytes,
            tx_bytes: session.tx_bytes,
            last_handshake_ms: Some(session.last_handshake),
        };
        if let TunnelState::Connected {
            last_handshake_ms, ..
        } = &mut self.tunnel
        {
            *last_handshake_ms = stats.last_handshake_ms;
        }
        self.broadcast(Event::Stats(stats));
    }

    fn walk_loads(&mut self) {
        for entry in &mut self.catalog {
            if let Some(load) = entry.server.load_pct {
                let walked = i64::from(load) + self.rng.jitter(4);
                entry.server.load_pct = Some(walked.clamp(5, 95) as u8);
            }
            entry.server.latency_ms =
                Some(entry.base_latency_ms + self.rng.range(0, LATENCY_JITTER_MS) as u32);
        }
        self.broadcast(Event::ServersUpdated {
            servers: self.servers(),
        });
    }

    fn set_tunnel(&mut self, tunnel: TunnelState) {
        info!(state = tunnel.name(), server = ?tunnel.server_id(), "tunnel");
        self.tunnel = tunnel.clone();
        self.broadcast(Event::TunnelChanged { tunnel });
    }

    /// Idempotent commands still produce an event so the requesting client sees confirmation.
    fn rebroadcast_tunnel(&self) {
        self.broadcast(Event::TunnelChanged {
            tunnel: self.tunnel.clone(),
        });
    }

    fn set_public_ip(&mut self, ip: Option<IpInfo>) {
        if self.public_ip != ip {
            self.public_ip = ip.clone();
            self.broadcast(Event::PublicIpChanged { public_ip: ip });
        }
    }

    fn log(&self, level: LogLevel, message: String) {
        match level {
            LogLevel::Error => error!("{message}"),
            LogLevel::Warn => warn!("{message}"),
            LogLevel::Info | LogLevel::Unknown => info!("{message}"),
            LogLevel::Debug => debug!("{message}"),
        }
        self.broadcast(Event::Log { level, message });
    }

    fn broadcast(&self, event: Event) {
        // Fails only when nobody is subscribed.
        let _ = self.events.send(event);
    }

    fn servers(&self) -> Vec<vpnui_proto::Server> {
        self.catalog.iter().map(|e| e.server.clone()).collect()
    }

    fn entry(&self, id: &ServerId) -> Option<&CatalogEntry> {
        self.catalog.iter().find(|e| e.server.id == *id)
    }

    fn best_server(&self) -> Option<ServerId> {
        self.catalog
            .iter()
            .min_by_key(|e| {
                let load = e.server.load_pct.map_or(u32::MAX / 4, u32::from);
                let latency = e.server.latency_ms.unwrap_or(u32::MAX / 4);
                (load * 2 + latency, e.server.id.clone())
            })
            .map(|e| e.server.id.clone())
    }

    fn should_fail(&mut self, rate: f64) -> bool {
        if self.fail_next {
            self.fail_next = false;
            return true;
        }
        self.rng.chance(rate)
    }

    fn scaled(&self, duration: Duration) -> Duration {
        duration.mul_f64(self.time_scale)
    }

    fn after_ms(&self, ms: u64) -> Instant {
        Instant::now() + self.scaled(Duration::from_millis(ms))
    }

    fn after_range(&mut self, lo_ms: u64, hi_ms: u64) -> Instant {
        let delay = self.rng.millis(lo_ms, hi_ms);
        Instant::now() + self.scaled(delay)
    }
}

/// 1s, 2s, 4s, 8s, then capped at 15s.
fn reconnect_backoff(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(5);
    Duration::from_secs(1 << exponent).min(RECONNECT_BACKOFF_CAP)
}

async fn sleep_opt(deadline: Option<Instant>) {
    match deadline {
        Some(at) => sleep_until(at).await,
        None => std::future::pending().await,
    }
}

async fn recv_control(control: &mut Option<mpsc::Receiver<Control>>) -> Option<Control> {
    match control {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let secs: Vec<u64> = (1..=7).map(|a| reconnect_backoff(a).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 15, 15, 15]);
    }
}
