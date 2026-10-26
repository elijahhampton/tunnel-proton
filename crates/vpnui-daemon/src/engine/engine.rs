//! The engine: sole owner of tunnel, policy, route, and DNS state. It runs on one thread and
//! performs every privileged step through [`Platform`], in order.
//!
//! The kill-switch exceptions are derived from the write-ahead journal: an endpoint or tunnel
//! interface is allowed exactly while its journal entry exists. Undoing an entry and recomputing
//! the policy are the same operation, which is what makes crash recovery a replay of undos.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};
use vpnui_proto::{
    ConnectPhase, ErrorBody, ErrorCode, Event, IpInfo, KillSwitchState, Server, ServerId, Settings,
    SettingsPatch, Stats, TunnelState, UnixMillis,
};

use crate::country;
use crate::net::net::{DefaultRoute, IpNet, split_default_routes};
use crate::platform::{Anchor, Mono, Now, Platform, PlatformError, WgInstance};
use crate::policy::policy::{self, Policy};
use crate::profile::profile::Profile;
use crate::shared::Shared;
use crate::state::{JournalEntry, PersistedState, Undo};
use crate::uapi::uapi::DeviceConfig;

pub(crate) const BACKOFF_SECS: [u64; 5] = [1, 2, 4, 8, 15];
pub(crate) const SOFT_ATTEMPTS: u32 = 3;
pub(crate) const DEFAULT_TUNNEL_MTU: u16 = 1420;
pub(crate) const TUNNEL_OVERHEAD: u16 = 80;

#[derive(Debug, Clone)]
pub struct EngineOptions {
    pub handshake_timeout: Duration,
    /// WireGuard's REJECT_AFTER_TIME: a session older than this cannot carry data.
    pub reject_after: Duration,
    pub soft_window: Duration,
    pub keepalive: u16,
    pub wake_gap: Duration,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(15),
            reject_after: Duration::from_secs(180),
            soft_window: Duration::from_secs(5),
            keepalive: 25,
            wake_gap: Duration::from_secs(5),
        }
    }
}

#[derive(Debug)]
pub enum Action {
    Connect(String),
    QuickConnect,
    Disconnect,
    SetKillSwitch(bool),
    SetSettings(SettingsPatch),
    ReloadProfiles,
}

pub type Reply = tokio::sync::oneshot::Sender<Result<(), ErrorBody>>;

pub enum Input {
    Command {
        action: Action,
        reply: Option<Reply>,
    },
    Tick,
    /// Result of the optional public-IP check.
    PublicIp(Option<IpAddr>),
    /// Leave the loop. `graceful` tears the tunnel down first; otherwise this simulates a crash.
    Stop {
        graceful: bool,
        done: Option<std::sync::mpsc::Sender<()>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {message}", code.as_str())]
pub struct EngineError {
    pub code: ErrorCode,
    pub message: String,
}

impl EngineError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn body(&self) -> ErrorBody {
        ErrorBody {
            code: self.code,
            message: self.message.clone(),
        }
    }
}

impl From<PlatformError> for EngineError {
    fn from(e: PlatformError) -> Self {
        Self::new(e.op.error_code(), e.to_string())
    }
}

pub(crate) type Result<T, E = EngineError> = std::result::Result<T, E>;

#[derive(Debug, Clone)]
pub(crate) struct Retry {
    pub(crate) attempt: u32,
    pub(crate) reason: String,
}

#[derive(Debug, Clone)]
pub(crate) enum Phase {
    /// Waiting for the first handshake. `retry` is set for a hard reconnect attempt.
    Handshaking {
        deadline: Mono,
        retry: Option<Retry>,
    },
    Connected,
    /// Backing off before the next attempt.
    Waiting {
        retry: Retry,
        at: Mono,
        at_wall: UnixMillis,
    },
    /// A soft attempt is in flight: waiting for a handshake newer than `forced_at`.
    Soft {
        retry: Retry,
        deadline: Mono,
        forced_at: UnixMillis,
    },
    /// No default route; nothing to do until one appears.
    Offline {
        retry: Retry,
    },
}

#[derive(Debug)]
pub(crate) struct Session {
    pub(crate) id: u64,
    pub(crate) profile: Profile,
    pub(crate) route: DefaultRoute,
    pub(crate) instance: Option<WgInstance>,
    pub(crate) phase: Phase,
    pub(crate) started_at: UnixMillis,
    pub(crate) since: Option<UnixMillis>,
    pub(crate) last_handshake: Option<UnixMillis>,
}

pub(crate) struct Engine<P: Platform> {
    pub(crate) p: P,
    pub(crate) shared: Arc<Shared>,
    pub(crate) opts: EngineOptions,
    pub(crate) st: PersistedState,
    pub(crate) catalog: Vec<Profile>,
    pub(crate) kill_switch: KillSwitchState,
    pub(crate) session: Option<Session>,
    pub(crate) last_error: Option<String>,
    pub(crate) last_tick: Option<Now>,
    pub(crate) next_session: u64,
    pub(crate) last_loaded: Option<Policy>,
    pub(crate) recovering: bool,
    pub(crate) published_tunnel: Option<TunnelState>,
    pub(crate) public_ip: Option<IpInfo>,
}

pub(crate) fn backoff(attempt: u32) -> Duration {
    let index = usize::try_from(attempt.saturating_sub(1)).unwrap_or(usize::MAX);
    let secs = BACKOFF_SECS
        .get(index)
        .copied()
        .unwrap_or(BACKOFF_SECS[BACKOFF_SECS.len() - 1]);
    Duration::from_secs(secs)
}

pub(crate) fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Which routes send traffic into the tunnel: the split default routes for every family, plus
/// any narrower AllowedIPs.
pub fn tunnel_routes(profile: &Profile) -> Vec<IpNet> {
    let mut routes: Vec<IpNet> = split_default_routes().to_vec();
    for net in &profile.peer.allowed_ips {
        if !net.is_default() && !routes.contains(net) {
            routes.push(*net);
        }
    }
    routes
}

pub fn server_of(profile: &Profile) -> Server {
    let country = profile.country_code.as_deref().and_then(country::lookup);
    Server {
        id: ServerId::new(profile.id.clone()),
        name: profile.name.clone(),
        country_code: profile
            .country_code
            .clone()
            .unwrap_or_else(|| "--".to_owned()),
        country: match (country, &profile.country_code) {
            (Some(c), _) => c.name.to_owned(),
            (None, Some(code)) => code.clone(),
            (None, None) => "No country".to_owned(),
        },
        city: profile.city.clone().unwrap_or_default(),
        lat: country.map(|c| c.lat),
        lon: country.map(|c| c.lon),
        load_pct: None,
        latency_ms: None,
        features: Vec::new(),
        profile_id: Some(ServerId::new(profile.id.clone())),
        entry_ip: Some(profile.endpoint().ip()),
        imported_at_ms: Some(profile.imported_at),
    }
}

pub(crate) fn same_ignoring_handshake(a: &TunnelState, b: &TunnelState) -> bool {
    match (a, b) {
        (
            TunnelState::Connected {
                server_id: s1,
                since_ms: t1,
                endpoint: e1,
                ..
            },
            TunnelState::Connected {
                server_id: s2,
                since_ms: t2,
                endpoint: e2,
                ..
            },
        ) => s1 == s2 && t1 == t2 && e1 == e2,
        (a, b) => a == b,
    }
}

/// Runs the engine until it is told to stop or every sender is gone.
pub(crate) fn run<P: Platform>(mut engine: Engine<P>, inbox: std::sync::mpsc::Receiver<Input>) {
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Instant;

    let mut next_tick = Instant::now() + engine.tick_interval();
    loop {
        let wait = next_tick.saturating_duration_since(Instant::now());
        match inbox.recv_timeout(wait) {
            Ok(Input::Stop { graceful, done }) => {
                engine.handle(Input::Stop { graceful, done });
                return;
            }
            Ok(input) => {
                engine.handle(input);
                next_tick = next_tick.min(Instant::now() + engine.tick_interval());
            }
            Err(RecvTimeoutError::Timeout) => {
                engine.handle(Input::Tick);
                next_tick = Instant::now() + engine.tick_interval();
            }
            Err(RecvTimeoutError::Disconnected) => {
                engine.shutdown();
                return;
            }
        }
    }
}

#[cfg(test)]
use crate::engine::tests;
