//! Application state, inputs, and outputs. [`update`] is the only function that changes
//! [`AppState`], and it performs no I/O: anything that leaves the process is an [`Effect`].

#[cfg(test)]
pub(crate) mod fixtures;
mod intent;
mod keymap;
mod posture;
mod update;

use std::collections::VecDeque;
use std::time::Duration;

use crossterm::event::{KeyEvent, MouseEvent};
use vpnui_proto::{
    DaemonMessage, IpInfo, KillSwitchState, ProtocolVersion, Request, RequestId, Server, ServerId,
    Settings, Snapshot, Stats, TunnelState, UnixMillis,
};

pub use intent::{Intent, PendingRequest, SettingKey, Slot};
pub use posture::{Posture, kill_switch_warning, posture};
pub use update::update;

use crate::browser::Browser;
use crate::layout::{self, AppLayout};
use crate::theme::Theme;

pub const PENDING_TIMEOUT: Duration = Duration::from_secs(10);
pub const TOAST_TTL: Duration = Duration::from_secs(5);
pub const EVENT_LOG_CAPACITY: usize = 200;
pub const RECENTS_SHOWN: usize = 5;
pub const TRAFFIC_WINDOW: usize = 60;
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub enum Event {
    Tick(UnixMillis),
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
    Link(LinkEvent),
    Daemon(Box<DaemonMessage>),
    /// SIGINT, SIGTERM, or SIGHUP.
    Shutdown,
}

/// Socket-level happenings reported by the link task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    /// A new socket is open. Nothing has been exchanged on it yet.
    Connected,
    /// The socket closed or could not be opened; the link retries after `retry_in`.
    Down {
        reason: String,
        retry_in: Duration,
    },
    SendFailed(RequestId),
    Malformed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Send(Request),
    Log(Severity, String),
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Success,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonLink {
    /// Socket opening or handshake (hello, subscribe) in progress.
    Connecting,
    /// A snapshot has arrived on the current socket; the projection is current.
    Live,
    Lost {
        since: UnixMillis,
        next_retry_at: UnixMillis,
    },
}

/// The TUI's copy of daemon-owned state. Replaced wholesale by every snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct Projection {
    pub tunnel: TunnelState,
    pub kill_switch: KillSwitchState,
    pub settings: Settings,
    pub servers: Vec<Server>,
    pub recents: Vec<ServerId>,
    pub public_ip: Option<IpInfo>,
    pub stats: Option<Stats>,
    pub profiles_count: u32,
}

impl Projection {
    pub fn from_snapshot(snapshot: Snapshot) -> Self {
        Self {
            tunnel: snapshot.tunnel,
            kill_switch: snapshot.kill_switch,
            settings: snapshot.settings,
            servers: snapshot.servers,
            recents: snapshot.recents,
            public_ip: snapshot.public_ip,
            stats: None,
            profiles_count: snapshot.profiles_count,
        }
    }

    /// The server `quick_connect` will use, mirroring the daemon's rule for imported profiles:
    /// the most recent entry in recents that still exists, else the most recently imported
    /// profile. `None` for catalogs that are not profiles; the daemon then picks.
    pub fn quick_connect_target(&self) -> Option<&Server> {
        if !self.servers.iter().any(|s| s.profile_id.is_some()) {
            return None;
        }
        self.recents
            .iter()
            .find_map(|id| self.server(id))
            .or_else(|| {
                self.servers
                    .iter()
                    .filter(|s| s.imported_at_ms.is_some())
                    .max_by(|a, b| {
                        a.imported_at_ms
                            .cmp(&b.imported_at_ms)
                            .then_with(|| b.id.cmp(&a.id))
                    })
            })
    }

    pub fn server(&self, id: &ServerId) -> Option<&Server> {
        self.servers.iter().find(|s| s.id == *id)
    }

    pub fn server_name(&self, id: &ServerId) -> String {
        self.server(id)
            .map_or_else(|| id.to_string(), |s| s.name.clone())
    }

    pub fn recent_servers(&self) -> impl Iterator<Item = &ServerId> {
        self.recents.iter().take(RECENTS_SHOWN)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMismatch {
    pub client: ProtocolVersion,
    pub daemon: Option<ProtocolVersion>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum View {
    #[default]
    Home,
    Servers,
    Stats,
    Settings,
}

impl View {
    pub const ALL: [Self; 4] = [Self::Home, Self::Servers, Self::Stats, Self::Settings];

    pub fn number(self) -> u8 {
        match self {
            Self::Home => 1,
            Self::Servers => 2,
            Self::Stats => 3,
            Self::Settings => 4,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Servers => "Servers",
            Self::Stats => "Stats",
            Self::Settings => "Settings",
        }
    }

    fn index(self) -> usize {
        usize::from(self.number() - 1)
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingRow {
    KillSwitch,
    AllowLan,
    BlockIpv6,
    AutoReconnect,
}

impl SettingRow {
    pub const ALL: [Self; 4] = [
        Self::KillSwitch,
        Self::AllowLan,
        Self::BlockIpv6,
        Self::AutoReconnect,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::KillSwitch => "Kill switch",
            Self::AllowLan => "Allow LAN while armed",
            Self::BlockIpv6 => "Block IPv6 outside the tunnel",
            Self::AutoReconnect => "Auto-reconnect",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::KillSwitch => {
                "When armed, the daemon blocks all traffic that does not go through the tunnel, \
                 including while connecting or reconnecting."
            }
            Self::AllowLan => {
                "Lets traffic to local networks (printers, NAS, router) bypass the kill switch. \
                 Turning this on lowers protection."
            }
            Self::BlockIpv6 => {
                "Drops IPv6 traffic that would otherwise leave outside the tunnel. Turning this \
                 off lowers protection."
            }
            Self::AutoReconnect => {
                "Reconnects automatically with backoff when the tunnel drops instead of staying \
                 disconnected."
            }
        }
    }

    pub fn setting_key(self) -> Option<SettingKey> {
        match self {
            Self::KillSwitch => None,
            Self::AllowLan => Some(SettingKey::AllowLan),
            Self::BlockIpv6 => Some(SettingKey::BlockIpv6),
            Self::AutoReconnect => Some(SettingKey::AutoReconnect),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    Help { scroll: u16 },
    Confirm { kind: ConfirmKind, selected: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmKind {
    DisconnectWhileArmed,
    Disarm,
    KillSwitchFailed { message: String },
    AllowLan,
    DisableBlockIpv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    DisconnectAndDisarm,
    DisconnectStayBlocked,
    Disarm,
    RetryArming,
    TurnOff,
    AllowLan,
    DisableBlockIpv6,
    Cancel,
}

impl ConfirmKind {
    pub fn title(&self) -> &'static str {
        match self {
            Self::DisconnectWhileArmed => "Disconnect?",
            Self::Disarm => "Disarm kill switch?",
            Self::KillSwitchFailed { .. } => "Kill switch failed",
            Self::AllowLan => "Allow LAN traffic?",
            Self::DisableBlockIpv6 => "Stop blocking IPv6?",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::DisconnectWhileArmed => {
                "Kill switch is armed. Disconnecting will block all traffic.".to_owned()
            }
            Self::Disarm => {
                "Disarming lets traffic leave unencrypted whenever the tunnel is down.".to_owned()
            }
            Self::KillSwitchFailed { message } => {
                format!("The blocking policy could not be applied: {message}")
            }
            Self::AllowLan => {
                "Local-network traffic will bypass the kill switch while it is armed.".to_owned()
            }
            Self::DisableBlockIpv6 => {
                "IPv6 traffic may leave outside the tunnel and reveal your address.".to_owned()
            }
        }
    }

    /// The last choice is always `Cancel`, which is also the initial selection.
    pub fn choices(&self) -> &'static [Choice] {
        match self {
            Self::DisconnectWhileArmed => &[
                Choice::DisconnectAndDisarm,
                Choice::DisconnectStayBlocked,
                Choice::Cancel,
            ],
            Self::Disarm => &[Choice::Disarm, Choice::Cancel],
            Self::KillSwitchFailed { .. } => {
                &[Choice::RetryArming, Choice::TurnOff, Choice::Cancel]
            }
            Self::AllowLan => &[Choice::AllowLan, Choice::Cancel],
            Self::DisableBlockIpv6 => &[Choice::DisableBlockIpv6, Choice::Cancel],
        }
    }
}

impl Choice {
    pub fn label(self) -> &'static str {
        match self {
            Self::DisconnectAndDisarm => "Disconnect and disarm",
            Self::DisconnectStayBlocked => "Disconnect, stay blocked",
            Self::Disarm => "Disarm",
            Self::RetryArming => "Retry arming",
            Self::TurnOff => "Turn kill switch off",
            Self::AllowLan => "Allow LAN",
            Self::DisableBlockIpv6 => "Stop blocking IPv6",
            Self::Cancel => "Cancel",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    pub text: String,
    pub severity: Severity,
    pub expires_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub at: UnixMillis,
    pub severity: Severity,
    pub text: String,
}

/// Newest first, bounded to [`EVENT_LOG_CAPACITY`].
#[derive(Debug, Clone, Default)]
pub struct EventLog {
    entries: VecDeque<LogEntry>,
}

impl EventLog {
    pub fn push(&mut self, entry: LogEntry) {
        if self.entries.len() == EVENT_LOG_CAPACITY {
            self.entries.pop_back();
        }
        self.entries.push_front(entry);
    }

    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Per-second throughput derived from consecutive cumulative `stats` events.
#[derive(Debug, Clone, Default)]
pub struct Traffic {
    pub rx: VecDeque<u64>,
    pub tx: VecDeque<u64>,
    last: Option<(u64, u64)>,
}

impl Traffic {
    pub fn record(&mut self, stats: Stats) {
        if let Some((rx, tx)) = self.last {
            if stats.rx_bytes < rx || stats.tx_bytes < tx {
                self.reset();
            } else {
                push_bounded(&mut self.rx, stats.rx_bytes - rx);
                push_bounded(&mut self.tx, stats.tx_bytes - tx);
            }
        }
        self.last = Some((stats.rx_bytes, stats.tx_bytes));
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn current(&self) -> Option<(u64, u64)> {
        Some((*self.rx.back()?, *self.tx.back()?))
    }
}

fn push_bounded(samples: &mut VecDeque<u64>, value: u64) {
    if samples.len() == TRAFFIC_WINDOW {
        samples.pop_front();
    }
    samples.push_back(value);
}

#[derive(Debug, Clone, Default)]
pub struct Ui {
    pub view: View,
    pub modal: Option<Modal>,
    pub browser: Browser,
    pub settings_cursor: usize,
    pub recents_cursor: usize,
    pub log_offset: usize,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub now: UnixMillis,
    pub width: u16,
    pub height: u16,
    pub link: DaemonLink,
    /// When the projection stopped being current; carried across failed reconnects.
    pub lost_since: Option<UnixMillis>,
    pub ever_live: bool,
    pub daemon: Option<Projection>,
    pub version_mismatch: Option<VersionMismatch>,
    pub in_flight: Vec<PendingRequest>,
    pub next_request_id: u64,
    pub ui: Ui,
    pub toast: Option<Toast>,
    pub log: EventLog,
    pub traffic: Traffic,
    /// Last public IP seen while the tunnel was down, i.e. the user's real location.
    pub origin: Option<IpInfo>,
    pub theme: Theme,
    pub quitting: bool,
}

impl AppState {
    pub fn new(theme: Theme, now: UnixMillis, width: u16, height: u16) -> Self {
        Self {
            now,
            width,
            height,
            link: DaemonLink::Connecting,
            lost_since: None,
            ever_live: false,
            daemon: None,
            version_mismatch: None,
            in_flight: Vec::new(),
            next_request_id: 1,
            ui: Ui::default(),
            toast: None,
            log: EventLog::default(),
            traffic: Traffic::default(),
            origin: None,
            theme,
            quitting: false,
        }
    }

    pub fn layout(&self) -> AppLayout {
        layout::compute(
            ratatui::layout::Rect::new(0, 0, self.width, self.height),
            self.ui.view,
        )
    }

    /// The projection, but only while it is current.
    pub fn live(&self) -> Option<&Projection> {
        match self.link {
            DaemonLink::Live => self.daemon.as_ref(),
            DaemonLink::Connecting | DaemonLink::Lost { .. } => None,
        }
    }

    pub fn is_stale(&self) -> bool {
        self.daemon.is_some() && self.live().is_none()
    }

    pub fn pending(&self, slot: Slot) -> Option<&PendingRequest> {
        self.in_flight.iter().find(|p| p.intent.slot() == slot)
    }

    pub fn servers(&self) -> &[Server] {
        self.daemon.as_ref().map_or(&[], |p| p.servers.as_slice())
    }

    /// Spinner frames are due only while the tunnel is mid-transition.
    pub fn animating(&self) -> bool {
        self.live().is_some_and(|p| match p.tunnel {
            TunnelState::Connecting { .. } | TunnelState::Reconnecting { .. } => true,
            TunnelState::Disconnected { .. }
            | TunnelState::Connected { .. }
            | TunnelState::Disconnecting
            | TunnelState::Unknown => false,
        })
    }
}

/// The contextual button in the rail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryAction {
    QuickConnect,
    Disconnect,
    Cancel,
    ReconnectNow,
    Wait,
}

impl PrimaryAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::QuickConnect => "Quick connect",
            Self::Disconnect => "Disconnect",
            Self::Cancel => "Cancel",
            Self::ReconnectNow => "Reconnect now",
            Self::Wait => "Disconnecting",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::QuickConnect => "c",
            Self::Disconnect => "d",
            Self::Cancel => "Esc",
            Self::ReconnectNow => "r",
            Self::Wait => "",
        }
    }

    pub fn for_tunnel(tunnel: &TunnelState) -> Self {
        match tunnel {
            TunnelState::Disconnected { .. } => Self::QuickConnect,
            TunnelState::Connecting { .. } => Self::Cancel,
            TunnelState::Connected { .. } => Self::Disconnect,
            TunnelState::Reconnecting { .. } => Self::ReconnectNow,
            TunnelState::Disconnecting | TunnelState::Unknown => Self::Wait,
        }
    }
}
