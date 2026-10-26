use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::ids::{ProtocolVersion, RequestId, ServerId};
use crate::types::{IpInfo, KillSwitchState, Server, Settings, SettingsPatch, Stats, TunnelState};

/// Client -> daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub id: RequestId,
    pub cmd: Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    Hello {
        client_version: String,
        protocol_version: ProtocolVersion,
    },
    Subscribe,
    Connect {
        server_id: ServerId,
    },
    QuickConnect,
    Disconnect,
    SetKillSwitch {
        armed: bool,
    },
    SetSettings(SettingsPatch),
    ReloadProfiles,
    #[serde(other)]
    Unknown,
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Subscribe => "subscribe",
            Self::Connect { .. } => "connect",
            Self::QuickConnect => "quick_connect",
            Self::Disconnect => "disconnect",
            Self::SetKillSwitch { .. } => "set_kill_switch",
            Self::SetSettings(_) => "set_settings",
            Self::ReloadProfiles => "reload_profiles",
            Self::Unknown => "unknown",
        }
    }
}

/// Daemon -> client reply to exactly one [`Request`].
///
/// `protocol_version` is only present on the reply to `hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub id: RequestId,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<ProtocolVersion>,
}

impl Response {
    pub fn ok(id: RequestId) -> Self {
        Self {
            id,
            ok: true,
            error: None,
            protocol_version: None,
        }
    }

    pub fn err(id: RequestId, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            error: Some(ErrorBody {
                code,
                message: message.into(),
            }),
            protocol_version: None,
        }
    }

    pub fn with_protocol_version(mut self, version: ProtocolVersion) -> Self {
        self.protocol_version = Some(version);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    UnknownServer,
    InvalidState,
    VersionMismatch,
    Internal,
    NoProfiles,
    NoNetwork,
    BinaryUntrusted,
    HandshakeTimeout,
    PfFailed,
    RouteFailed,
    DnsFailed,
    WgFailed,
    Busy,
    Unauthorized,
    #[serde(other)]
    Unknown,
}

impl ErrorCode {
    pub const ALL: [Self; 15] = [
        Self::BadRequest,
        Self::UnknownServer,
        Self::InvalidState,
        Self::VersionMismatch,
        Self::Internal,
        Self::NoProfiles,
        Self::NoNetwork,
        Self::BinaryUntrusted,
        Self::HandshakeTimeout,
        Self::PfFailed,
        Self::RouteFailed,
        Self::DnsFailed,
        Self::WgFailed,
        Self::Busy,
        Self::Unauthorized,
    ];

    /// The wire spelling, e.g. `handshake_timeout`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::UnknownServer => "unknown_server",
            Self::InvalidState => "invalid_state",
            Self::VersionMismatch => "version_mismatch",
            Self::Internal => "internal",
            Self::NoProfiles => "no_profiles",
            Self::NoNetwork => "no_network",
            Self::BinaryUntrusted => "binary_untrusted",
            Self::HandshakeTimeout => "handshake_timeout",
            Self::PfFailed => "pf_failed",
            Self::RouteFailed => "route_failed",
            Self::DnsFailed => "dns_failed",
            Self::WgFailed => "wg_failed",
            Self::Busy => "busy",
            Self::Unauthorized => "unauthorized",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(code: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == code)
            .unwrap_or(Self::Unknown)
    }
}

/// Daemon -> client, unsolicited. Broadcast to every subscribed client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Snapshot(Box<Snapshot>),
    TunnelChanged {
        tunnel: TunnelState,
    },
    KillSwitchChanged {
        kill_switch: KillSwitchState,
    },
    SettingsChanged {
        settings: Settings,
    },
    Stats(Stats),
    ServersUpdated {
        servers: Vec<Server>,
    },
    PublicIpChanged {
        public_ip: Option<IpInfo>,
    },
    Log {
        level: LogLevel,
        message: String,
    },
    #[serde(other)]
    Unknown,
}

impl Event {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Snapshot(_) => "snapshot",
            Self::TunnelChanged { .. } => "tunnel_changed",
            Self::KillSwitchChanged { .. } => "kill_switch_changed",
            Self::SettingsChanged { .. } => "settings_changed",
            Self::Stats(_) => "stats",
            Self::ServersUpdated { .. } => "servers_updated",
            Self::PublicIpChanged { .. } => "public_ip_changed",
            Self::Log { .. } => "log",
            Self::Unknown => "unknown",
        }
    }
}

/// Full authoritative state, sent in reply to `subscribe` and whenever a client must resync.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub protocol_version: ProtocolVersion,
    pub tunnel: TunnelState,
    pub kill_switch: KillSwitchState,
    pub settings: Settings,
    pub servers: Vec<Server>,
    /// Most recent first.
    pub recents: Vec<ServerId>,
    pub public_ip: Option<IpInfo>,
    /// Number of imported profiles. Absent from v1 snapshots.
    #[serde(default)]
    pub profiles_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    #[serde(other)]
    Unknown,
}

/// Anything the daemon writes to a client: `{"id":..,"ok":..}` or `{"event":{..}}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DaemonMessage {
    Response(Response),
    Event { event: Event },
}

impl<'de> Deserialize<'de> for DaemonMessage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Envelope {
            event: Event,
        }

        let value = serde_json::Value::deserialize(deserializer)?;
        if value.get("event").is_some() {
            Envelope::deserialize(value)
                .map(|e| Self::Event { event: e.event })
                .map_err(D::Error::custom)
        } else {
            Response::deserialize(value)
                .map(Self::Response)
                .map_err(D::Error::custom)
        }
    }
}
