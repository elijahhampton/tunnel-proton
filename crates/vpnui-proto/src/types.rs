use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::ids::{ServerId, UnixMillis};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TunnelState {
    Disconnected {
        #[serde(default)]
        last_error: Option<String>,
    },
    Connecting {
        server_id: ServerId,
        phase: ConnectPhase,
        started_at_ms: UnixMillis,
    },
    Connected {
        server_id: ServerId,
        since_ms: UnixMillis,
        endpoint: String,
        #[serde(default)]
        last_handshake_ms: Option<UnixMillis>,
    },
    /// `retry_at_ms` is `None` while a reconnect attempt is in progress.
    Reconnecting {
        server_id: ServerId,
        attempt: u32,
        #[serde(default)]
        retry_at_ms: Option<UnixMillis>,
        reason: String,
    },
    Disconnecting,
    #[serde(other)]
    Unknown,
}

impl TunnelState {
    pub fn server_id(&self) -> Option<&ServerId> {
        match self {
            Self::Connecting { server_id, .. }
            | Self::Connected { server_id, .. }
            | Self::Reconnecting { server_id, .. } => Some(server_id),
            Self::Disconnected { .. } | Self::Disconnecting | Self::Unknown => None,
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Disconnected { .. } => "disconnected",
            Self::Connecting { .. } => "connecting",
            Self::Connected { .. } => "connected",
            Self::Reconnecting { .. } => "reconnecting",
            Self::Disconnecting => "disconnecting",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectPhase {
    Resolving,
    Handshaking,
    ConfiguringRoutes,
    #[serde(other)]
    Unknown,
}

impl ConnectPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Resolving => "resolving",
            Self::Handshaking => "handshaking",
            Self::ConfiguringRoutes => "configuring routes",
            Self::Unknown => "working",
        }
    }
}

/// `Error` means the daemon tried to apply the blocking policy and failed; nothing is enforced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KillSwitchState {
    Off,
    Armed,
    Error {
        message: String,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub allow_lan: bool,
    pub block_ipv6: bool,
    pub auto_reconnect: bool,
}

/// Partial update for [`Settings`]; absent fields are left unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_lan: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_ipv6: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_reconnect: Option<bool>,
}

impl SettingsPatch {
    pub fn is_empty(&self) -> bool {
        self.allow_lan.is_none() && self.block_ipv6.is_none() && self.auto_reconnect.is_none()
    }

    pub fn apply(&self, settings: &mut Settings) {
        if let Some(v) = self.allow_lan {
            settings.allow_lan = v;
        }
        if let Some(v) = self.block_ipv6 {
            settings.block_ipv6 = v;
        }
        if let Some(v) = self.auto_reconnect {
            settings.auto_reconnect = v;
        }
    }

    /// Combines two patches; fields set in `later` win.
    pub fn merge(self, later: Self) -> Self {
        Self {
            allow_lan: later.allow_lan.or(self.allow_lan),
            block_ipv6: later.block_ipv6.or(self.block_ipv6),
            auto_reconnect: later.auto_reconnect.or(self.auto_reconnect),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    P2p,
    Streaming,
    Multihop,
    #[serde(other)]
    Unknown,
}

impl Feature {
    pub fn label(self) -> &'static str {
        match self {
            Self::P2p => "p2p",
            Self::Streaming => "streaming",
            Self::Multihop => "multihop",
            Self::Unknown => "?",
        }
    }
}

/// A connectable server. Fields a daemon cannot know are `None` and render as unknown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Server {
    pub id: ServerId,
    pub name: String,
    /// ISO 3166-1 alpha-2, upper case.
    pub country_code: String,
    pub country: String,
    pub city: String,
    #[serde(default)]
    pub lat: Option<f64>,
    #[serde(default)]
    pub lon: Option<f64>,
    #[serde(default)]
    pub load_pct: Option<u8>,
    #[serde(default)]
    pub latency_ms: Option<u32>,
    #[serde(default)]
    pub features: Vec<Feature>,
    /// Present when the server is an imported profile; equal to `id`.
    #[serde(default)]
    pub profile_id: Option<ServerId>,
    /// The tunnel endpoint address. Display only.
    #[serde(default)]
    pub entry_ip: Option<IpAddr>,
    #[serde(default)]
    pub imported_at_ms: Option<UnixMillis>,
}

/// An observed public address. Location fields are present only when the source knows them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpInfo {
    pub ip: IpAddr,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub lat: Option<f64>,
    #[serde(default)]
    pub lon: Option<f64>,
}

/// Cumulative counters for the current tunnel session. Emitted at 1 Hz while connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    #[serde(default)]
    pub last_handshake_ms: Option<UnixMillis>,
}
