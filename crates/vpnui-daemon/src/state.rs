//! The persisted daemon state, including the write-ahead journal of undo actions. Contains no
//! key material.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use vpnui_proto::Settings;

use crate::net::net::{IfName, IpNet};
use crate::platform::PfToken;

pub const FORMAT: u32 = 1;
pub const MAX_RECENTS: usize = 5;

/// How to undo one privileged mutation. This is appended before the mutation and 
/// removed after the undo succeeds; whatever remains after a crash is undone by recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Undo {
    /// Remove a pf pass rule for UDP to this endpoint.
    EndpointException {
        endpoint: SocketAddr,
    },
    /// Remove the pf pass rule for this tunnel interface.
    TunnelException {
        ifname: IfName,
    },
    /// Stop wireguard-go. `ifname` is unknown until the child reports it.
    WireGuard {
        ifname: Option<IfName>,
    },
    HostRoute {
        dest: IpAddr,
    },
    NetRoute {
        net: IpNet,
        ifname: IfName,
    },
    Dns,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub seq: u64,
    pub session: u64,
    pub undo: Undo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(default = "format")]
    pub format: u32,
    #[serde(default)]
    pub armed: bool,
    #[serde(default = "default_settings")]
    pub settings: Settings,
    /// Profile ids, most recent first.
    #[serde(default)]
    pub recents: Vec<String>,
    #[serde(default)]
    pub last_profile: Option<String>,
    #[serde(default)]
    pub pf_token: Option<PfToken>,
    /// pf was disabled before this daemon enabled it.
    #[serde(default)]
    pub pf_enabled_by_us: bool,
    #[serde(default)]
    pub journal: Vec<JournalEntry>,
    #[serde(default)]
    pub next_seq: u64,
}

fn format() -> u32 {
    FORMAT
}

pub fn default_settings() -> Settings {
    Settings {
        allow_lan: false,
        block_ipv6: true,
        auto_reconnect: true,
    }
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            format: FORMAT,
            armed: false,
            settings: default_settings(),
            recents: Vec::new(),
            last_profile: None,
            pf_token: None,
            pf_enabled_by_us: false,
            journal: Vec::new(),
            next_seq: 0,
        }
    }
}

impl PersistedState {
    /// Used when the state file exists but cannot be read: assume the kill switch was armed.
    pub fn fail_closed() -> Self {
        Self {
            armed: true,
            ..Self::default()
        }
    }

    pub fn push_recent(&mut self, id: &str) {
        self.recents.retain(|r| r != id);
        self.recents.insert(0, id.to_owned());
        self.recents.truncate(MAX_RECENTS);
        self.last_profile = Some(id.to_owned());
    }
}
