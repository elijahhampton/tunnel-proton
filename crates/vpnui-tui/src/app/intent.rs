use vpnui_proto::{
    Command, PROTOCOL_VERSION, RequestId, ServerId, Settings, SettingsPatch, TunnelState,
    UnixMillis,
};

use super::{CLIENT_VERSION, Projection};

/// What the user (or the handshake) asked the daemon for. Kept until a daemon event confirms
/// it, the daemon rejects it, or it times out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    Hello,
    Subscribe,
    Connect(ServerId),
    QuickConnect,
    Disconnect,
    SetKillSwitch(bool),
    SetSetting(SettingKey, bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingKey {
    AllowLan,
    BlockIpv6,
    AutoReconnect,
}

impl SettingKey {
    pub fn get(self, settings: &Settings) -> bool {
        match self {
            Self::AllowLan => settings.allow_lan,
            Self::BlockIpv6 => settings.block_ipv6,
            Self::AutoReconnect => settings.auto_reconnect,
        }
    }

    fn patch(self, value: bool) -> SettingsPatch {
        let mut patch = SettingsPatch::default();
        match self {
            Self::AllowLan => patch.allow_lan = Some(value),
            Self::BlockIpv6 => patch.block_ipv6 = Some(value),
            Self::AutoReconnect => patch.auto_reconnect = Some(value),
        }
        patch
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::AllowLan => "allow LAN",
            Self::BlockIpv6 => "block IPv6",
            Self::AutoReconnect => "auto-reconnect",
        }
    }
}

/// At most one request per slot is in flight; a second press while one is pending is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    Handshake,
    Tunnel,
    KillSwitch,
    Setting(SettingKey),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    pub id: RequestId,
    pub intent: Intent,
    pub sent_at: UnixMillis,
    /// The daemon replied `ok`; confirmation still comes from an event.
    pub acked: bool,
}

impl Intent {
    pub fn slot(&self) -> Slot {
        match self {
            Self::Hello | Self::Subscribe => Slot::Handshake,
            Self::Connect(_) | Self::QuickConnect | Self::Disconnect => Slot::Tunnel,
            Self::SetKillSwitch(_) => Slot::KillSwitch,
            Self::SetSetting(key, _) => Slot::Setting(*key),
        }
    }

    pub fn command(&self) -> Command {
        match self {
            Self::Hello => Command::Hello {
                client_version: CLIENT_VERSION.to_owned(),
                protocol_version: PROTOCOL_VERSION,
            },
            Self::Subscribe => Command::Subscribe,
            Self::Connect(server_id) => Command::Connect {
                server_id: server_id.clone(),
            },
            Self::QuickConnect => Command::QuickConnect,
            Self::Disconnect => Command::Disconnect,
            Self::SetKillSwitch(armed) => Command::SetKillSwitch { armed: *armed },
            Self::SetSetting(key, value) => Command::SetSettings(key.patch(*value)),
        }
    }

    pub fn describe(&self, projection: Option<&Projection>) -> String {
        match self {
            Self::Hello => "hello".to_owned(),
            Self::Subscribe => "subscribe".to_owned(),
            Self::Connect(id) => {
                let name = projection.map_or_else(|| id.to_string(), |p| p.server_name(id));
                format!("connect to {name}")
            }
            Self::QuickConnect => "quick connect".to_owned(),
            Self::Disconnect => "disconnect".to_owned(),
            Self::SetKillSwitch(true) => "arm kill switch".to_owned(),
            Self::SetKillSwitch(false) => "disarm kill switch".to_owned(),
            Self::SetSetting(key, value) => {
                format!("{} {}", key.label(), if *value { "on" } else { "off" })
            }
        }
    }

    /// The daemon has started acting on a tunnel request once the tunnel reports it.
    pub fn confirmed_by_tunnel(&self, tunnel: &TunnelState) -> bool {
        match self {
            Self::Connect(id) => match tunnel {
                TunnelState::Connecting { server_id, .. }
                | TunnelState::Connected { server_id, .. } => server_id == id,
                TunnelState::Disconnected { .. }
                | TunnelState::Reconnecting { .. }
                | TunnelState::Disconnecting
                | TunnelState::Unknown => false,
            },
            Self::QuickConnect => matches!(
                tunnel,
                TunnelState::Connecting { .. } | TunnelState::Connected { .. }
            ),
            Self::Disconnect => matches!(
                tunnel,
                TunnelState::Disconnecting | TunnelState::Disconnected { .. }
            ),
            Self::Hello | Self::Subscribe | Self::SetKillSwitch(_) | Self::SetSetting(..) => false,
        }
    }

    /// Any `kill_switch_changed` settles a kill-switch request, including `Error`.
    pub fn confirmed_by_kill_switch(&self) -> bool {
        matches!(self, Self::SetKillSwitch(_))
    }

    pub fn confirmed_by_settings(&self, settings: &Settings) -> bool {
        match self {
            Self::SetSetting(key, value) => key.get(settings) == *value,
            Self::Hello
            | Self::Subscribe
            | Self::Connect(_)
            | Self::QuickConnect
            | Self::Disconnect
            | Self::SetKillSwitch(_) => false,
        }
    }

    pub fn is_handshake(&self) -> bool {
        self.slot() == Slot::Handshake
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setting_intents_send_partial_patches() {
        let cmd = Intent::SetSetting(SettingKey::BlockIpv6, false).command();
        assert_eq!(
            cmd,
            Command::SetSettings(SettingsPatch {
                allow_lan: None,
                block_ipv6: Some(false),
                auto_reconnect: None,
            })
        );
    }

    #[test]
    fn connect_is_not_confirmed_by_a_reconnecting_echo() {
        let id = ServerId::new("se-sto-001");
        let intent = Intent::Connect(id.clone());
        assert!(!intent.confirmed_by_tunnel(&TunnelState::Reconnecting {
            server_id: id.clone(),
            attempt: 1,
            retry_at_ms: None,
            reason: "x".into(),
        }));
        assert!(intent.confirmed_by_tunnel(&TunnelState::Connecting {
            server_id: id,
            phase: vpnui_proto::ConnectPhase::Resolving,
            started_at_ms: UnixMillis(0),
        }));
    }
}
