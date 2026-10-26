use vpnui_proto::{KillSwitchState, TunnelState};

use super::{AppState, DaemonLink};

/// What the user's traffic is doing right now, collapsed from tunnel, kill switch, and link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Posture {
    /// Tunnel is up; traffic is encrypted.
    Protected,
    /// Tunnel is not up and nothing is blocking; traffic leaves in the clear.
    Exposed,
    /// Tunnel is not up and the kill switch is blocking all traffic.
    Blocked,
    /// The daemon link is not live, so the current state cannot be known.
    Unknown,
}

impl Posture {
    pub const ALL: [Self; 4] = [Self::Protected, Self::Exposed, Self::Blocked, Self::Unknown];

    pub fn word(self) -> &'static str {
        match self {
            Self::Protected => "PROTECTED",
            Self::Exposed => "EXPOSED",
            Self::Blocked => "BLOCKED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

pub fn posture(state: &AppState) -> Posture {
    let Some(projection) = state.daemon.as_ref() else {
        return Posture::Unknown;
    };
    match state.link {
        DaemonLink::Connecting | DaemonLink::Lost { .. } => Posture::Unknown,
        DaemonLink::Live => classify(&projection.tunnel, &projection.kill_switch),
    }
}

/// Unrecognized tunnel states count as not connected; unrecognized kill-switch states count as
/// not blocking.
fn classify(tunnel: &TunnelState, kill_switch: &KillSwitchState) -> Posture {
    match tunnel {
        TunnelState::Connected { .. } => Posture::Protected,
        TunnelState::Disconnected { .. }
        | TunnelState::Connecting { .. }
        | TunnelState::Reconnecting { .. }
        | TunnelState::Disconnecting
        | TunnelState::Unknown => match kill_switch {
            KillSwitchState::Armed => Posture::Blocked,
            KillSwitchState::Off | KillSwitchState::Error { .. } | KillSwitchState::Unknown => {
                Posture::Exposed
            }
        },
    }
}

/// The kill switch's failure message when it is in `Error`, from current or stale data.
pub fn kill_switch_warning(state: &AppState) -> Option<&str> {
    match &state.daemon.as_ref()?.kill_switch {
        KillSwitchState::Error { message } => Some(message),
        KillSwitchState::Off | KillSwitchState::Armed | KillSwitchState::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use vpnui_proto::{ConnectPhase, ServerId, Settings, UnixMillis};

    use super::Posture::{Blocked, Exposed, Protected, Unknown};
    use super::*;
    use crate::app::Projection;
    use crate::theme::{ColorMode, Theme};

    fn tunnels() -> [TunnelState; 6] {
        let id = ServerId::new("ch-zrh-012");
        [
            TunnelState::Disconnected {
                last_error: Some("handshake timed out".into()),
            },
            TunnelState::Connecting {
                server_id: id.clone(),
                phase: ConnectPhase::Handshaking,
                started_at_ms: UnixMillis(1),
            },
            TunnelState::Connected {
                server_id: id.clone(),
                since_ms: UnixMillis(1),
                endpoint: "198.51.100.1:51820".into(),
                last_handshake_ms: None,
            },
            TunnelState::Reconnecting {
                server_id: id,
                attempt: 2,
                retry_at_ms: Some(UnixMillis(5)),
                reason: "peer stopped responding".into(),
            },
            TunnelState::Disconnecting,
            TunnelState::Unknown,
        ]
    }

    fn kill_switches() -> [KillSwitchState; 4] {
        [
            KillSwitchState::Off,
            KillSwitchState::Armed,
            KillSwitchState::Error {
                message: "pf failed".into(),
            },
            KillSwitchState::Unknown,
        ]
    }

    fn links() -> [DaemonLink; 3] {
        [
            DaemonLink::Connecting,
            DaemonLink::Live,
            DaemonLink::Lost {
                since: UnixMillis(1),
                next_retry_at: UnixMillis(2),
            },
        ]
    }

    /// Expected posture with a live link. Rows follow `tunnels()`, columns `kill_switches()`:
    /// Off, Armed, Error, Unknown.
    const LIVE_TABLE: [[Posture; 4]; 6] = [
        [Exposed, Blocked, Exposed, Exposed],         // Disconnected
        [Exposed, Blocked, Exposed, Exposed],         // Connecting
        [Protected, Protected, Protected, Protected], // Connected
        [Exposed, Blocked, Exposed, Exposed],         // Reconnecting
        [Exposed, Blocked, Exposed, Exposed],         // Disconnecting
        [Exposed, Blocked, Exposed, Exposed],         // Unknown
    ];

    fn state(link: DaemonLink, tunnel: TunnelState, kill_switch: KillSwitchState) -> AppState {
        let mut state = AppState::new(Theme::new(ColorMode::None, false), UnixMillis(10), 80, 24);
        state.link = link;
        state.daemon = Some(Projection {
            tunnel,
            kill_switch,
            settings: Settings {
                allow_lan: false,
                block_ipv6: true,
                auto_reconnect: true,
            },
            servers: Vec::new(),
            recents: Vec::new(),
            public_ip: None,
            stats: None,
            profiles_count: 0,
        });
        state
    }

    #[test]
    fn full_cross_product() {
        let mut checked = 0;
        for link in links() {
            for (t, tunnel) in tunnels().into_iter().enumerate() {
                for (k, kill_switch) in kill_switches().into_iter().enumerate() {
                    let expected = match link {
                        DaemonLink::Live => LIVE_TABLE[t][k],
                        DaemonLink::Connecting | DaemonLink::Lost { .. } => Unknown,
                    };
                    let s = state(link, tunnel.clone(), kill_switch.clone());
                    assert_eq!(
                        posture(&s),
                        expected,
                        "link={link:?} tunnel={tunnel:?} kill_switch={kill_switch:?}"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 3 * 6 * 4);
    }

    #[test]
    fn no_projection_is_unknown_even_if_live() {
        for link in links() {
            let mut s = state(link, tunnels()[2].clone(), KillSwitchState::Armed);
            s.daemon = None;
            assert_eq!(posture(&s), Unknown);
        }
    }

    #[test]
    fn kill_switch_error_raises_warning_in_every_posture() {
        for link in links() {
            for tunnel in tunnels() {
                let s = state(
                    link,
                    tunnel,
                    KillSwitchState::Error {
                        message: "pf failed".into(),
                    },
                );
                assert_eq!(kill_switch_warning(&s), Some("pf failed"));
            }
        }
        let s = state(
            DaemonLink::Live,
            tunnels()[0].clone(),
            KillSwitchState::Armed,
        );
        assert_eq!(kill_switch_warning(&s), None);
    }

    #[test]
    fn words_are_distinct() {
        let mut words: Vec<_> = Posture::ALL.iter().map(|p| p.word()).collect();
        words.dedup();
        assert_eq!(words.len(), 4);
    }
}
