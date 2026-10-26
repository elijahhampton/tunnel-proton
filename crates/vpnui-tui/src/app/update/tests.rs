use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use vpnui_proto::{
    Command, ErrorCode, Event as DaemonEvent, KillSwitchState, PROTOCOL_VERSION, ProtocolVersion,
    Response, ServerId, Settings, Stats, TunnelState, UnixMillis,
};

use super::update;
use crate::app::fixtures::*;
use crate::app::{
    AppState, ConfirmKind, DaemonLink, EVENT_LOG_CAPACITY, Effect, Event, Intent, LinkEvent,
    LogEntry, Modal, Posture, Severity, Slot, View, posture,
};
use crate::browser::NodeKey;

fn commands(effects: &[Effect]) -> Vec<Command> {
    sent(effects).into_iter().map(|r| r.cmd).collect()
}

fn toast(state: &AppState) -> String {
    state
        .toast
        .as_ref()
        .map(|t| t.text.clone())
        .unwrap_or_default()
}

fn tunnel_changed(tunnel: TunnelState) -> Event {
    daemon(DaemonEvent::TunnelChanged { tunnel })
}

fn kill_switch_changed(kill_switch: KillSwitchState) -> Event {
    daemon(DaemonEvent::KillSwitchChanged { kill_switch })
}

fn tick(state: &mut AppState, secs: u64) -> Vec<Effect> {
    update(state, Event::Tick(at(secs)))
}

// --- handshake and link ---------------------------------------------------------------------

#[test]
fn handshake_goes_hello_subscribe_snapshot_live() {
    let mut state = AppState::new(theme(), T0, 120, 40);
    assert_eq!(state.link, DaemonLink::Connecting);
    assert_eq!(posture(&state), Posture::Unknown);

    let effects = update(&mut state, Event::Link(LinkEvent::Connected));
    let hello = sent(&effects);
    assert!(
        matches!(hello[0].cmd, Command::Hello { protocol_version, .. } if protocol_version == PROTOCOL_VERSION)
    );

    let effects = update(
        &mut state,
        reply(Response::ok(hello[0].id).with_protocol_version(PROTOCOL_VERSION)),
    );
    let subscribe = sent(&effects);
    assert_eq!(subscribe[0].cmd, Command::Subscribe);
    assert_ne!(subscribe[0].id, hello[0].id);
    assert_eq!(state.link, DaemonLink::Connecting);

    update(&mut state, reply(Response::ok(subscribe[0].id)));
    update(
        &mut state,
        daemon(DaemonEvent::Snapshot(Box::new(snapshot(
            connected(),
            KillSwitchState::Armed,
        )))),
    );
    assert_eq!(state.link, DaemonLink::Live);
    assert_eq!(posture(&state), Posture::Protected);
    assert!(state.in_flight.is_empty());
}

#[test]
fn events_before_the_snapshot_are_ignored() {
    let mut state = AppState::new(theme(), T0, 120, 40);
    update(&mut state, Event::Link(LinkEvent::Connected));
    update(&mut state, tunnel_changed(connected()));
    assert!(state.daemon.is_none());
    assert_eq!(posture(&state), Posture::Unknown);
}

#[test]
fn hello_version_mismatch_blocks_with_both_versions() {
    let mut state = AppState::new(theme(), T0, 120, 40);
    let hello = sent(&update(&mut state, Event::Link(LinkEvent::Connected)));
    let effects = update(
        &mut state,
        reply(
            Response::err(hello[0].id, ErrorCode::VersionMismatch, "nope")
                .with_protocol_version(ProtocolVersion(2)),
        ),
    );
    assert!(
        sent(&effects).is_empty(),
        "must not subscribe after a mismatch"
    );
    let mismatch = state.version_mismatch.expect("mismatch recorded");
    assert_eq!(mismatch.client, PROTOCOL_VERSION);
    assert_eq!(mismatch.daemon, Some(ProtocolVersion(2)));

    assert!(update(&mut state, key('c')).is_empty());
    assert_eq!(update(&mut state, key('q')), vec![Effect::Quit]);
}

#[test]
fn snapshot_version_mismatch_is_also_caught() {
    let mut s = snapshot(connected(), KillSwitchState::Off);
    s.protocol_version = ProtocolVersion(9);
    let state = live_with(s, 120, 40);
    assert!(state.version_mismatch.is_some());
    assert_ne!(state.link, DaemonLink::Live);
}

#[test]
fn losing_the_link_keeps_stale_data_and_reconnect_discards_it() {
    let mut state = live(connected(), KillSwitchState::Armed);
    tick(&mut state, 5);
    update(
        &mut state,
        Event::Link(LinkEvent::Down {
            reason: "daemon closed the connection".into(),
            retry_in: Duration::from_secs(1),
        }),
    );
    assert_eq!(posture(&state), Posture::Unknown);
    assert!(state.is_stale());
    assert!(matches!(state.link, DaemonLink::Lost { since, .. } if since == at(5)));
    assert!(
        state.daemon.is_some(),
        "last-known data is kept for display"
    );

    // Actions are refused with a reason while the link is down.
    assert!(sent(&update(&mut state, key('d'))).is_empty());
    assert!(toast(&state).contains("Daemon unreachable"));

    // A failed retry keeps the original loss time.
    tick(&mut state, 8);
    update(
        &mut state,
        Event::Link(LinkEvent::Down {
            reason: "refused".into(),
            retry_in: Duration::from_secs(2),
        }),
    );
    assert!(matches!(state.link, DaemonLink::Lost { since, .. } if since == at(5)));

    let effects = update(&mut state, Event::Link(LinkEvent::Connected));
    assert!(
        state.daemon.is_none(),
        "projection is discarded on reconnect"
    );
    assert_eq!(state.link, DaemonLink::Connecting);
    assert!(matches!(commands(&effects)[..], [Command::Hello { .. }]));
}

#[test]
fn link_reset_drops_in_flight_requests_with_a_toast() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    assert_eq!(sent(&update(&mut state, key('c'))).len(), 1);
    update(
        &mut state,
        Event::Link(LinkEvent::Down {
            reason: "x".into(),
            retry_in: Duration::from_secs(1),
        }),
    );
    assert!(state.in_flight.is_empty());
    assert!(
        state
            .log
            .iter()
            .any(|e| e.text.contains("1 pending action"))
    );
}

// --- dedupe, confirmation, timeouts ---------------------------------------------------------

#[test]
fn double_press_sends_one_command() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    let first = update(&mut state, key('c'));
    assert_eq!(commands(&first), vec![Command::QuickConnect]);

    let second = update(&mut state, key('c'));
    assert!(sent(&second).is_empty());
    assert!(
        toast(&state).contains("Still waiting"),
        "toast: {}",
        toast(&state)
    );

    // Any tunnel action shares the slot.
    assert!(sent(&update(&mut state, key('r'))).is_empty());
}

#[test]
fn pending_clears_only_on_the_confirming_event() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    let request = sent(&update(&mut state, key('c'))).remove(0);

    update(&mut state, reply(Response::ok(request.id)));
    let pending = state.pending(Slot::Tunnel).expect("still pending after ok");
    assert!(pending.acked);

    // An unrelated event does not confirm.
    update(&mut state, kill_switch_changed(KillSwitchState::Off));
    assert!(state.pending(Slot::Tunnel).is_some());

    update(&mut state, tunnel_changed(connecting()));
    assert!(state.pending(Slot::Tunnel).is_none());
    assert!(sent(&update(&mut state, key('c'))).is_empty());
    assert!(toast(&state).contains("Already connecting"));
}

#[test]
fn protection_state_is_never_updated_optimistically() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    let effects = update(&mut state, key('s'));
    assert_eq!(
        commands(&effects),
        vec![Command::SetKillSwitch { armed: true }]
    );
    assert_eq!(
        state.daemon.as_ref().map(|p| &p.kill_switch),
        Some(&KillSwitchState::Off)
    );
    assert_eq!(posture(&state), Posture::Exposed);

    update(&mut state, kill_switch_changed(KillSwitchState::Armed));
    assert_eq!(posture(&state), Posture::Blocked);
    assert!(state.pending(Slot::KillSwitch).is_none());
}

#[test]
fn unconfirmed_request_times_out_after_ten_seconds() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    update(&mut state, key('s'));
    tick(&mut state, 9);
    assert!(state.pending(Slot::KillSwitch).is_some());
    let effects = tick(&mut state, 10);
    assert!(state.pending(Slot::KillSwitch).is_none());
    assert!(toast(&state).contains("No confirmation"));
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::Log(Severity::Error, _)))
    );
    assert_eq!(
        sent(&update(&mut state, key('s'))).len(),
        1,
        "slot is free again"
    );
}

#[test]
fn rejected_request_raises_an_error_toast() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    let request = sent(&update(&mut state, key('c'))).remove(0);
    update(
        &mut state,
        reply(Response::err(request.id, ErrorCode::InvalidState, "busy")),
    );
    assert!(state.pending(Slot::Tunnel).is_none());
    assert_eq!(
        toast(&state),
        "Daemon rejected quick connect: That action is not possible right now (invalid_state)"
    );
    assert!(
        state
            .log
            .iter()
            .any(|e| e.text == "daemon detail (invalid_state): busy")
    );
}

#[test]
fn known_error_codes_get_a_sentence_and_the_code_verbatim() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    let request = sent(&update(&mut state, key('c'))).remove(0);
    update(
        &mut state,
        reply(Response::err(
            request.id,
            ErrorCode::BinaryUntrusted,
            "wireguard-go hash mismatch",
        )),
    );
    assert!(toast(&state).ends_with(
        "wireguard-go is not installed in a trusted location; run sudo vpnuid install \
         (binary_untrusted)"
    ));
}

#[test]
fn refusal_without_a_request_is_surfaced() {
    for code in [ErrorCode::Unauthorized, ErrorCode::Busy] {
        let mut state = AppState::new(theme(), T0, 120, 40);
        update(&mut state, Event::Link(LinkEvent::Connected));
        let effects = update(
            &mut state,
            reply(Response::err(
                vpnui_proto::RequestId(0),
                code,
                "uid 502 is not allowed",
            )),
        );
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::Log(Severity::Error, _)))
        );
        assert!(toast(&state).starts_with("Daemon refused the connection"));
        assert!(toast(&state).contains(code.as_str()));
        assert!(
            state
                .log
                .iter()
                .any(|e| e.text.contains("uid 502 is not allowed"))
        );
    }

    let mut state = live(disconnected(), KillSwitchState::Off);
    let effects = update(
        &mut state,
        reply(Response::err(
            vpnui_proto::RequestId(99),
            ErrorCode::Internal,
            "x",
        )),
    );
    assert!(state.toast.is_none(), "other strays are only logged");
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::Log(Severity::Info, _)))
    );
}

#[test]
fn coded_last_error_is_expanded_in_the_failure_toast() {
    let mut state = live(connecting(), KillSwitchState::Armed);
    update(
        &mut state,
        tunnel_changed(TunnelState::Disconnected {
            last_error: Some("handshake_timeout: no handshake within 15s".into()),
        }),
    );
    assert_eq!(
        toast(&state),
        "Connection failed: The server did not respond to the handshake (handshake_timeout): \
         no handshake within 15s. Kill switch is blocking traffic"
    );
}

#[test]
fn profiles_count_follows_servers_updated() {
    let mut state = live_with(
        profiles_snapshot(disconnected(), KillSwitchState::Off, Vec::new(), Vec::new()),
        120,
        40,
    );
    assert_eq!(state.daemon.as_ref().map(|p| p.profiles_count), Some(0));
    update(
        &mut state,
        daemon(DaemonEvent::ServersUpdated {
            servers: colombia_profiles(),
        }),
    );
    assert_eq!(state.daemon.as_ref().map(|p| p.profiles_count), Some(2));
}

#[test]
fn quick_connect_target_mirrors_the_daemon_rule() {
    let target = |recents: Vec<ServerId>| {
        let state = live_with(
            profiles_snapshot(
                disconnected(),
                KillSwitchState::Off,
                colombia_profiles(),
                recents,
            ),
            120,
            40,
        );
        state
            .daemon
            .as_ref()
            .and_then(|p| p.quick_connect_target())
            .map(|s| s.name.clone())
    };
    // No recents: the most recently imported profile (CO#7, imported a day ago).
    assert_eq!(target(Vec::new()), Some("CO#7".to_owned()));
    // The first recent that still exists wins.
    assert_eq!(
        target(vec![ServerId::new("gone-000000"), co4()]),
        Some("CO#4".to_owned())
    );
    // Catalogs that are not profiles (the mock) leave the choice to the daemon.
    let mock = live(disconnected(), KillSwitchState::Off);
    assert!(
        mock.daemon
            .as_ref()
            .and_then(|p| p.quick_connect_target())
            .is_none()
    );
}

#[test]
fn sort_key_explains_when_only_name_is_available() {
    let mut state = live_with(
        profiles_snapshot(
            disconnected(),
            KillSwitchState::Off,
            colombia_profiles(),
            Vec::new(),
        ),
        120,
        40,
    );
    update(&mut state, key('2'));
    update(&mut state, key('o'));
    assert_eq!(state.ui.browser.sort, crate::browser::SortKey::Name);
    assert!(toast(&state).contains("no load or latency data"));

    let mut mock = live(disconnected(), KillSwitchState::Off);
    update(&mut mock, key('2'));
    update(&mut mock, key('o'));
    assert_eq!(mock.ui.browser.sort, crate::browser::SortKey::Load);
}

#[test]
fn ip_without_coordinates_is_not_used_as_origin() {
    let mut state = live_with(
        profiles_snapshot(
            disconnected(),
            KillSwitchState::Off,
            colombia_profiles(),
            Vec::new(),
        ),
        120,
        40,
    );
    update(
        &mut state,
        daemon(DaemonEvent::PublicIpChanged {
            public_ip: Some(vpnui_proto::IpInfo {
                ip: std::net::IpAddr::from([203, 0, 113, 9]),
                city: String::new(),
                country: String::new(),
                lat: None,
                lon: None,
            }),
        }),
    );
    assert!(state.origin.is_none());
}

#[test]
fn send_failure_clears_pending() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    let request = sent(&update(&mut state, key('c'))).remove(0);
    update(&mut state, Event::Link(LinkEvent::SendFailed(request.id)));
    assert!(state.pending(Slot::Tunnel).is_none());
    assert!(toast(&state).contains("Could not send"));
}

// --- confirm modals -------------------------------------------------------------------------

fn choose_label(state: &mut AppState, label: &str) -> Vec<Effect> {
    let Some(Modal::Confirm { kind, .. }) = &state.ui.modal else {
        panic!("expected a confirm modal, got {:?}", state.ui.modal);
    };
    let index = kind
        .choices()
        .iter()
        .position(|c| c.label() == label)
        .expect("choice exists");
    let count = kind.choices().len();
    // Default selection is Cancel (the last choice); walk forward to the target.
    for _ in 0..(index + 1) % count {
        update(state, code(KeyCode::Down));
    }
    update(state, code(KeyCode::Enter))
}

#[test]
fn disconnect_while_armed_asks_first() {
    let mut state = live(connected(), KillSwitchState::Armed);
    let effects = update(&mut state, key('d'));
    assert!(sent(&effects).is_empty());
    let Some(Modal::Confirm { kind, selected }) = &state.ui.modal else {
        panic!("no modal");
    };
    assert_eq!(*kind, ConfirmKind::DisconnectWhileArmed);
    assert_eq!(kind.choices()[*selected].label(), "Cancel");
    assert!(
        kind.message()
            .contains("Kill switch is armed. Disconnecting will block all traffic.")
    );

    // Enter on the default does nothing.
    assert!(sent(&update(&mut state, code(KeyCode::Enter))).is_empty());
    assert!(state.ui.modal.is_none());

    update(&mut state, key('d'));
    let effects = choose_label(&mut state, "Disconnect, stay blocked");
    assert_eq!(commands(&effects), vec![Command::Disconnect]);
}

#[test]
fn disconnect_and_disarm_sends_both() {
    let mut state = live(connected(), KillSwitchState::Armed);
    update(&mut state, key('d'));
    let effects = choose_label(&mut state, "Disconnect and disarm");
    assert_eq!(
        commands(&effects),
        vec![Command::Disconnect, Command::SetKillSwitch { armed: false }]
    );
}

#[test]
fn escape_closes_the_modal_without_sending() {
    let mut state = live(connected(), KillSwitchState::Armed);
    update(&mut state, key('d'));
    assert!(sent(&update(&mut state, code(KeyCode::Esc))).is_empty());
    assert!(state.ui.modal.is_none());
}

#[test]
fn disconnect_without_kill_switch_is_immediate() {
    let mut state = live(connected(), KillSwitchState::Off);
    assert_eq!(
        commands(&update(&mut state, key('d'))),
        vec![Command::Disconnect]
    );
    assert!(state.ui.modal.is_none());
}

#[test]
fn disarm_requires_confirmation_but_arming_does_not() {
    let mut state = live(disconnected(), KillSwitchState::Armed);
    assert!(sent(&update(&mut state, key('s'))).is_empty());
    let effects = choose_label(&mut state, "Disarm");
    assert_eq!(
        commands(&effects),
        vec![Command::SetKillSwitch { armed: false }]
    );

    let mut state = live(disconnected(), KillSwitchState::Off);
    assert_eq!(
        commands(&update(&mut state, key('s'))),
        vec![Command::SetKillSwitch { armed: true }]
    );
}

#[test]
fn kill_switch_error_offers_retry_or_off() {
    let mut state = live(
        connected(),
        KillSwitchState::Error {
            message: "pf failed".into(),
        },
    );
    update(&mut state, key('s'));
    let effects = choose_label(&mut state, "Retry arming");
    assert_eq!(
        commands(&effects),
        vec![Command::SetKillSwitch { armed: true }]
    );

    // Re-arming that fails again settles the request and reports the error.
    update(
        &mut state,
        kill_switch_changed(KillSwitchState::Error {
            message: "pf failed".into(),
        }),
    );
    assert!(state.pending(Slot::KillSwitch).is_none());
    assert!(toast(&state).contains("Kill switch failed"));
}

#[test]
fn settings_that_lower_protection_need_confirmation() {
    let mut state = live(connected(), KillSwitchState::Armed);
    update(&mut state, key('4'));
    assert_eq!(state.ui.view, View::Settings);

    // Allow LAN: off -> on lowers protection.
    update(&mut state, code(KeyCode::Down));
    assert!(sent(&update(&mut state, code(KeyCode::Enter))).is_empty());
    let effects = choose_label(&mut state, "Allow LAN");
    let patch = commands(&effects);
    assert!(
        matches!(&patch[..], [Command::SetSettings(p)] if p.allow_lan == Some(true) && p.block_ipv6.is_none())
    );

    // Block IPv6: on -> off lowers protection.
    update(&mut state, code(KeyCode::Down));
    assert!(sent(&update(&mut state, code(KeyCode::Enter))).is_empty());
    assert!(matches!(
        &state.ui.modal,
        Some(Modal::Confirm {
            kind: ConfirmKind::DisableBlockIpv6,
            ..
        })
    ));
    update(&mut state, code(KeyCode::Esc));

    // Auto-reconnect toggles directly.
    update(&mut state, code(KeyCode::Down));
    let effects = update(&mut state, code(KeyCode::Enter));
    assert!(
        matches!(&commands(&effects)[..], [Command::SetSettings(p)] if p.auto_reconnect == Some(false))
    );
}

#[test]
fn raising_protection_never_asks() {
    let mut s = snapshot(disconnected(), KillSwitchState::Off);
    s.settings = Settings {
        allow_lan: true,
        block_ipv6: false,
        auto_reconnect: false,
    };
    let mut state = live_with(s, 120, 40);
    update(&mut state, key('4'));
    for _ in 0..3 {
        update(&mut state, code(KeyCode::Down));
        let effects = update(&mut state, code(KeyCode::Enter));
        assert_eq!(sent(&effects).len(), 1);
        assert!(state.ui.modal.is_none());
    }
}

#[test]
fn settings_pending_clears_when_value_matches() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    update(&mut state, key('4'));
    update(&mut state, code(KeyCode::Up));
    update(&mut state, code(KeyCode::End));
    update(&mut state, code(KeyCode::Enter));
    assert!(
        state
            .pending(Slot::Setting(crate::app::SettingKey::AutoReconnect))
            .is_some()
    );

    update(
        &mut state,
        daemon(DaemonEvent::SettingsChanged {
            settings: settings(),
        }),
    );
    assert!(
        state
            .pending(Slot::Setting(crate::app::SettingKey::AutoReconnect))
            .is_some()
    );

    let mut changed = settings();
    changed.auto_reconnect = false;
    update(
        &mut state,
        daemon(DaemonEvent::SettingsChanged { settings: changed }),
    );
    assert!(
        state
            .pending(Slot::Setting(crate::app::SettingKey::AutoReconnect))
            .is_none()
    );
}

// --- tunnel actions -------------------------------------------------------------------------

#[test]
fn escape_cancels_a_connect_without_a_modal_even_when_armed() {
    let mut state = live(connecting(), KillSwitchState::Armed);
    assert_eq!(posture(&state), Posture::Blocked);
    let effects = update(&mut state, code(KeyCode::Esc));
    assert_eq!(commands(&effects), vec![Command::Disconnect]);
    assert!(state.ui.modal.is_none());
}

#[test]
fn escape_clears_search_before_cancelling() {
    let mut state = live(connecting(), KillSwitchState::Off);
    update(&mut state, key('/'));
    update(&mut state, key('z'));
    update(&mut state, code(KeyCode::Enter));
    assert!(state.ui.browser.searching());
    assert!(sent(&update(&mut state, code(KeyCode::Esc))).is_empty());
    assert!(!state.ui.browser.searching());
    assert_eq!(
        commands(&update(&mut state, code(KeyCode::Esc))),
        vec![Command::Disconnect]
    );
}

#[test]
fn reconnect_now_targets_the_reconnecting_server() {
    let mut state = live(reconnecting(), KillSwitchState::Off);
    assert_eq!(
        commands(&update(&mut state, key('r'))),
        vec![Command::Connect {
            server_id: zurich()
        }]
    );
}

#[test]
fn enter_on_a_server_connects_and_on_a_group_toggles() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    update(&mut state, key('2'));
    // Countries sort by name: Brazil, Japan, Sweden, Switzerland.
    update(&mut state, code(KeyCode::End));
    assert_eq!(
        state.ui.browser.selected,
        Some(NodeKey::Country("CH".into()))
    );
    assert!(sent(&update(&mut state, code(KeyCode::Enter))).is_empty());
    update(&mut state, key('j'));
    update(&mut state, key('l'));
    update(&mut state, key('l'));
    assert_eq!(
        state.ui.browser.selected,
        Some(NodeKey::Server(ServerId::new("ch-gva-001")))
    );
    assert_eq!(
        commands(&update(&mut state, code(KeyCode::Enter))),
        vec![Command::Connect {
            server_id: ServerId::new("ch-gva-001")
        }]
    );
}

#[test]
fn connecting_to_the_current_server_is_refused_with_a_reason() {
    let mut state = live(connected(), KillSwitchState::Off);
    update(&mut state, key('1'));
    assert!(sent(&update(&mut state, code(KeyCode::Enter))).is_empty());
    assert!(toast(&state).contains("Already connected to Zürich #12"));
    update(&mut state, key('j'));
    assert_eq!(
        commands(&update(&mut state, code(KeyCode::Enter))),
        vec![Command::Connect {
            server_id: ServerId::new("se-sto-002")
        }]
    );
}

#[test]
fn quick_connect_explains_why_it_is_unavailable() {
    let mut state = live(connected(), KillSwitchState::Off);
    assert!(sent(&update(&mut state, key('c'))).is_empty());
    assert!(toast(&state).contains("Already connected"));
}

// --- tunnel events --------------------------------------------------------------------------

#[test]
fn failed_connect_with_kill_switch_reports_blocked() {
    let mut state = live(connecting(), KillSwitchState::Armed);
    update(
        &mut state,
        tunnel_changed(TunnelState::Disconnected {
            last_error: Some("handshake timed out".into()),
        }),
    );
    assert_eq!(posture(&state), Posture::Blocked);
    assert!(toast(&state).contains("Kill switch is blocking traffic"));
}

#[test]
fn unknown_tunnel_state_is_skipped() {
    let mut state = live(connected(), KillSwitchState::Off);
    let effects = update(&mut state, tunnel_changed(TunnelState::Unknown));
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::Log(Severity::Warn, _)))
    );
    assert_eq!(posture(&state), Posture::Protected);
    let effects = update(&mut state, daemon(DaemonEvent::Unknown));
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::Log(Severity::Warn, _)))
    );
}

#[test]
fn connected_event_moves_server_to_front_of_recents() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    let tokyo = ServerId::new("jp-tyo-007");
    update(
        &mut state,
        tunnel_changed(TunnelState::Connected {
            server_id: tokyo.clone(),
            since_ms: at(1),
            endpoint: "198.51.100.40:51820".into(),
            last_handshake_ms: None,
        }),
    );
    let recents = state
        .daemon
        .as_ref()
        .map(|p| p.recents.clone())
        .unwrap_or_default();
    assert_eq!(recents.first(), Some(&tokyo));
    assert_eq!(recents.iter().filter(|id| **id == tokyo).count(), 1);
}

#[test]
fn stats_produce_per_second_rates() {
    let mut state = live(connected(), KillSwitchState::Off);
    for (rx, tx) in [(1_000, 100), (3_000, 150), (6_000, 450)] {
        update(
            &mut state,
            daemon(DaemonEvent::Stats(Stats {
                rx_bytes: rx,
                tx_bytes: tx,
                last_handshake_ms: None,
            })),
        );
    }
    assert_eq!(
        state.traffic.rx.iter().copied().collect::<Vec<_>>(),
        [2_000, 3_000]
    );
    assert_eq!(state.traffic.current(), Some((3_000, 300)));
}

#[test]
fn public_ip_while_down_becomes_origin() {
    let mut state = live(connected(), KillSwitchState::Off);
    assert!(
        state.origin.is_none(),
        "connected snapshot reveals no origin"
    );
    update(&mut state, tunnel_changed(disconnected()));
    update(
        &mut state,
        daemon(DaemonEvent::PublicIpChanged {
            public_ip: Some(home_ip()),
        }),
    );
    assert_eq!(
        state.origin.as_ref().map(|o| o.city.as_str()),
        Some("New York")
    );
}

// --- ui -------------------------------------------------------------------------------------

#[test]
fn toasts_expire_after_five_seconds_but_stay_in_the_log() {
    let mut state = live(connected(), KillSwitchState::Off);
    update(&mut state, key('c'));
    let text = toast(&state);
    assert!(!text.is_empty());
    tick(&mut state, 4);
    assert!(state.toast.is_some());
    tick(&mut state, 5);
    assert!(state.toast.is_none());
    assert!(state.log.iter().any(|e| e.text == text));
}

#[test]
fn event_log_is_bounded_newest_first() {
    let mut state = AppState::new(theme(), T0, 120, 40);
    for i in 0..EVENT_LOG_CAPACITY + 50 {
        state.log.push(LogEntry {
            at: UnixMillis(i as u64),
            severity: Severity::Info,
            text: i.to_string(),
        });
    }
    assert_eq!(state.log.len(), EVENT_LOG_CAPACITY);
    let newest = (EVENT_LOG_CAPACITY + 49).to_string();
    assert_eq!(
        state.log.iter().next().map(|e| e.text.as_str()),
        Some(newest.as_str())
    );
}

#[test]
fn servers_updated_keeps_selection_on_the_same_server() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    update(&mut state, key('2'));
    update(&mut state, key('o')); // sort by load
    update(&mut state, key('/'));
    for c in "zür".chars() {
        update(&mut state, key(c));
    }
    update(&mut state, code(KeyCode::Enter));
    // Rows: CH, Zürich, #12 (41%), #3 (83%).
    update(&mut state, code(KeyCode::End));
    let target = NodeKey::Server(ServerId::new("ch-zrh-003"));
    assert_eq!(state.ui.browser.selected, Some(target.clone()));

    let mut servers = servers();
    for s in &mut servers {
        if s.id.as_str() == "ch-zrh-003" {
            s.load_pct = Some(5);
        }
    }
    update(&mut state, daemon(DaemonEvent::ServersUpdated { servers }));
    assert_eq!(state.ui.browser.selected, Some(target));
}

#[test]
fn view_switching_by_number_tab_and_mouse() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    update(&mut state, key('3'));
    assert_eq!(state.ui.view, View::Stats);
    update(&mut state, code(KeyCode::Tab));
    assert_eq!(state.ui.view, View::Settings);
    update(&mut state, code(KeyCode::BackTab));
    update(&mut state, code(KeyCode::BackTab));
    assert_eq!(state.ui.view, View::Servers);

    let tabs = state.layout().tab_hits();
    let (_, home) = tabs[0];
    update(
        &mut state,
        Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: home.x + 1,
            row: home.y,
            modifiers: KeyModifiers::NONE,
        }),
    );
    assert_eq!(state.ui.view, View::Home);
}

#[test]
fn clicking_a_confirm_choice_activates_it() {
    let mut state = live(connected(), KillSwitchState::Armed);
    update(&mut state, key('d'));
    let Some(Modal::Confirm { kind, .. }) = &state.ui.modal else {
        panic!("no modal");
    };
    let geometry = crate::layout::confirm(state.layout().area, kind);
    let target = geometry.choices[1];
    let effects = update(
        &mut state,
        Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: target.x + 2,
            row: target.y,
            modifiers: KeyModifiers::NONE,
        }),
    );
    assert_eq!(commands(&effects), vec![Command::Disconnect]);
}

#[test]
fn too_small_only_quits() {
    let mut state = live(connected(), KillSwitchState::Off);
    update(&mut state, Event::Resize(40, 10));
    assert!(update(&mut state, key('d')).is_empty());
    assert!(update(&mut state, key('?')).is_empty());
    assert_eq!(update(&mut state, key('q')), vec![Effect::Quit]);
    let ctrl_c = Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(update(&mut state, ctrl_c), vec![Effect::Quit]);
}

#[test]
fn resize_clamps_scroll_to_keep_selection_visible() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    update(&mut state, key('2'));
    update(&mut state, key('/'));
    update(&mut state, key('a'));
    update(&mut state, code(KeyCode::Enter));
    update(&mut state, code(KeyCode::End));
    update(&mut state, Event::Resize(60, 18));
    let list = state.layout().servers_list().expect("servers list");
    let rows = state.ui.browser.rows(state.servers());
    let selected = state.ui.browser.selected_index(&rows).expect("selection");
    let offset = state.ui.browser.offset;
    assert!(selected >= offset && selected < offset + usize::from(list.height));
}

#[test]
fn animation_only_while_tunnel_is_transitioning() {
    assert!(live(connecting(), KillSwitchState::Off).animating());
    assert!(live(reconnecting(), KillSwitchState::Off).animating());
    assert!(!live(connected(), KillSwitchState::Off).animating());
    assert!(!live(disconnected(), KillSwitchState::Off).animating());
}

#[test]
fn intent_describes_for_messages() {
    let state = live(disconnected(), KillSwitchState::Off);
    assert_eq!(
        Intent::Connect(zurich()).describe(state.daemon.as_ref()),
        "connect to Zürich #12"
    );
}
