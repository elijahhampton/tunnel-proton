//! Renders real states into a `TestBackend` and checks the text. Run with `--nocapture` to see
//! every buffer.

use std::time::Duration;

use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use vpnui_proto::{Event as DaemonEvent, KillSwitchState, ProtocolVersion, Stats, TunnelState};

use super::view;
use crate::app::fixtures::*;
use crate::app::{AppState, Event, LinkEvent, Posture, VersionMismatch, posture, update};
use crate::format;
use crate::theme::{ColorMode, Theme};

const SIZES: [(u16, u16); 2] = [(80, 24), (120, 40)];

fn render(state: &AppState) -> String {
    let mut terminal = Terminal::new(TestBackend::new(state.width, state.height)).unwrap();
    terminal.draw(|frame| view(state, frame)).unwrap();
    text(terminal.backend().buffer())
}

/// One line per row; cells hidden behind a wide glyph are skipped.
fn text(buffer: &Buffer) -> String {
    let width = usize::from(buffer.area.width);
    let mut out = String::new();
    for row in buffer.content().chunks(width) {
        let mut skip = 0;
        for cell in row {
            if skip == 0 {
                out.push_str(cell.symbol());
            }
            skip = skip.max(format::width(cell.symbol())).saturating_sub(1);
        }
        out.push('\n');
    }
    out
}

fn show(label: &str, state: &AppState) -> String {
    let screen = render(state);
    println!(
        "=== {label} ({}x{}) ===\n{screen}",
        state.width, state.height
    );
    screen
}

fn resized(mut state: AppState, (w, h): (u16, u16)) -> AppState {
    update(&mut state, Event::Resize(w, h));
    state
}

fn stale(mut state: AppState) -> AppState {
    update(&mut state, Event::Tick(at(30)));
    update(
        &mut state,
        Event::Link(LinkEvent::Down {
            reason: "daemon closed the connection".into(),
            retry_in: Duration::from_secs(4),
        }),
    );
    update(&mut state, Event::Tick(at(42)));
    state
}

fn with_traffic(mut state: AppState) -> AppState {
    let (mut rx, mut tx) = (0u64, 0u64);
    for i in 0..70u64 {
        update(&mut state, Event::Tick(at(i)));
        let burst = if i % 9 == 0 { 6 } else { 1 };
        rx += (200_000 + (i % 7) * 40_000) * burst;
        tx += 20_000 + (i % 5) * 9_000;
        update(
            &mut state,
            daemon(DaemonEvent::Stats(Stats {
                rx_bytes: rx,
                tx_bytes: tx,
                last_handshake_ms: Some(at(0)),
            })),
        );
    }
    state
}

fn posture_cases() -> Vec<(&'static str, AppState, Posture, &'static str)> {
    vec![
        (
            "protected, armed",
            live(connected(), KillSwitchState::Armed),
            Posture::Protected,
            "ARMED",
        ),
        (
            "exposed, idle",
            live(disconnected(), KillSwitchState::Off),
            Posture::Exposed,
            "OFF",
        ),
        (
            "exposed while connecting",
            live(connecting(), KillSwitchState::Off),
            Posture::Exposed,
            "OFF",
        ),
        (
            "blocked while reconnecting",
            live(reconnecting(), KillSwitchState::Armed),
            Posture::Blocked,
            "ARMED",
        ),
        (
            "exposed, kill switch error",
            live(
                disconnected(),
                KillSwitchState::Error {
                    message: "failed to load packet filter rules".into(),
                },
            ),
            Posture::Exposed,
            "ERROR",
        ),
        (
            "unknown, stale",
            stale(live(connected(), KillSwitchState::Armed)),
            Posture::Unknown,
            "ARMED",
        ),
        (
            "unknown, never connected",
            AppState::new(theme(), T0, 120, 40),
            Posture::Unknown,
            "unknown",
        ),
    ]
}

#[test]
fn every_posture_at_both_sizes() {
    for size in SIZES {
        for (label, state, expected, kill_switch) in posture_cases() {
            let state = resized(state, size);
            assert_eq!(posture(&state), expected, "{label}");
            let screen = show(label, &state);
            assert!(
                screen.contains(expected.word()),
                "{label}: posture word missing"
            );
            assert!(
                screen.contains(kill_switch),
                "{label}: kill switch {kill_switch} missing"
            );
        }
    }
}

#[test]
fn posture_symbols_render_next_to_words() {
    for (_, state, expected, _) in posture_cases() {
        let screen = render(&state);
        let symbol = state.theme.posture_symbol(expected);
        assert!(
            screen.contains(&format!("{symbol}  {}", expected.word())),
            "{expected:?} banner missing symbol"
        );
    }
}

#[test]
fn stale_data_is_labelled() {
    for size in SIZES {
        let state = resized(stale(live(connected(), KillSwitchState::Armed)), size);
        let screen = show("stale", &state);
        assert!(screen.contains("stale (12s ago)"), "stale label missing");
        assert!(screen.contains("daemon lost"));
    }
}

#[test]
fn kill_switch_error_is_prominent() {
    for size in SIZES {
        let state = resized(
            live(
                connected(),
                KillSwitchState::Error {
                    message: "failed to load rules".into(),
                },
            ),
            size,
        );
        let screen = show("kill switch error while protected", &state);
        assert!(screen.contains("KILL SWITCH FAILED"));
    }
}

#[test]
fn too_small_terminal_shows_message_without_panicking() {
    for (w, h) in [(59, 24), (80, 17), (40, 10), (12, 3), (1, 1)] {
        let state = resized(live(connected(), KillSwitchState::Armed), (w, h));
        let screen = show("too small", &state);
        if w >= 45 {
            assert!(screen.contains(&format!("terminal too small (have {w}x{h}, need 60x18)")));
        }
    }
}

#[test]
fn minimum_size_renders_full_ui() {
    let state = resized(live(connected(), KillSwitchState::Armed), (60, 18));
    let screen = show("minimum", &state);
    assert!(screen.contains("PROTECTED"));
    assert!(screen.contains("[1 Home]"));
}

fn each_view(state: AppState, label: &str) {
    for size in SIZES {
        for (key, name) in [
            ('1', "home"),
            ('2', "servers"),
            ('3', "stats"),
            ('4', "settings"),
        ] {
            let mut state = resized(state.clone(), size);
            update(&mut state, crate::app::fixtures::key(key));
            let screen = show(&format!("{label}: {name}"), &state);
            assert!(screen.contains("[1 Home]") && screen.contains("[4 Settings]"));
        }
    }
}

#[test]
fn each_view_connected() {
    each_view(
        with_traffic(live(connected(), KillSwitchState::Armed)),
        "connected",
    );
}

#[test]
fn each_view_disconnected() {
    each_view(live(disconnected(), KillSwitchState::Off), "disconnected");
}

#[test]
fn servers_view_shows_tree_details_and_search() {
    for size in SIZES {
        let mut state = resized(live(connected(), KillSwitchState::Off), size);
        update(&mut state, key('2'));
        update(&mut state, code(KeyCode::End));
        for _ in 0..4 {
            update(&mut state, key('l'));
        }
        let screen = show("servers expanded", &state);
        assert!(
            screen.contains("Switzerland CH  3 servers  avg load 49%"),
            "country row"
        );
        assert!(screen.contains("Geneva #1"));
        assert!(
            screen.contains("Enter connect to Geneva #1") || screen.contains("Enter switch from")
        );

        update(&mut state, key('/'));
        for c in "são".chars() {
            update(&mut state, key(c));
        }
        let screen = show("servers search", &state);
        assert!(screen.contains("São Paulo #4"));
        assert!(screen.contains("1 matching"));
        assert!(!screen.contains("Geneva #1"));
    }
}

#[test]
fn stats_view_shows_session_and_log() {
    for size in SIZES {
        let mut state = resized(
            with_traffic(live(connected(), KillSwitchState::Armed)),
            size,
        );
        update(&mut state, key('3'));
        let screen = show("stats", &state);
        assert!(screen.contains("198.51.100.12:51820"));
        assert!(screen.contains("Event log"));
        assert!(screen.contains("Download"));
        assert!(screen.contains("MiB"));
    }
}

#[test]
fn handshake_age_past_threshold_is_flagged() {
    let mut state = live(connected(), KillSwitchState::Off);
    update(&mut state, Event::Tick(at(200)));
    update(&mut state, key('3'));
    let screen = show("old handshake", &state);
    assert!(screen.contains("3m ago"));
    let buffer = {
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal.draw(|f| view(&state, f)).unwrap();
        terminal.backend().buffer().clone()
    };
    let row = text(&buffer)
        .lines()
        .position(|l| l.contains("Handshake"))
        .expect("handshake row");
    let col = text(&buffer)
        .lines()
        .nth(row)
        .and_then(|l| l.find("3m ago"))
        .expect("age");
    let x = format::width(&text(&buffer).lines().nth(row).unwrap_or_default()[..col]) as u16;
    let cell = &buffer[(x, row as u16)];
    assert_eq!(cell.style().add_modifier, state.theme.error.add_modifier);
    assert!(Duration::from_secs(200) > super::HANDSHAKE_STALE_AFTER);
}

#[test]
fn modals_render_at_minimum_and_wide_sizes() {
    for size in [(60, 18), (120, 40)] {
        let mut state = resized(live(connected(), KillSwitchState::Armed), size);
        update(&mut state, key('d'));
        let screen = show("disconnect confirm", &state);
        assert!(screen.contains("Disconnect and disarm"));
        assert!(screen.contains("Disconnect, stay blocked"));
        assert!(screen.contains("Cancel"));
        assert!(screen.contains("Disconnecting will"));

        update(&mut state, code(KeyCode::Esc));
        update(&mut state, key('?'));
        let screen = show("help", &state);
        assert!(screen.contains("Keys"));
        assert!(screen.contains("quick connect"));
    }
}

#[test]
fn version_mismatch_screen_names_both_versions() {
    let mut state = live(connected(), KillSwitchState::Armed);
    state.version_mismatch = Some(VersionMismatch {
        client: ProtocolVersion(1),
        daemon: Some(ProtocolVersion(2)),
    });
    let screen = show("version mismatch", &state);
    assert!(screen.contains("protocol v1"));
    assert!(screen.contains("speaks v2"));
}

#[test]
fn ascii_mode_uses_no_box_drawing_or_symbols() {
    let ascii = Theme::new(ColorMode::None, true);
    for (label, state, _, _) in posture_cases() {
        for size in SIZES {
            for view_key in ['1', '2', '3', '4'] {
                let mut state = resized(state.clone(), size);
                state.theme = ascii.clone();
                update(&mut state, key(view_key));
                if view_key == '2' {
                    update(&mut state, code(KeyCode::End));
                    update(&mut state, key('l'));
                    update(&mut state, key('l'));
                }
                let screen = render(&state);
                let offending: Vec<char> = screen
                    .chars()
                    .filter(|c| {
                        matches!(*c as u32, 0x2190..=0x21FF | 0x2500..=0x25FF | 0x2700..=0x27BF | 0x2800..=0x28FF)
                            || matches!(*c, '…' | '·' | '›')
                    })
                    .collect();
                assert!(
                    offending.is_empty(),
                    "{label}: non-ASCII glyphs {offending:?}\n{screen}"
                );
            }
        }
    }
    let mut state = live(connected(), KillSwitchState::Armed);
    state.theme = ascii;
    show("ascii home", &state);
}

#[test]
fn no_flag_emoji_or_wide_symbols() {
    for (_, state, _, _) in posture_cases() {
        let screen = render(&state);
        assert!(
            !screen
                .chars()
                .any(|c| matches!(c as u32, 0x1F1E6..=0x1F1FF)),
            "regional indicator symbols found"
        );
    }
}

#[test]
fn narrow_status_bar_shows_server_and_kill_switch() {
    let state = live(connected(), KillSwitchState::Armed);
    let state = resized(state, (80, 24));
    let screen = show("narrow status bar", &state);
    let top: Vec<&str> = screen.lines().take(4).collect();
    assert!(top[1].contains("PROTECTED") && top[1].contains("Zürich #12 CH"));
    assert!(top[3].contains("Kill switch") && top[3].contains("ARMED"));
}

#[test]
fn pending_indicator_is_visible() {
    let mut state = live(disconnected(), KillSwitchState::Off);
    update(&mut state, key('s'));
    let screen = show("pending kill switch", &state);
    assert!(screen.contains("pending…"));
    assert_eq!(
        state.daemon.as_ref().map(|p| &p.tunnel),
        Some(&TunnelState::Disconnected { last_error: None })
    );
}

fn colombia(tunnel: TunnelState, recents: Vec<vpnui_proto::ServerId>) -> AppState {
    live_with(
        profiles_snapshot(tunnel, KillSwitchState::Armed, colombia_profiles(), recents),
        80,
        24,
    )
}

fn connected_co4() -> TunnelState {
    TunnelState::Connected {
        server_id: co4(),
        since_ms: at(0),
        endpoint: "203.0.113.40:51820".into(),
        last_handshake_ms: Some(at(0)),
    }
}

#[test]
fn empty_state_tells_the_user_to_import() {
    for size in SIZES {
        for (view_key, name) in [('1', "home"), ('2', "servers")] {
            let mut state = resized(
                live_with(
                    profiles_snapshot(
                        TunnelState::Disconnected { last_error: None },
                        KillSwitchState::Off,
                        Vec::new(),
                        Vec::new(),
                    ),
                    120,
                    40,
                ),
                size,
            );
            update(&mut state, key(view_key));
            let screen = show(&format!("empty state: {name}"), &state);
            assert!(screen.contains("No profiles yet."), "{name}");
            assert!(
                screen.contains("Download WireGuard configs from your account,"),
                "{name}"
            );
            assert!(screen.contains("then run:"), "{name}");
            assert!(screen.contains("sudo vpnuid import <files>"), "{name}");
            assert!(screen.contains("Only countries you import"), "{name}");
        }
    }
}

#[test]
fn colombia_only_catalog_home_servers_stats() {
    let mut state = colombia(connected_co4(), vec![co4()]);
    let screen = show("colombia: home (connected, no IP check)", &state);
    assert!(screen.contains("PROTECTED"));
    assert!(screen.contains("IP not checked"), "status bar IP");
    assert!(screen.contains("Entry 203.0.113.40"), "status bar entry");

    update(&mut state, key('2'));
    update(&mut state, code(KeyCode::Home));
    update(&mut state, key('l'));
    update(&mut state, key('l'));
    update(&mut state, key('l'));
    update(&mut state, key('l'));
    let screen = show("colombia: servers", &state);
    assert!(screen.contains("Colombia CO"));
    assert!(screen.contains("CO#4") && screen.contains("CO#7"));
    assert!(
        screen.contains("Entry      203.0.113.40"),
        "detail pane entry"
    );
    assert!(screen.contains("avg load —"));

    update(&mut state, key('3'));
    let screen = show("colombia: stats", &state);
    assert!(screen.contains("203.0.113.40:51820"));
}

#[test]
fn colombia_wide_posture_card_shows_entry_and_quick_connect_target() {
    let state = resized(
        colombia(TunnelState::Disconnected { last_error: None }, Vec::new()),
        (120, 40),
    );
    let screen = show("colombia: wide, disconnected", &state);
    assert!(screen.contains("IP      not checked"));
    assert!(screen.contains("Entry   —"));
    assert!(
        screen.contains("Quick connect (CO#7)"),
        "most recently imported"
    );
    assert!(screen.contains("quick connect (CO#7)"), "footer hint");
}

#[test]
fn option_fields_render_as_dashes() {
    let mut state = colombia(TunnelState::Disconnected { last_error: None }, vec![co4()]);
    update(&mut state, key('2'));
    update(&mut state, code(KeyCode::Home));
    for _ in 0..4 {
        update(&mut state, key('l'));
    }
    let screen = show("option fields: servers", &state);
    let row = screen
        .lines()
        .filter_map(|l| l.split("││").next())
        .find(|left| left.starts_with('│') && left.contains("CO#4"))
        .expect("tree row for CO#4");
    assert_eq!(
        row.matches('—').count(),
        2,
        "load and latency dashes: {row}"
    );
    assert!(screen.contains("Load       —"));
    assert!(screen.contains("Latency    —"));
    assert!(screen.contains("Features   —"));

    update(&mut state, key('1'));
    let screen = show("option fields: home recents", &state);
    let recent = screen
        .lines()
        .filter_map(|l| l.split("││").next())
        .find(|left| left.starts_with('│') && left.contains("CO#4"))
        .expect("recents row");
    assert!(recent.contains('—'), "recents load: {recent}");
}

#[test]
fn map_skips_markers_without_coordinates() {
    let mut servers = colombia_profiles();
    for s in &mut servers {
        s.lat = None;
        s.lon = None;
    }
    let state = live_with(
        profiles_snapshot(connected_co4(), KillSwitchState::Off, servers, vec![co4()]),
        120,
        40,
    );
    let screen = show("map without coordinates", &state);
    assert!(!screen.contains(state.theme.sym.server), "no server marker");
    assert!(!screen.contains("you ("), "no home marker");
}
