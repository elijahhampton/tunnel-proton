//! The real engine and socket server on the fake platform, driven by the real TUI client code.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream as StdStream;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout_at};
use vpnui_daemon::daemon::{self, Daemon};
use vpnui_daemon::engine::EngineOptions;
use vpnui_daemon::fake::FakePlatform;
use vpnui_daemon::net::DefaultRoute;
use vpnui_daemon::platform::Op;
use vpnui_daemon::server::ServerConfig;
use vpnui_daemon::testkeys::{profile, secret_forms};
use vpnui_proto::{DaemonMessage, ErrorCode, KillSwitchState, TunnelState, UnixMillis, decode};
use vpnui_tui::app::{AppState, DaemonLink, Event, Posture, posture};
use vpnui_tui::runtime::{Core, start};
use vpnui_tui::theme::{ColorMode, Theme};

const WAIT: Duration = Duration::from_secs(20);

fn fake() -> FakePlatform {
    let profiles = vec![
        profile(1, "CO#4", "203.0.113.40:51820", 3_000),
        profile(2, "US-NY#123", "198.51.100.7:51820", 2_000),
        profile(3, "SE#2", "198.51.100.9:443", 1_000),
    ];
    let fake = FakePlatform::new().with_profiles(profiles.clone());
    {
        let mut st = fake.state();
        st.audit.enabled = true;
        st.audit.allowed_endpoints = profiles.iter().map(|p| p.endpoint()).collect();
    }
    fake
}

fn me() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn launch(fake: &FakePlatform, allowed: BTreeSet<u32>) -> (Daemon, PathBuf) {
    let daemon = daemon::start(
        fake.clone(),
        EngineOptions::default(),
        ServerConfig {
            allowed_uids: allowed,
            max_clients: 8,
        },
    )
    .unwrap();
    let socket = fake.state().socket_path.clone().unwrap();
    (daemon, socket)
}

struct Tui {
    core: Core,
    events: mpsc::Receiver<Event>,
    _link: tokio::task::JoinHandle<()>,
}

impl Tui {
    fn attach(socket: PathBuf) -> Self {
        let (core, _tx, events, link) = start(socket, Theme::new(ColorMode::None, false), 120, 40);
        Self {
            core,
            events,
            _link: link,
        }
    }

    fn state(&self) -> &AppState {
        self.core.state()
    }

    fn press(&mut self, c: char) {
        self.core.dispatch(Event::Key(KeyEvent::new(
            KeyCode::Char(c),
            KeyModifiers::NONE,
        )));
    }

    async fn until(&mut self, what: &str, done: impl Fn(&AppState) -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done(self.core.state()) {
            let Ok(Some(event)) = timeout_at(deadline, self.events.recv()).await else {
                let s = self.core.state();
                panic!(
                    "timed out waiting for {what}: link={:?} posture={:?} tunnel={:?} log={:#?}",
                    s.link,
                    posture(s),
                    s.daemon.as_ref().map(|p| &p.tunnel),
                    s.log.iter().take(8).collect::<Vec<_>>()
                );
            };
            self.core.dispatch(Event::Tick(UnixMillis::now()));
            self.core.dispatch(event);
        }
    }
}

fn tunnel(s: &AppState) -> Option<&TunnelState> {
    s.daemon.as_ref().map(|p| &p.tunnel)
}

fn kill_switch(s: &AppState) -> Option<&KillSwitchState> {
    s.daemon.as_ref().map(|p| &p.kill_switch)
}

/// Advances the fake clock in step with real time, as the real clock would.
fn run_clock(fake: &FakePlatform) -> tokio::task::JoinHandle<()> {
    let fake = fake.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            fake.advance(20);
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_drop_network_change_crash_restart() {
    let fake = fake();
    let clock = run_clock(&fake);
    let (daemon, socket) = launch(&fake, [me()].into());
    let mut tui = Tui::attach(socket.clone());

    tui.until("live", |s| s.link == DaemonLink::Live).await;
    assert_eq!(posture(tui.state()), Posture::Exposed);
    assert_eq!(
        tui.state().daemon.as_ref().map(|p| p.servers.len()),
        Some(3)
    );

    tui.press('s');
    tui.until("armed", |s| kill_switch(s) == Some(&KillSwitchState::Armed))
        .await;
    assert_eq!(posture(tui.state()), Posture::Blocked);

    tui.press('c');
    tui.until("connected", |s| {
        matches!(tunnel(s), Some(TunnelState::Connected { .. }))
    })
    .await;
    assert_eq!(posture(tui.state()), Posture::Protected);
    let server = tunnel(tui.state())
        .and_then(TunnelState::server_id)
        .unwrap()
        .to_string();
    assert!(
        server.starts_with("co-4-"),
        "quick connect picks the newest import: {server}"
    );
    {
        let st = fake.state();
        assert_eq!(st.net_routes.len(), 4);
        assert!(st.dns.is_some());
    }

    // wireguard-go dies; armed means blocked until the hard reconnect brings it back.
    fake.kill_wireguard();
    tui.until("reconnecting", |s| {
        matches!(tunnel(s), Some(TunnelState::Reconnecting { .. }))
    })
    .await;
    assert_eq!(posture(tui.state()), Posture::Blocked);
    tui.until("reconnected", |s| {
        matches!(tunnel(s), Some(TunnelState::Connected { .. }))
    })
    .await;

    // A new network: the endpoint route follows the new gateway without dropping the tunnel.
    fake.set_default_route(Some(DefaultRoute {
        gateway: Ipv4Addr::new(172, 20, 10, 1),
        interface: "en1".parse().unwrap(),
        address: Some(Ipv4Addr::new(172, 20, 10, 2)),
    }));
    let endpoint = "203.0.113.40".parse().unwrap();
    let deadline = std::time::Instant::now() + WAIT;
    while fake.state().host_routes.get(&endpoint) != Some(&Ipv4Addr::new(172, 20, 10, 1)) {
        assert!(
            std::time::Instant::now() < deadline,
            "endpoint route was not re-pinned"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(matches!(
        tunnel(tui.state()),
        Some(TunnelState::Connected { .. })
    ));

    // Crash: no teardown runs. The client must stop trusting what it knew.
    daemon.stop(false).await;
    tui.until("link lost", |s| matches!(s.link, DaemonLink::Lost { .. }))
        .await;
    assert_eq!(posture(tui.state()), Posture::Unknown);
    assert!(
        !fake.state().net_routes.is_empty(),
        "a crash leaves routes behind"
    );

    let before = fake.op_count();
    fake.state().audit.recovering = true;
    let (restarted, _) = launch(&fake, [me()].into());
    fake.state().audit.recovering = false;
    let ops: Vec<Op> = fake.state().ops[before..].iter().map(|r| r.op).collect();
    let load = ops.iter().position(|o| *o == Op::PfLoad).unwrap();
    let bind = ops.iter().position(|o| *o == Op::BindSocket).unwrap();
    assert!(
        load < bind,
        "I4: the baseline policy loads before the socket exists"
    );

    tui.until("live again", |s| s.link == DaemonLink::Live)
        .await;
    assert_eq!(
        tunnel(tui.state()),
        Some(&TunnelState::Disconnected { last_error: None })
    );
    assert_eq!(kill_switch(tui.state()), Some(&KillSwitchState::Armed));
    assert_eq!(
        posture(tui.state()),
        Posture::Blocked,
        "restarted armed: fail closed"
    );
    {
        let st = fake.state();
        assert!(st.tunnel_is_clean(), "recovery removed the crashed session");
        assert!(st.kill_switch_rules().ends_with("block drop quick all\n"));
    }

    tui.press('c');
    tui.until("connected after restart", |s| {
        matches!(tunnel(s), Some(TunnelState::Connected { .. }))
    })
    .await;

    restarted.stop(true).await;
    clock.abort();
    let st = fake.state();
    assert!(
        st.tunnel_is_clean(),
        "graceful shutdown tears the tunnel down"
    );
    assert!(
        !st.kill_switch_rules().is_empty(),
        "but leaves the armed policy in place"
    );
    assert!(st.violations.is_empty(), "audit: {:#?}", st.violations);
    let dump = format!("{:?}{:?}", st.ops, st.state_file);
    for n in 1..=3 {
        for form in secret_forms(n) {
            assert!(!dump.contains(&form));
        }
    }
}

fn first_line(socket: &PathBuf) -> Option<DaemonMessage> {
    let stream = StdStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).ok()?;
    decode(line.trim_end()).ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthorized_users_are_refused_before_any_command() {
    let fake = fake();
    let (daemon, socket) = launch(&fake, BTreeSet::new());
    if me() != 0 {
        let message = tokio::task::spawn_blocking({
            let socket = socket.clone();
            move || first_line(&socket)
        })
        .await
        .unwrap();
        let Some(DaemonMessage::Response(response)) = message else {
            panic!("expected a refusal, got {message:?}");
        };
        assert_eq!(
            response.error.map(|e| e.code),
            Some(ErrorCode::Unauthorized)
        );

        let mut tui = Tui::attach(socket.clone());
        tui.until("refusal shown", |s| {
            s.log
                .iter()
                .any(|e| e.text.to_lowercase().contains("not allowed"))
        })
        .await;
        assert_ne!(tui.state().link, DaemonLink::Live);
    }
    daemon.stop(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ninth_client_is_told_the_daemon_is_busy() {
    let fake = fake();
    let (daemon, socket) = launch(&fake, [me()].into());
    let held: Vec<StdStream> = (0..8)
        .map(|_| StdStream::connect(&socket).unwrap())
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let message = tokio::task::spawn_blocking({
        let socket = socket.clone();
        move || first_line(&socket)
    })
    .await
    .unwrap();
    let Some(DaemonMessage::Response(response)) = message else {
        panic!("expected busy, got {message:?}");
    };
    assert_eq!(response.error.map(|e| e.code), Some(ErrorCode::Busy));
    drop(held);
    daemon.stop(true).await;
}
