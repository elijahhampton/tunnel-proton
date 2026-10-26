//! Drives the real client (link task + reducer) against the mock daemon running in-process.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};
use vpnui_mockd::{Config, Control, Scenario, serve};
use vpnui_proto::{KillSwitchState, TunnelState, UnixMillis};
use vpnui_tui::app::{AppState, DaemonLink, Event, Posture, Slot, posture};
use vpnui_tui::runtime::{Core, start};
use vpnui_tui::theme::{ColorMode, Theme};

const TIME_SCALE: f64 = 0.05;
const WAIT: Duration = Duration::from_secs(15);

fn socket_path() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("vpnui-e2e-{}-{n}.sock", std::process::id()))
}

fn spawn_daemon(path: &Path, control: mpsc::Receiver<Control>) -> JoinHandle<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).unwrap();
    let config = Config::new(7, Scenario::Calm)
        .with_time_scale(TIME_SCALE)
        .without_random_faults()
        .with_control(control);
    tokio::spawn(async move {
        let _ = serve(listener, config).await;
    })
}

struct Client {
    core: Core,
    events: mpsc::Receiver<Event>,
    _link: JoinHandle<()>,
}

impl Client {
    fn connect(path: &Path) -> Self {
        let (core, _tx, events, link) = start(
            path.to_path_buf(),
            Theme::new(ColorMode::None, false),
            120,
            40,
        );
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

    fn press_code(&mut self, code: KeyCode) {
        self.core
            .dispatch(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)));
    }

    /// Pumps real events (and wall-clock ticks) until `done` holds.
    async fn until(&mut self, what: &str, done: impl Fn(&AppState) -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done(self.core.state()) {
            let next = timeout_at(deadline, self.events.recv()).await;
            let Ok(Some(event)) = next else {
                let s = self.core.state();
                panic!(
                    "timed out waiting for {what}: link={:?} posture={:?} tunnel={:?} log={:#?}",
                    s.link,
                    posture(s),
                    s.daemon.as_ref().map(|p| &p.tunnel),
                    s.log.iter().take(8).collect::<Vec<_>>(),
                );
            };
            self.core.dispatch(Event::Tick(UnixMillis::now()));
            self.core.dispatch(event);
        }
    }
}

fn tunnel(state: &AppState) -> Option<&TunnelState> {
    state.daemon.as_ref().map(|p| &p.tunnel)
}

fn kill_switch(state: &AppState) -> Option<&KillSwitchState> {
    state.daemon.as_ref().map(|p| &p.kill_switch)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_drop_crash_restart_recover() {
    let path = socket_path();
    let (control, control_rx) = mpsc::channel(8);
    let daemon = spawn_daemon(&path, control_rx);
    let mut client = Client::connect(&path);

    client
        .until("initial snapshot", |s| s.link == DaemonLink::Live)
        .await;
    assert_eq!(posture(client.state()), Posture::Exposed);
    assert!(client.state().servers().len() >= 150);

    // Arm the kill switch; protection changes only when the daemon confirms.
    client.press('s');
    assert!(client.state().pending(Slot::KillSwitch).is_some());
    assert_eq!(kill_switch(client.state()), Some(&KillSwitchState::Off));
    client
        .until("kill switch armed", |s| {
            kill_switch(s) == Some(&KillSwitchState::Armed) && s.pending(Slot::KillSwitch).is_none()
        })
        .await;
    assert_eq!(posture(client.state()), Posture::Blocked);

    // Quick connect, pressed twice: only one command goes out.
    client.press('c');
    client.press('c');
    assert_eq!(client.state().in_flight.len(), 1);
    client
        .until("connecting", |s| {
            matches!(tunnel(s), Some(TunnelState::Connecting { .. }))
        })
        .await;
    assert_eq!(
        posture(client.state()),
        Posture::Blocked,
        "armed while connecting"
    );
    client
        .until("connected", |s| {
            matches!(tunnel(s), Some(TunnelState::Connected { .. }))
        })
        .await;
    assert_eq!(posture(client.state()), Posture::Protected);
    let first_server = tunnel(client.state()).and_then(|t| t.server_id()).cloned();
    client
        .until("public ip moves to the exit", |s| {
            s.daemon
                .as_ref()
                .and_then(|p| p.public_ip.as_ref())
                .is_some_and(|ip| ip.ip.to_string().starts_with("198.51.100."))
        })
        .await;
    client
        .until("stats flowing", |s| s.traffic.current().is_some())
        .await;

    // Forced drop: kill switch keeps traffic blocked, auto-reconnect brings it back.
    control.send(Control::Drop).await.unwrap();
    client
        .until("reconnecting", |s| {
            matches!(tunnel(s), Some(TunnelState::Reconnecting { .. }))
        })
        .await;
    assert_eq!(posture(client.state()), Posture::Blocked);
    client
        .until("reconnected", |s| {
            matches!(tunnel(s), Some(TunnelState::Connected { .. }))
        })
        .await;
    assert_eq!(
        tunnel(client.state()).and_then(|t| t.server_id()).cloned(),
        first_server
    );

    // Daemon crash: the link is lost and posture is Unknown, with stale data retained.
    daemon.abort();
    client
        .until("link lost", |s| matches!(s.link, DaemonLink::Lost { .. }))
        .await;
    assert_eq!(posture(client.state()), Posture::Unknown);
    assert!(client.state().is_stale());
    assert!(matches!(
        tunnel(client.state()),
        Some(TunnelState::Connected { .. })
    ));

    // Actions are refused while the link is down.
    client.press('d');
    assert!(client.state().in_flight.is_empty());

    // Restart. The fresh daemon has no tunnel and no kill switch; the client must show that,
    // not its stale projection.
    let (_control, control_rx) = mpsc::channel(8);
    let restarted = spawn_daemon(&path, control_rx);
    client
        .until("link live again", |s| s.link == DaemonLink::Live)
        .await;
    assert!(!client.state().is_stale());
    assert_eq!(
        tunnel(client.state()),
        Some(&TunnelState::Disconnected { last_error: None })
    );
    assert_eq!(kill_switch(client.state()), Some(&KillSwitchState::Off));
    assert_eq!(posture(client.state()), Posture::Exposed);
    assert!(
        client
            .state()
            .log
            .iter()
            .any(|e| e.text.contains("Reconnected to the daemon"))
    );

    // And the recovered link carries commands.
    client.press('c');
    client
        .until("connected after restart", |s| {
            matches!(tunnel(s), Some(TunnelState::Connected { .. }))
        })
        .await;
    assert_eq!(posture(client.state()), Posture::Protected);

    restarted.abort();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_client_sees_shared_state_and_failures() {
    let path = socket_path();
    let (control, control_rx) = mpsc::channel(8);
    let daemon = spawn_daemon(&path, control_rx);
    let mut a = Client::connect(&path);
    let mut b = Client::connect(&path);
    a.until("a live", |s| s.link == DaemonLink::Live).await;
    b.until("b live", |s| s.link == DaemonLink::Live).await;

    a.press('s');
    b.until("b sees a's kill switch", |s| {
        kill_switch(s) == Some(&KillSwitchState::Armed)
    })
    .await;

    control.send(Control::FailNext).await.unwrap();
    b.press('c');
    a.until("a sees the failed handshake", |s| {
        matches!(tunnel(s), Some(TunnelState::Disconnected { last_error: Some(e) }) if e.contains("handshake"))
    })
    .await;
    assert_eq!(
        posture(a.state()),
        Posture::Blocked,
        "failed connect while armed is blocked"
    );

    control.send(Control::KillSwitchError).await.unwrap();
    a.until("kill switch error", |s| {
        matches!(kill_switch(s), Some(KillSwitchState::Error { .. }))
    })
    .await;
    assert_eq!(posture(a.state()), Posture::Exposed);
    assert!(vpnui_tui::app::kill_switch_warning(a.state()).is_some());

    // Retry from the error dialog after the operator clears the fault.
    control.send(Control::KillSwitchClear).await.unwrap();
    a.until("kill switch re-applied", |s| {
        kill_switch(s) == Some(&KillSwitchState::Armed)
    })
    .await;

    // Disarming asks first; Cancel (the default) leaves the kill switch armed.
    a.press('s');
    a.press_code(KeyCode::Enter);
    assert!(a.state().in_flight.is_empty());

    daemon.abort();
    let _ = std::fs::remove_file(&path);
}
