use std::collections::BTreeSet;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, Once};

use tokio::sync::broadcast;
use vpnui_proto::{ConnectPhase, ErrorCode, Event, KillSwitchState, SettingsPatch, TunnelState, UnixMillis};

use crate::engine::engine::{Action, Engine, EngineError, EngineOptions, Input};
use crate::fake::fake::{FakeCrash, FakePlatform, HandshakeMode};
use crate::fake::audit;
use crate::net::net::IfName;
use crate::platform::{ Anchor, Op, Platform};
use crate::policy::policy::{self, Policy};
use crate::profile::profile::Profile;
use crate::shared::Shared;
use crate::testkeys::{profile, secret_forms};

const CO: &str = "co-4";
const US: &str = "us-ny-123";
const SE: &str = "se-2";

fn catalog() -> Vec<Profile> {
    vec![
        profile(1, "CO#4", "203.0.113.40:51820", 3_000),
        profile(2, "US-NY#123", "198.51.100.7:51820", 2_000),
        profile(3, "SE#2", "198.51.100.9:443", 1_000),
    ]
}

fn id_of(prefix: &str) -> String {
    catalog()
        .into_iter()
        .find(|p| p.id.starts_with(prefix))
        .map(|p| p.id)
        .unwrap()
}

fn endpoint_of(prefix: &str) -> SocketAddr {
    catalog()
        .into_iter()
        .find(|p| p.id.starts_with(prefix))
        .map(|p| p.endpoint())
        .unwrap()
}

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Logs;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn quiet_crashes() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info.payload().downcast_ref::<FakeCrash>().is_none() {
                default(info);
            }
        }));
    });
}

struct Harness {
    fake: FakePlatform,
    engine: Option<Engine<FakePlatform>>,
    events: broadcast::Receiver<Event>,
    event_log: Vec<String>,
    logs: Logs,
    _log_guard: tracing::subscriber::DefaultGuard,
    label: String,
}

impl Harness {
    fn new() -> Self {
        Self::with(FakePlatform::new().with_profiles(catalog()))
    }

    fn with(fake: FakePlatform) -> Self {
        quiet_crashes();
        fake.state().audit.enabled = true;
        let logs = Logs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        let shared = Shared::new();
        let (_, events) = shared.subscribe();
        let engine = Engine::start(fake.clone(), shared, EngineOptions::default());
        let mut h = Self {
            fake,
            engine: Some(engine),
            events,
            event_log: Vec::new(),
            logs,
            _log_guard: guard,
            label: String::new(),
        };
        h.settle();
        h
    }

    fn engine(&mut self) -> &mut Engine<FakePlatform> {
        self.engine.as_mut().unwrap()
    }

    fn eng(&self) -> &Engine<FakePlatform> {
        self.engine.as_ref().unwrap()
    }

    fn allow(&self, prefix: &str) {
        self.fake
            .state()
            .audit
            .allowed_endpoints
            .insert(endpoint_of(prefix));
    }

    fn cmd(&mut self, action: Action) -> Result<(), EngineError> {
        match &action {
            Action::Connect(id) => {
                let ep = catalog()
                    .into_iter()
                    .find(|p| &p.id == id)
                    .map(|p| p.endpoint());
                if let Some(ep) = ep {
                    self.fake.state().audit.allowed_endpoints.insert(ep);
                }
            }
            Action::QuickConnect => {
                for p in catalog() {
                    self.fake
                        .state()
                        .audit
                        .allowed_endpoints
                        .insert(p.endpoint());
                }
            }
            Action::Disconnect
            | Action::SetKillSwitch(_)
            | Action::SetSettings(_)
            | Action::ReloadProfiles => {}
        }
        let result = self.engine().command(action);
        self.settle();
        result
    }

    fn connect(&mut self, prefix: &str) -> Result<(), EngineError> {
        self.cmd(Action::Connect(id_of(prefix)))
    }

    fn arm(&mut self) {
        self.cmd(Action::SetKillSwitch(true)).unwrap();
    }

    fn tick(&mut self, ms: u64) {
        self.fake.advance(ms);
        self.engine().handle(Input::Tick);
        self.settle();
    }

    fn run_for(&mut self, total_ms: u64, step_ms: u64) {
        let mut elapsed = 0;
        while elapsed < total_ms {
            self.tick(step_ms);
            elapsed += step_ms;
        }
    }

    fn connected(&mut self, prefix: &str) {
        self.connect(prefix).unwrap();
        self.tick(250);
        assert!(
            matches!(self.tunnel(), TunnelState::Connected { .. }),
            "{:?}",
            self.tunnel()
        );
    }

    fn tunnel(&self) -> TunnelState {
        self.eng().tunnel()
    }

    fn kill_switch(&self) -> KillSwitchState {
        self.eng().kill_switch().clone()
    }

    fn session_endpoint(&self) -> Option<SocketAddr> {
        let id = self.eng().session_profile().map(str::to_owned)?;
        catalog()
            .into_iter()
            .find(|p| p.id == id)
            .map(|p| p.endpoint())
    }

    fn settle(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            self.event_log.push(serde_json::to_string(&event).unwrap());
        }
        let Some(engine) = self.engine.as_ref() else {
            return;
        };
        let reported = engine.kill_switch().clone();
        let endpoint = engine.session_profile().and_then(|id| {
            catalog()
                .into_iter()
                .find(|p| p.id == id)
                .map(|p| p.endpoint())
        });
        let mut problems = self.fake.violations();
        problems.extend(audit::check_quiescent(
            &self.fake.state(),
            &reported,
            endpoint,
        ));
        if !problems.is_empty() {
            let st = self.fake.state();
            let tail: Vec<String> = st
                .ops
                .iter()
                .enumerate()
                .rev()
                .take(40)
                .rev()
                .map(|(i, r)| {
                    format!(
                        "  #{i} {:?}{}",
                        r.op,
                        if r.ok {
                            String::new()
                        } else {
                            format!(" FAILED {}", r.detail)
                        }
                    )
                })
                .collect();
            panic!(
                "{}: invariant violations:\n{}\nrecent ops:\n{}\nkill switch rules:\n{}\ntokens: {:?}",
                self.label,
                problems.join("\n"),
                tail.join("\n"),
                st.kill_switch_rules(),
                st.tokens
            );
        }
    }

    /// Drops the engine without any cleanup, as SIGKILL would, then starts a new one.
    fn restart(&mut self) {
        self.engine = None;
        self.fake.state().crash_after = None;
        self.fake.state().fail_at = None;
        let shared = Shared::new();
        let (_, events) = shared.subscribe();
        self.events = events;
        self.fake.state().audit.recovering = true;
        self.engine = Some(Engine::start(
            self.fake.clone(),
            shared,
            EngineOptions::default(),
        ));
        self.fake.state().audit.recovering = false;
        self.settle();
    }

    fn assert_no_secrets(&mut self) {
        let mut haystacks = self.event_log.clone();
        haystacks.push(String::from_utf8_lossy(&self.logs.0.lock().unwrap()).into_owned());
        haystacks.push(self.fake.state().state_file.clone().unwrap_or_default());
        haystacks.push(format!("{:?}", self.engine.as_ref()));
        haystacks.push(format!("{:?}", self.fake.state().ops));
        for n in 1..=3 {
            for form in secret_forms(n) {
                for haystack in &haystacks {
                    assert!(!haystack.contains(&form), "I5: key material leaked: {form}");
                }
            }
        }
    }

    fn baseline(&self) -> String {
        let st = audit::persisted(&self.fake.state()).unwrap_or_default();
        policy::render(&Policy {
            armed: st.armed,
            allow_lan: st.settings.allow_lan,
            block_ipv6: st.settings.block_ipv6,
            endpoints: BTreeSet::new(),
            tunnel_if: None,
        })
    }

    fn ops_since(&self, start: usize) -> Vec<Op> {
        self.fake.state().ops[start..]
            .iter()
            .map(|r| r.op)
            .collect()
    }
}

// --- connect, disconnect, switch -------------------------------------------------------------

#[test]
fn connect_then_disconnect() {
    let mut h = Harness::new();
    h.connect(CO).unwrap();
    assert!(matches!(
        h.tunnel(),
        TunnelState::Connecting {
            phase: ConnectPhase::Handshaking,
            ..
        }
    ));
    assert!(
        h.fake.state().net_routes.is_empty(),
        "no default routes before the handshake"
    );
    h.tick(250);
    let TunnelState::Connected { endpoint, .. } = h.tunnel() else {
        panic!("{:?}", h.tunnel())
    };
    assert_eq!(endpoint, "203.0.113.40:51820");
    {
        let st = h.fake.state();
        assert_eq!(
            st.host_routes.get(&endpoint_of(CO).ip()),
            Some(&Ipv4Addr::new(192, 168, 1, 1))
        );
        let nets: Vec<String> = st.net_routes.iter().map(|(n, _)| n.to_string()).collect();
        assert_eq!(nets.len(), 4);
        for split in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {
            assert!(nets.contains(&split.to_owned()), "{split}");
        }
        assert_eq!(st.dns.as_deref(), Some(&["10.2.0.1".parse().unwrap()][..]));
        let wg = st.instances.values().next().unwrap();
        assert_eq!(wg.keepalive, 25);
        assert_eq!(wg.mtu, Some(1420), "physical MTU 1500 minus 80");
        assert!(wg.configured_key.is_some() && wg.up);
    }
    assert_eq!(h.eng().persisted().recents.first(), Some(&id_of(CO)));

    h.cmd(Action::Disconnect).unwrap();
    assert_eq!(h.tunnel(), TunnelState::Disconnected { last_error: None });
    assert!(h.fake.state().tunnel_is_clean());
    assert!(h.eng().persisted().journal.is_empty());
    h.assert_no_secrets();
}

#[test]
fn armed_connect_orders_policy_before_routes() {
    let mut h = Harness::new();
    h.arm();
    let start = h.fake.op_count();
    h.connect(CO).unwrap();
    h.tick(250);
    let ops = h.ops_since(start);
    let pos = |op: Op| ops.iter().position(|o| *o == op).unwrap();
    let loads: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, o)| **o == Op::PfLoad)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(loads.len(), 2, "endpoint exception, then tunnel exception");
    assert!(
        loads[0] < pos(Op::WgSpawn),
        "endpoint allowed before wireguard-go starts"
    );
    assert!(
        loads[1] > pos(Op::InterfaceConfigure) && loads[1] < pos(Op::RouteAddHost),
        "tunnel pass before any route"
    );
    assert!(
        pos(Op::UapiStatus) < pos(Op::RouteAddNet),
        "default routes only after the handshake"
    );
    assert!(pos(Op::RouteAddNet) < pos(Op::DnsSet));
    let rules = h.fake.state().kill_switch_rules().to_owned();
    assert!(rules.contains("to 203.0.113.40 port 51820") && rules.contains("on utun4"));
    assert_eq!(h.kill_switch(), KillSwitchState::Armed);
}

#[test]
fn disconnect_while_armed_leaves_the_baseline() {
    let mut h = Harness::new();
    h.arm();
    h.connected(CO);
    h.cmd(Action::Disconnect).unwrap();
    let st = h.fake.state();
    assert!(st.tunnel_is_clean());
    assert_eq!(
        st.kill_switch_rules(),
        policy::render(&Policy {
            armed: true,
            block_ipv6: true,
            ..Policy::default()
        })
    );
    assert!(st.pf_enabled());
}

#[test]
fn switching_servers_is_break_before_make_and_covers_both_endpoints() {
    let mut h = Harness::new();
    h.arm();
    h.connected(CO);
    let start = h.fake.op_count();
    h.connect(US).unwrap();
    let loads: Vec<String> = {
        let st = h.fake.state();
        st.ops[start..]
            .iter()
            .filter(|r| r.op == Op::PfLoad)
            .map(|r| r.detail.clone())
            .collect()
    };
    assert!(!loads.is_empty());
    let ops = h.ops_since(start);
    let stop = ops.iter().position(|o| *o == Op::WgStop).unwrap();
    let spawn = ops.iter().position(|o| *o == Op::WgSpawn).unwrap();
    assert!(stop < spawn, "old tunnel is gone before the new one starts");
    h.tick(250);
    assert!(
        matches!(h.tunnel(), TunnelState::Connected { ref server_id, .. } if server_id.as_str() == id_of(US))
    );
    let rules = h.fake.state().kill_switch_rules().to_owned();
    assert!(rules.contains("198.51.100.7 port 51820"));
    assert!(
        !rules.contains("203.0.113.40"),
        "old endpoint removed after the switch"
    );
    assert_eq!(h.fake.state().instances.len(), 1);
}

#[test]
fn reconnecting_to_the_same_server_is_idempotent() {
    let mut h = Harness::new();
    h.connected(CO);
    let spawns = h.ops_since(0).iter().filter(|o| **o == Op::WgSpawn).count();
    h.connect(CO).unwrap();
    assert_eq!(
        h.ops_since(0).iter().filter(|o| **o == Op::WgSpawn).count(),
        spawns
    );
}

#[test]
fn cancel_during_handshake_compensates() {
    let mut h = Harness::new();
    h.fake.set_handshake(HandshakeMode::Never);
    h.arm();
    h.connect(CO).unwrap();
    h.tick(250);
    h.cmd(Action::Disconnect).unwrap();
    assert!(h.fake.state().tunnel_is_clean());
    let baseline = h.baseline();

    assert_eq!(h.fake.state().kill_switch_rules(), baseline);
}

// --- preconditions and errors ------------------------------------------------------------------

#[test]
fn preconditions_fail_without_touching_the_kill_switch() {
    let mut h = Harness::new();
    h.arm();
    let rules = h.fake.state().kill_switch_rules().to_owned();

    h.fake.set_default_route(None);
    let e = h.connect(CO).unwrap_err();
    assert_eq!(e.code, ErrorCode::NoNetwork);
    assert_eq!(h.fake.state().kill_switch_rules(), rules);

    h.fake
        .set_default_route(FakePlatform::new().state().default_route.clone());
    h.fake.state().binary_trusted = false;
    assert_eq!(h.connect(CO).unwrap_err().code, ErrorCode::BinaryUntrusted);
    assert_eq!(h.fake.state().kill_switch_rules(), rules);

    assert_eq!(
        h.cmd(Action::Connect("nope".into())).unwrap_err().code,
        ErrorCode::UnknownServer
    );
    assert_eq!(h.kill_switch(), KillSwitchState::Armed);
    assert!(h.fake.state().tunnel_is_clean());
}

#[test]
fn no_profiles_is_reported() {
    let mut h = Harness::with(FakePlatform::new());
    assert_eq!(
        h.cmd(Action::QuickConnect).unwrap_err().code,
        ErrorCode::NoProfiles
    );
    assert_eq!(
        h.cmd(Action::Connect("x".into())).unwrap_err().code,
        ErrorCode::NoProfiles
    );
}

#[test]
fn handshake_timeout_fails_closed() {
    let mut h = Harness::new();
    h.arm();
    h.fake.set_handshake(HandshakeMode::Never);
    h.connect(CO).unwrap();
    h.run_for(15_250, 250);
    let TunnelState::Disconnected {
        last_error: Some(error),
    } = h.tunnel()
    else {
        panic!("{:?}", h.tunnel())
    };
    assert!(error.starts_with("handshake_timeout:"), "{error}");
    assert!(h.fake.state().tunnel_is_clean());
    let baseline = h.baseline();

    assert_eq!(
        h.fake.state().kill_switch_rules(),
        baseline,
        "armed failure leaves block-all, never open"
    );
    assert_eq!(h.kill_switch(), KillSwitchState::Armed);
}

#[test]
fn quick_connect_prefers_recents_then_newest_import() {
    let mut h = Harness::new();
    h.cmd(Action::QuickConnect).unwrap();
    h.tick(250);
    assert!(
        matches!(h.tunnel(), TunnelState::Connected { ref server_id, .. } if server_id.as_str() == id_of(CO)),
        "newest import"
    );
    h.connect(SE).unwrap();
    h.tick(250);
    h.cmd(Action::Disconnect).unwrap();
    h.cmd(Action::QuickConnect).unwrap();
    h.tick(250);
    assert!(
        matches!(h.tunnel(), TunnelState::Connected { ref server_id, .. } if server_id.as_str() == id_of(SE)),
        "most recent"
    );
    assert_eq!(h.eng().persisted().recents[..2], [id_of(SE), id_of(CO)]);
}

// --- failure injection -------------------------------------------------------------------------

const UNDO_OF: [(Op, Op); 5] = [
    (Op::PfLoad, Op::PfLoad),
    (Op::WgSpawn, Op::WgStop),
    (Op::RouteAddHost, Op::RouteDeleteHost),
    (Op::RouteAddNet, Op::RouteDeleteNet),
    (Op::DnsSet, Op::DnsClear),
];

fn undo_kind(op: Op) -> Option<Op> {
    UNDO_OF
        .iter()
        .find(|(done, _)| *done == op)
        .map(|(_, undo)| *undo)
}

fn is_undo(op: Op) -> bool {
    matches!(
        op,
        Op::PfLoad | Op::WgStop | Op::RouteDeleteHost | Op::RouteDeleteNet | Op::DnsClear
    )
}

#[test]
fn failure_at_every_connect_step_is_compensated_in_reverse() {
    for armed in [false, true] {
        let mut probe = Harness::new();
        if armed {
            probe.arm();
        }
        let start = probe.fake.op_count();
        probe.connected(CO);
        let end = probe.fake.op_count();

        for index in start..end {
            let mut h = Harness::new();
            h.label = format!("armed={armed} failing op #{index}");
            if armed {
                h.arm();
            }
            assert_eq!(h.fake.op_count(), start, "deterministic setup");
            h.fake.fail_at(index);
            let failed_op = probe.fake.state().ops[index].op;
            let _ = h.connect(CO);
            h.run_for(16_000, 250);

            assert_eq!(
                h.eng().persisted().armed,
                armed,
                "{}: armed intent unchanged",
                h.label
            );
            let expected_ks = if armed {
                KillSwitchState::Armed
            } else {
                KillSwitchState::Off
            };
            assert_eq!(h.kill_switch(), expected_ks, "{}", h.label);
            let tunnel = h.tunnel();
            if matches!(tunnel, TunnelState::Connected { .. }) {
            } else if tunnel == (TunnelState::Disconnected { last_error: None }) {
                {
                    assert!(
                        matches!(failed_op, Op::WgVerify | Op::DefaultRoute),
                        "{}: {failed_op:?}",
                        h.label
                    );
                    assert!(!h.ops_since(index).contains(&Op::WgSpawn), "{}", h.label);
                    assert!(h.fake.state().tunnel_is_clean(), "{}", h.label);
                }
            } else if let TunnelState::Disconnected {
                last_error: Some(_),
            } = tunnel
            {
                {
                    assert!(h.fake.state().tunnel_is_clean(), "{}: leftovers", h.label);
                    assert!(h.eng().persisted().journal.is_empty(), "{}", h.label);
                    let baseline = h.baseline();
                    assert_eq!(h.fake.state().kill_switch_rules(), baseline, "{}", h.label);

                    let ops = h.ops_since(start);
                    let failed_at = index - start;
                    let done: Vec<Op> = ops[..=failed_at]
                        .iter()
                        .enumerate()
                        .filter(|(i, o)| {
                            (*i < failed_at || undo_kind(failed_op).is_some())
                                && undo_kind(**o).is_some()
                        })
                        .filter_map(|(_, o)| undo_kind(*o))
                        .collect();
                    let undone: Vec<Op> = ops[failed_at + 1..]
                        .iter()
                        .copied()
                        .filter(|o| is_undo(*o))
                        .collect();
                    let expected: Vec<Op> = done.into_iter().rev().collect();
                    assert_eq!(
                        undone, expected,
                        "{}: compensation order ({failed_op:?})",
                        h.label
                    );
                }
            } else {
                panic!("{}: unexpected final state {tunnel:?}", h.label);
            }
            h.assert_no_secrets();
        }
    }
}

// --- crash and recovery ------------------------------------------------------------------------

#[test]
fn crash_after_every_mutation_recovers_cleanly_and_fails_closed_first() {
    for armed in [false, true] {
        let mut probe = Harness::new();
        if armed {
            probe.arm();
        }
        let start = probe.fake.op_count();
        probe.connected(CO);
        probe.cmd(Action::Disconnect).unwrap();
        let end = probe.fake.op_count();

        for index in start..end {
            let mut h = Harness::new();
            h.label = format!("armed={armed} crash after op #{index}");
            if armed {
                h.arm();
            }
            h.fake.crash_after(index);
            h.allow(CO);
            let crashed = catch_unwind(AssertUnwindSafe(|| {
                let _ = h
                    .engine
                    .as_mut()
                    .unwrap()
                    .command(Action::Connect(id_of(CO)));
                h.fake.advance(250);
                h.engine.as_mut().unwrap().handle(Input::Tick);
                let _ = h.engine.as_mut().unwrap().command(Action::Disconnect);
            }));
            assert!(crashed.is_err(), "{}: expected a crash", h.label);

            let before = h.fake.op_count();
            h.restart();
            let listener = h.engine().bind_socket();
            assert!(listener.is_ok());
            let ops = h.ops_since(before);
            assert_eq!(ops.first(), Some(&Op::LoadState), "{}", h.label);
            let bind = ops.iter().position(|o| *o == Op::BindSocket).unwrap();
            if armed {
                let load = ops.iter().position(|o| *o == Op::PfLoad).unwrap();
                assert_eq!(
                    load, 1,
                    "{}: I4 baseline policy is the first action",
                    h.label
                );
                assert!(load < bind, "{}: I4 policy before the socket", h.label);
            } else {
                assert!(!ops[..bind].contains(&Op::PfLoad), "{}", h.label);
            }
            let st = h.fake.state();
            assert!(
                st.tunnel_is_clean(),
                "{}: kernel not clean: {:?}",
                h.label,
                (&st.instances, &st.host_routes, &st.net_routes, &st.dns)
            );
            drop(st);
            assert!(h.eng().persisted().journal.is_empty(), "{}", h.label);
            let baseline = h.baseline();

            assert_eq!(h.fake.state().kill_switch_rules(), baseline, "{}", h.label);
            assert_eq!(h.tunnel(), TunnelState::Disconnected { last_error: None });
        }
    }
}

#[test]
fn corrupt_state_fails_closed() {
    let fake = FakePlatform::new().with_profiles(catalog());
    fake.state().state_file = Some("{ not json".into());
    let h = Harness::with(fake);
    assert!(h.eng().persisted().armed);
    assert_eq!(h.kill_switch(), KillSwitchState::Armed);
    assert!(!h.fake.state().kill_switch_rules().is_empty());
}

#[test]
fn startup_when_disarmed_clears_a_stale_anchor() {
    let fake = FakePlatform::new().with_profiles(catalog());
    let stale = policy::render(&Policy {
        armed: true,
        ..Policy::default()
    });
    fake.state().anchors.insert(Anchor::KillSwitch, stale);
    let h = Harness::with(fake);
    assert!(h.fake.state().kill_switch_rules().is_empty(), "I3");
}

// --- kill switch and settings ------------------------------------------------------------------

#[test]
fn arming_enables_pf_with_a_token_and_disarming_releases_it() {
    let mut h = Harness::new();
    h.arm();
    {
        let st = h.fake.state();
        assert!(st.pf_enabled() && st.tokens.len() == 1);
        assert!(st.states_flushed >= 1, "states flushed on arming");
    }
    assert!(h.eng().persisted().pf_enabled_by_us);
    h.cmd(Action::SetKillSwitch(false)).unwrap();
    let st = h.fake.state();
    assert!(st.kill_switch_rules().is_empty() && st.tokens.is_empty() && !st.pf_enabled());
}

#[test]
fn pf_enabled_by_someone_else_stays_enabled() {
    let fake = FakePlatform::new().with_profiles(catalog());
    fake.state().pf_enabled_externally = true;
    let mut h = Harness::with(fake);
    h.label = "external pf".into();
    h.arm();
    assert!(!h.eng().persisted().pf_enabled_by_us);
    h.cmd(Action::SetKillSwitch(false)).unwrap();
    assert!(h.fake.state().pf_enabled());
}

#[test]
fn settings_reload_the_policy_and_flush_only_when_tightening() {
    let mut h = Harness::new();
    h.arm();
    let flushed = h.fake.state().states_flushed;
    h.cmd(Action::SetSettings(SettingsPatch {
        allow_lan: Some(true),
        ..SettingsPatch::default()
    }))
    .unwrap();
    assert!(
        h.fake
            .state()
            .kill_switch_rules()
            .contains("192.168.0.0/16")
    );
    assert_eq!(
        h.fake.state().states_flushed,
        flushed,
        "relaxing does not flush"
    );
    h.cmd(Action::SetSettings(SettingsPatch {
        allow_lan: Some(false),
        ..SettingsPatch::default()
    }))
    .unwrap();
    assert!(
        !h.fake
            .state()
            .kill_switch_rules()
            .contains("192.168.0.0/16")
    );
    assert_eq!(
        h.fake.state().states_flushed,
        flushed + 1,
        "tightening flushes"
    );
    assert_eq!(
        h.cmd(Action::SetSettings(SettingsPatch::default()))
            .unwrap_err()
            .code,
        ErrorCode::BadRequest
    );
}

#[test]
fn failed_policy_load_reports_error_and_recovers() {
    let mut h = Harness::new();
    h.fake.state().failing.insert(Op::PfLoad);
    let e = h.cmd(Action::SetKillSwitch(true)).unwrap_err();
    assert_eq!(e.code, ErrorCode::PfFailed);
    assert!(matches!(h.kill_switch(), KillSwitchState::Error { .. }));
    assert!(
        h.eng().persisted().armed,
        "intent stays armed so a restart fails closed"
    );
    h.fake.state().failing.clear();
    h.arm();
    assert_eq!(h.kill_switch(), KillSwitchState::Armed);
}

// --- reconnects --------------------------------------------------------------------------------

fn reconnect_state(h: &Harness) -> (u32, Option<UnixMillis>, String) {
    let tunnel = h.tunnel();
    let TunnelState::Reconnecting {
        attempt,
        retry_at_ms,
        reason,
        ..
    } = tunnel
    else {
        panic!("expected Reconnecting, got {tunnel:?}");
    };
    (attempt, retry_at_ms, reason)
}

#[test]
fn backoff_schedule_soft_then_hard() {
    let mut h = Harness::new();
    h.arm();
    h.connected(CO);
    h.fake.set_handshake(HandshakeMode::Stalled);
    h.run_for(180_000, 1_000);
    let (attempt, retry_at, reason) = reconnect_state(&h);
    assert_eq!(attempt, 1);
    assert!(reason.contains("no handshake for 180s"), "{reason}");
    let now = h.eng().platform().now().wall;
    assert_eq!(retry_at.map(|at| at.0 - now.0), Some(1_000));
    assert!(
        h.fake.state().kill_switch_rules().contains("on utun4"),
        "soft path keeps the tunnel"
    );

    let mut delays = Vec::new();
    let mut kinds = Vec::new();
    for _ in 0..6 {
        let (attempt, retry_at, _) = reconnect_state(&h);
        let now = h.eng().platform().now().wall;
        let delay = retry_at.map(|at| at.0 - now.0).unwrap();
        delays.push(delay / 1000);
        let before = h.fake.op_count();
        h.tick(delay);
        let ops = h.ops_since(before);
        kinds.push((
            attempt,
            ops.contains(&Op::WgSpawn),
            ops.contains(&Op::UapiRefresh),
        ));
        // Let the attempt's window expire.
        let mut guard = 0;
        while !matches!(
            h.tunnel(),
            TunnelState::Reconnecting {
                retry_at_ms: Some(_),
                ..
            }
        ) {
            h.tick(1_000);
            guard += 1;
            assert!(guard < 30, "attempt never finished");
        }
        assert!(
            matches!(h.kill_switch(), KillSwitchState::Armed),
            "kill switch untouched"
        );
    }
    assert_eq!(delays, [1, 2, 4, 8, 15, 15]);
    for (attempt, spawned, refreshed) in &kinds {
        if *attempt <= 3 {
            assert!(
                *refreshed && !*spawned,
                "attempt {attempt} must be soft: {kinds:?}"
            );
        } else {
            assert!(*spawned, "attempt {attempt} must be hard: {kinds:?}");
        }
    }

    h.fake.set_handshake(HandshakeMode::Immediate);
    h.run_for(20_000, 250);
    assert!(
        matches!(h.tunnel(), TunnelState::Connected { .. }),
        "{:?}",
        h.tunnel()
    );
}

#[test]
fn dead_wireguard_triggers_hard_reconnect() {
    let mut h = Harness::new();
    h.arm();
    h.connected(CO);
    h.fake.kill_wireguard();
    h.tick(1_000);
    let (attempt, _, reason) = reconnect_state(&h);
    assert_eq!((attempt, reason.as_str()), (1, "wireguard-go exited"));
    {
        let st = h.fake.state();
        assert!(st.instances.is_empty(), "dead instance reaped");
        assert!(
            !st.kill_switch_rules().contains("on utun4"),
            "its pass rule removed"
        );
        assert!(
            st.kill_switch_rules().contains("203.0.113.40"),
            "endpoint kept for the retry"
        );
    }
    h.tick(1_000);
    h.tick(250);
    assert!(
        matches!(h.tunnel(), TunnelState::Connected { .. }),
        "{:?}",
        h.tunnel()
    );
    assert!(h.fake.state().kill_switch_rules().contains("on utun5"));
}

#[test]
fn auto_reconnect_off_disconnects() {
    let mut h = Harness::new();
    h.cmd(Action::SetSettings(SettingsPatch {
        auto_reconnect: Some(false),
        ..SettingsPatch::default()
    }))
    .unwrap();
    h.connected(CO);
    h.fake.kill_wireguard();
    h.tick(1_000);
    let TunnelState::Disconnected {
        last_error: Some(e),
    } = h.tunnel()
    else {
        panic!("{:?}", h.tunnel())
    };
    assert!(e.starts_with("wg_failed:"), "{e}");
    assert!(h.fake.state().tunnel_is_clean());
}

// --- network changes ---------------------------------------------------------------------------

#[test]
fn network_change_repins_the_endpoint_route() {
    let mut h = Harness::new();
    h.connected(CO);
    let refreshes = h.fake.state().instances.values().next().unwrap().refreshes;
    h.fake.set_default_route(Some(crate::net::net::DefaultRoute {
        gateway: Ipv4Addr::new(172, 20, 10, 1),
        interface: "en1".parse::<IfName>().unwrap(),
        address: Some(Ipv4Addr::new(172, 20, 10, 2)),
    }));
    h.tick(1_000);
    let st = h.fake.state();
    assert_eq!(
        st.host_routes.get(&endpoint_of(CO).ip()),
        Some(&Ipv4Addr::new(172, 20, 10, 1))
    );
    assert_eq!(
        st.instances.values().next().unwrap().refreshes,
        refreshes + 1,
        "handshake forced"
    );
    drop(st);
    assert!(matches!(h.tunnel(), TunnelState::Connected { .. }));
}

#[test]
fn offline_waits_without_churning_then_recovers() {
    let mut h = Harness::new();
    h.arm();
    h.connected(CO);
    let route = h.fake.state().default_route.clone();
    h.fake.set_default_route(None);
    h.tick(1_000);
    let (_, retry_at, reason) = reconnect_state(&h);
    assert_eq!((retry_at, reason.as_str()), (None, "network offline"));
    let before = h.fake.op_count();
    h.run_for(60_000, 1_000);
    let ops = h.ops_since(before);
    assert!(
        !ops.contains(&Op::WgSpawn)
            && !ops.contains(&Op::UapiRefresh)
            && !ops.contains(&Op::PfLoad),
        "no churn while offline"
    );
    h.fake.set_default_route(route);
    h.tick(1_000);
    h.tick(250);
    assert!(
        matches!(h.tunnel(), TunnelState::Connected { .. }),
        "{:?}",
        h.tunnel()
    );
}

#[test]
fn wake_from_sleep_is_a_network_change() {
    let mut h = Harness::new();
    h.connected(CO);
    let refreshes = h.fake.state().instances.values().next().unwrap().refreshes;
    h.fake.sleep_gap(30 * 60_000);
    h.tick(1_000);
    assert_eq!(
        h.fake.state().instances.values().next().unwrap().refreshes,
        refreshes + 1
    );
}

#[test]
fn long_ticks_while_awake_are_not_wake_ups() {
    let mut h = Harness::new();
    h.connected(CO);
    let refreshes = h.fake.state().instances.values().next().unwrap().refreshes;
    for _ in 0..3 {
        h.tick(6_000);
    }
    assert_eq!(
        h.fake.state().instances.values().next().unwrap().refreshes,
        refreshes,
        "both clocks advanced together: no sleep happened"
    );
}

// --- randomized ---------------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn randomized_sequences_keep_every_invariant() {
    let runs: u64 = std::env::var("VPNUID_RANDOM_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);
    let steps = 40;
    let prefixes = [CO, US, SE];
    let routes = [
        Some(crate::net::net::DefaultRoute {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            interface: "en0".parse().unwrap(),
            address: Some(Ipv4Addr::new(192, 168, 1, 23)),
        }),
        Some(crate::net::net::DefaultRoute {
            gateway: Ipv4Addr::new(172, 20, 10, 1),
            interface: "en1".parse().unwrap(),
            address: Some(Ipv4Addr::new(172, 20, 10, 2)),
        }),
        None,
    ];
    let only: Option<u64> = std::env::var("VPNUID_RANDOM_SEED")
        .ok()
        .and_then(|v| v.parse().ok());
    for seed in 0..runs {
        if only.is_some_and(|s| s != seed) {
            continue;
        }
        let mut rng = Rng(seed);
        let mut h = Harness::new();
        for step in 0..steps {
            h.label = format!("seed {seed} step {step}");
            let choice = rng.below(20);
            if choice == 19 {
                let at = h.fake.op_count() + usize::try_from(rng.below(15)).unwrap();
                h.fake.crash_after(at);
                h.allow(prefixes[1]);
                let crashed = catch_unwind(AssertUnwindSafe(|| {
                    let engine = h.engine.as_mut().unwrap();
                    let _ = engine.command(Action::Connect(id_of(prefixes[1])));
                    h.fake.advance(250);
                    h.engine.as_mut().unwrap().handle(Input::Tick);
                }));
                if crashed.is_err() {
                    h.restart();
                } else {
                    h.fake.state().crash_after = None;
                    h.settle();
                }
                continue;
            }
            if choice == 18 {
                let at = h.fake.op_count() + usize::try_from(rng.below(20)).unwrap();
                h.fake.fail_at(at);
                continue;
            }
            match choice {
                0..=3 => {
                    let prefix = prefixes[usize::try_from(rng.below(3)).unwrap()];
                    let _ = h.connect(prefix);
                }
                4 => {
                    let _ = h.cmd(Action::Disconnect);
                }
                5 => {
                    let _ = h.cmd(Action::SetKillSwitch(true));
                }
                6 => {
                    let _ = h.cmd(Action::SetKillSwitch(false));
                }
                7 => {
                    let on = rng.below(2) == 0;
                    let _ = h.cmd(Action::SetSettings(SettingsPatch {
                        allow_lan: Some(on),
                        ..SettingsPatch::default()
                    }));
                }
                8 => {
                    let on = rng.below(2) == 0;
                    let _ = h.cmd(Action::SetSettings(SettingsPatch {
                        block_ipv6: Some(on),
                        ..SettingsPatch::default()
                    }));
                }
                9 => {
                    let on = rng.below(3) != 0;
                    let _ = h.cmd(Action::SetSettings(SettingsPatch {
                        auto_reconnect: Some(on),
                        ..SettingsPatch::default()
                    }));
                }
                10 => {
                    let route = routes[usize::try_from(rng.below(3)).unwrap()].clone();
                    h.fake.set_default_route(route);
                    h.tick(1_000);
                }
                11 => {
                    h.fake.sleep_gap(rng.below(3_600_000));
                    h.tick(1_000);
                }
                12 => {
                    h.fake.kill_wireguard();
                    h.tick(1_000);
                }
                13 => {
                    let mode = [
                        HandshakeMode::Immediate,
                        HandshakeMode::Never,
                        HandshakeMode::Stalled,
                    ][usize::try_from(rng.below(3)).unwrap()];
                    h.fake.set_handshake(mode);
                }
                14 => {
                    let _ = h.cmd(Action::QuickConnect);
                }
                15 => h.run_for(200_000, 5_000),
                _ => {
                    let ms = rng.below(4_000);
                    h.tick(ms);
                }
            }
        }
        h.fake.state().fail_at = None;
        h.fake.set_handshake(HandshakeMode::Immediate);
        h.fake.set_default_route(routes[0].clone());
        let _ = h.cmd(Action::Disconnect);
        h.run_for(5_000, 1_000);
        assert!(
            h.fake.state().tunnel_is_clean(),
            "seed {seed}: not clean after a final disconnect"
        );
        let endpoint = h.session_endpoint();
        assert_eq!(endpoint, None);
        h.assert_no_secrets();
    }
}

#[test]
fn engine_debug_and_logs_are_redacted() {
    let mut h = Harness::new();
    h.arm();
    h.connected(CO);
    h.fake.kill_wireguard();
    h.run_for(10_000, 1_000);
    h.cmd(Action::Disconnect).unwrap();
    let logs = String::from_utf8_lossy(&h.logs.0.lock().unwrap()).into_owned();
    assert!(logs.contains("connected"), "logs are captured");
    let _ = std::io::stderr().flush();
    h.assert_no_secrets();
}
