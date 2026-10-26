//! An in-memory [`Platform`] that models the kernel state the daemon changes: pf anchors and
//! tokens, routes, DNS, and wireguard-go instances. It records every call, can fail the nth one
//! or crash after it, and runs [`audit::check_op`] after each one.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use vpnui_proto::UnixMillis;

use crate::fake::audit;
use crate::net::net::{DefaultRoute, IfName, IpNet};
use crate::platform::{
    Anchor, Mono, Now, Op, PResult, PfToken, Platform, PlatformError, WgInstance,
};
use crate::policy;
use crate::profile::profile::Profile;
use crate::secret::{PublicKey, SecretKey};
use crate::testkeys::TempDir;
use crate::uapi::uapi::{DeviceConfig, DeviceStatus};

/// Panic payload for a simulated crash; see [`FakePlatform::crash_after`].
#[derive(Debug)]
pub struct FakeCrash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeMode {
    /// Handshakes complete as soon as the peer is configured or refreshed, and rekey while alive.
    Immediate,
    /// The server never responds.
    Never,
    /// Earlier handshakes stand but no new ones happen.
    Stalled,
}

#[derive(Debug, Clone)]
pub struct FakeWg {
    pub pid: u32,
    pub alive: bool,
    pub configured_key: Option<SecretKey>,
    pub peer: Option<PublicKey>,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: u16,
    pub handshake_at: Option<u64>,
    pub refreshes: u32,
    pub addresses: Vec<IpNet>,
    pub mtu: Option<u16>,
    pub up: bool,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRecord {
    pub op: Op,
    pub ok: bool,
    pub detail: String,
}

/// What the test considers legitimate, independent of engine state.
#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    pub enabled: bool,
    pub allowed_endpoints: BTreeSet<SocketAddr>,
    /// Startup recovery is running: the baseline policy has been loaded ahead of undoing
    /// leftover routes, so routes into a dead tunnel are black holes by design.
    pub recovering: bool,
}

#[derive(Debug)]
pub struct FakeState {
    pub wall: u64,
    pub mono: u64,
    pub ops: Vec<OpRecord>,
    pub fail_at: Option<usize>,
    pub failing: BTreeSet<Op>,
    pub crash_after: Option<usize>,
    pub anchors: BTreeMap<Anchor, String>,
    pub pf_enabled_externally: bool,
    pub tokens: BTreeSet<u64>,
    pub next_token: u64,
    pub states_flushed: u32,
    pub selftest_packets: u64,
    pub default_route: Option<DefaultRoute>,
    pub phys_mtu: u16,
    pub host_routes: BTreeMap<IpAddr, Ipv4Addr>,
    pub net_routes: BTreeSet<(IpNet, IfName)>,
    pub dns: Option<Vec<IpAddr>>,
    pub instances: BTreeMap<IfName, FakeWg>,
    pub next_unit: u32,
    pub next_pid: u32,
    pub handshake: HandshakeMode,
    pub binary_trusted: bool,
    pub state_file: Option<String>,
    pub profiles: Vec<Profile>,
    pub socket_dir: Option<TempDir>,
    pub socket_path: Option<PathBuf>,
    pub service_loaded: bool,
    pub audit: AuditContext,
    pub violations: Vec<String>,
}

impl FakeState {
    fn new() -> Self {
        Self {
            wall: 1_760_000_000_000,
            mono: 1_000,
            ops: Vec::new(),
            fail_at: None,
            failing: BTreeSet::new(),
            crash_after: None,
            anchors: BTreeMap::new(),
            pf_enabled_externally: false,
            tokens: BTreeSet::new(),
            next_token: 1000,
            states_flushed: 0,
            selftest_packets: 0,
            default_route: Some(DefaultRoute {
                gateway: Ipv4Addr::new(192, 168, 1, 1),
                interface: IfName::from_static("en0"),
                address: Some(Ipv4Addr::new(192, 168, 1, 23)),
            }),
            phys_mtu: 1500,
            host_routes: BTreeMap::new(),
            net_routes: BTreeSet::new(),
            dns: None,
            instances: BTreeMap::new(),
            next_unit: 4,
            next_pid: 4242,
            handshake: HandshakeMode::Immediate,
            binary_trusted: true,
            state_file: None,
            profiles: Vec::new(),
            socket_dir: None,
            socket_path: None,
            service_loaded: false,
            audit: AuditContext::default(),
            violations: Vec::new(),
        }
    }

    pub fn pf_enabled(&self) -> bool {
        self.pf_enabled_externally || !self.tokens.is_empty()
    }

    pub fn kill_switch_rules(&self) -> &str {
        self.anchors
            .get(&Anchor::KillSwitch)
            .map_or("", String::as_str)
    }

    /// Nothing the daemon creates per connection is left in the kernel.
    pub fn tunnel_is_clean(&self) -> bool {
        self.instances.is_empty()
            && self.host_routes.is_empty()
            && self.net_routes.is_empty()
            && self.dns.is_none()
    }

    fn handshake_now(&mut self, ifname: &IfName) {
        let wall = self.wall;
        if self.handshake == HandshakeMode::Immediate
            && let Some(wg) = self.instances.get_mut(ifname)
        {
            wg.handshake_at = Some(wall);
        }
    }

    fn live(&mut self, op: Op, ifname: &IfName) -> PResult<&mut FakeWg> {
        match self.instances.get_mut(ifname) {
            Some(wg) if wg.alive => Ok(wg),
            Some(_) | None => Err(PlatformError::new(op, format!("{ifname} does not exist"))),
        }
    }
}

#[derive(Clone)]
pub struct FakePlatform {
    inner: Arc<Mutex<FakeState>>,
}

impl Default for FakePlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl FakePlatform {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeState::new())),
        }
    }

    pub fn state(&self) -> MutexGuard<'_, FakeState> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn with_profiles(self, profiles: Vec<Profile>) -> Self {
        self.state().profiles = profiles;
        self
    }

    /// Fails the call with this index in [`FakeState::ops`].
    pub fn fail_at(&self, index: usize) {
        self.state().fail_at = Some(index);
    }

    /// Panics with [`FakeCrash`] right after the call with this index completes.
    pub fn crash_after(&self, index: usize) {
        self.state().crash_after = Some(index);
    }

    pub fn op_count(&self) -> usize {
        self.state().ops.len()
    }

    pub fn advance(&self, ms: u64) {
        let mut st = self.state();
        st.wall += ms;
        st.mono += ms;
        for wg in st.instances.values_mut().filter(|w| w.alive) {
            wg.rx += ms * 40;
            wg.tx += ms * 4;
        }
    }

    /// The wall clock moves but the monotonic clock does not, as across a sleep.
    pub fn sleep_gap(&self, ms: u64) {
        self.state().wall += ms;
    }

    pub fn set_default_route(&self, route: Option<DefaultRoute>) {
        self.state().default_route = route;
    }

    pub fn set_handshake(&self, mode: HandshakeMode) {
        self.state().handshake = mode;
    }

    /// wireguard-go dies: its interface and the routes through it vanish, but the record of the
    /// instance remains until the daemon stops it.
    pub fn kill_wireguard(&self) {
        let mut st = self.state();
        let dead: Vec<IfName> = st.instances.keys().cloned().collect();
        for wg in st.instances.values_mut() {
            wg.alive = false;
        }
        st.net_routes.retain(|(_, ifname)| !dead.contains(ifname));
    }

    pub fn violations(&self) -> Vec<String> {
        self.state().violations.clone()
    }

    fn call<T>(&self, op: Op, f: impl FnOnce(&mut FakeState) -> PResult<T>) -> PResult<T> {
        let (result, crash) = {
            let mut st = self.state();
            let index = st.ops.len();
            let injected = st.fail_at == Some(index) || st.failing.contains(&op);
            let result = if injected {
                Err(PlatformError::new(op, "injected failure"))
            } else {
                f(&mut st)
            };
            let detail = match &result {
                Ok(_) => String::new(),
                Err(e) => e.detail.clone(),
            };
            st.ops.push(OpRecord {
                op,
                ok: result.is_ok(),
                detail,
            });
            if st.audit.enabled {
                let found = audit::check_op(&st);
                for violation in found {
                    let line = format!("after op #{index} {op:?}: {violation}");
                    st.violations.push(line);
                }
            }
            (result, st.crash_after == Some(index))
        };
        if crash {
            std::panic::panic_any(FakeCrash);
        }
        result
    }
}

impl Platform for FakePlatform {
    fn now(&self) -> Now {
        let st = self.state();
        Now {
            wall: UnixMillis(st.wall),
            mono: Mono(st.mono),
        }
    }

    fn load_state(&self) -> PResult<Option<String>> {
        self.call(Op::LoadState, |st| Ok(st.state_file.clone()))
    }

    fn save_state(&self, json: &str) -> PResult<()> {
        self.call(Op::SaveState, |st| {
            st.state_file = Some(json.to_owned());
            Ok(())
        })
    }

    fn load_profiles(&self) -> PResult<Vec<Profile>> {
        self.call(Op::LoadProfiles, |st| Ok(st.profiles.clone()))
    }

    fn pf_load(&self, anchor: Anchor, ruleset: &str) -> PResult<()> {
        self.call(Op::PfLoad, |st| {
            if ruleset.is_empty() {
                st.anchors.remove(&anchor);
            } else {
                st.anchors.insert(anchor, ruleset.to_owned());
            }
            Ok(())
        })
    }

    fn pf_flush(&self, anchor: Anchor) -> PResult<()> {
        self.call(Op::PfFlush, |st| {
            st.anchors.remove(&anchor);
            Ok(())
        })
    }

    fn pf_flush_states(&self) -> PResult<()> {
        self.call(Op::PfFlushStates, |st| {
            st.states_flushed += 1;
            Ok(())
        })
    }

    fn pf_enable(&self) -> PResult<PfToken> {
        self.call(Op::PfEnable, |st| {
            let token = st.next_token;
            st.next_token += 1;
            st.tokens.insert(token);
            PfToken::try_from(token.to_string()).map_err(|e| PlatformError::new(Op::PfEnable, e))
        })
    }

    fn pf_release(&self, token: &PfToken) -> PResult<()> {
        self.call(Op::PfRelease, |st| {
            if let Ok(value) = token.as_str().parse::<u64>() {
                st.tokens.remove(&value);
            }
            Ok(())
        })
    }

    fn pf_is_enabled(&self) -> PResult<bool> {
        self.call(Op::PfStatus, |st| Ok(st.pf_enabled()))
    }

    fn pf_disable(&self) -> PResult<()> {
        self.call(Op::PfDisable, |st| {
            st.pf_enabled_externally = false;
            st.tokens.clear();
            Ok(())
        })
    }

    fn pf_anchor_packets(&self, anchor: Anchor) -> PResult<u64> {
        self.call(Op::PfCounters, |st| match anchor {
            Anchor::SelfTest => Ok(st.selftest_packets),
            Anchor::KillSwitch => Ok(0),
        })
    }

    fn send_probe(&self) -> PResult<()> {
        self.call(Op::Probe, |st| {
            let blocked = st
                .anchors
                .get(&Anchor::SelfTest)
                .is_some_and(|r| r.contains(policy::policy::SELFTEST_RULE));
            if blocked && st.pf_enabled() && st.default_route.is_some() {
                st.selftest_packets += 1;
            }
            Ok(())
        })
    }

    fn default_route(&self) -> PResult<Option<DefaultRoute>> {
        self.call(Op::DefaultRoute, |st| Ok(st.default_route.clone()))
    }

    fn interface_mtu(&self, ifname: &IfName) -> PResult<Option<u16>> {
        self.call(Op::InterfaceMtu, |st| {
            if st
                .default_route
                .as_ref()
                .is_some_and(|r| &r.interface == ifname)
            {
                return Ok(Some(st.phys_mtu));
            }
            Ok(st.instances.get(ifname).and_then(|w| w.mtu))
        })
    }

    fn interface_exists(&self, ifname: &IfName) -> PResult<bool> {
        self.call(Op::InterfaceExists, |st| {
            Ok(st
                .default_route
                .as_ref()
                .is_some_and(|r| &r.interface == ifname)
                || st.instances.get(ifname).is_some_and(|w| w.alive))
        })
    }

    fn route_add_host(&self, dest: IpAddr, gateway: Ipv4Addr) -> PResult<()> {
        self.call(Op::RouteAddHost, |st| {
            st.host_routes.insert(dest, gateway);
            Ok(())
        })
    }

    fn route_delete_host(&self, dest: IpAddr) -> PResult<()> {
        self.call(Op::RouteDeleteHost, |st| {
            st.host_routes.remove(&dest);
            Ok(())
        })
    }

    fn route_add_net(&self, net: IpNet, ifname: &IfName) -> PResult<()> {
        self.call(Op::RouteAddNet, |st| {
            st.live(Op::RouteAddNet, ifname)?;
            st.net_routes.insert((net, ifname.clone()));
            Ok(())
        })
    }

    fn route_delete_net(&self, net: IpNet, ifname: &IfName) -> PResult<()> {
        self.call(Op::RouteDeleteNet, |st| {
            st.net_routes.remove(&(net, ifname.clone()));
            Ok(())
        })
    }

    fn interface_configure(&self, ifname: &IfName, addresses: &[IpNet], mtu: u16) -> PResult<()> {
        self.call(Op::InterfaceConfigure, |st| {
            let wg = st.live(Op::InterfaceConfigure, ifname)?;
            wg.addresses = addresses.to_vec();
            wg.mtu = Some(mtu);
            wg.up = true;
            Ok(())
        })
    }

    fn dns_set(&self, servers: &[IpAddr]) -> PResult<()> {
        self.call(Op::DnsSet, |st| {
            st.dns = Some(servers.to_vec());
            Ok(())
        })
    }

    fn dns_clear(&self) -> PResult<()> {
        self.call(Op::DnsClear, |st| {
            st.dns = None;
            Ok(())
        })
    }

    fn wg_verify(&self) -> PResult<()> {
        self.call(Op::WgVerify, |st| {
            if st.binary_trusted {
                Ok(())
            } else {
                Err(PlatformError::new(
                    Op::WgVerify,
                    "wireguard-go is not pinned",
                ))
            }
        })
    }

    fn wg_spawn(&self) -> PResult<WgInstance> {
        self.call(Op::WgSpawn, |st| {
            if !st.binary_trusted {
                return Err(PlatformError::new(
                    Op::WgSpawn,
                    "wireguard-go is not pinned",
                ));
            }
            let ifname: IfName = format!("utun{}", st.next_unit)
                .parse()
                .map_err(|_| PlatformError::new(Op::WgSpawn, "bad name"))?;
            st.next_unit += 1;
            let pid = st.next_pid;
            st.next_pid += 1;
            st.instances.insert(
                ifname.clone(),
                FakeWg {
                    pid,
                    alive: true,
                    configured_key: None,
                    peer: None,
                    endpoint: None,
                    keepalive: 0,
                    handshake_at: None,
                    refreshes: 0,
                    addresses: Vec::new(),
                    mtu: None,
                    up: false,
                    rx: 0,
                    tx: 0,
                },
            );
            Ok(WgInstance { ifname, pid })
        })
    }

    fn wg_alive(&self, instance: &WgInstance) -> PResult<bool> {
        self.call(Op::WgAlive, |st| {
            Ok(st
                .instances
                .get(&instance.ifname)
                .is_some_and(|w| w.alive && w.pid == instance.pid))
        })
    }

    fn wg_stop(&self, ifname: Option<&IfName>) -> PResult<()> {
        self.call(Op::WgStop, |st| {
            let gone: Vec<IfName> = match ifname {
                Some(name) => vec![name.clone()],
                None => st.instances.keys().cloned().collect(),
            };
            for name in &gone {
                st.instances.remove(name);
            }
            st.net_routes.retain(|(_, i)| !gone.contains(i));
            Ok(())
        })
    }

    fn uapi_configure(&self, ifname: &IfName, config: &DeviceConfig<'_>) -> PResult<()> {
        self.call(Op::UapiConfigure, |st| {
            let wg = st.live(Op::UapiConfigure, ifname)?;
            wg.configured_key = Some(config.private_key.clone());
            wg.peer = Some(*config.peer);
            wg.endpoint = Some(config.endpoint);
            wg.keepalive = config.keepalive;
            st.handshake_now(ifname);
            Ok(())
        })
    }

    fn uapi_refresh(
        &self,
        ifname: &IfName,
        peer: &PublicKey,
        endpoint: SocketAddr,
        keepalive: u16,
    ) -> PResult<()> {
        self.call(Op::UapiRefresh, |st| {
            let wg = st.live(Op::UapiRefresh, ifname)?;
            if wg.peer.as_ref() != Some(peer) {
                return Err(PlatformError::new(Op::UapiRefresh, "unknown peer"));
            }
            wg.endpoint = Some(endpoint);
            wg.keepalive = keepalive;
            wg.refreshes += 1;
            st.handshake_now(ifname);
            Ok(())
        })
    }

    fn uapi_status(&self, ifname: &IfName) -> PResult<DeviceStatus> {
        self.call(Op::UapiStatus, |st| {
            let wall = st.wall;
            let mode = st.handshake;
            let wg = st.live(Op::UapiStatus, ifname)?;
            if mode == HandshakeMode::Immediate
                && wg.peer.is_some()
                && wg
                    .handshake_at
                    .is_none_or(|at| wall.saturating_sub(at) > 120_000)
            {
                wg.handshake_at = Some(wall);
            }
            Ok(DeviceStatus {
                last_handshake: wg.handshake_at.map(UnixMillis),
                rx_bytes: wg.rx,
                tx_bytes: wg.tx,
            })
        })
    }

    fn bind_socket(&self) -> PResult<UnixListener> {
        self.call(Op::BindSocket, |st| {
            let fail = |e: std::io::Error| PlatformError::new(Op::BindSocket, e.to_string());
            if st.socket_dir.is_none() {
                st.socket_dir = Some(TempDir::new("sock").map_err(fail)?);
            }
            let dir = st.socket_dir.as_ref().map(|d| d.path().to_path_buf());
            let path = dir.unwrap_or_default().join("vpnui.sock");
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).map_err(fail)?;
            st.socket_path = Some(path);
            Ok(listener)
        })
    }

    fn remove_socket(&self) -> PResult<()> {
        self.call(Op::RemoveSocket, |st| {
            if let Some(path) = st.socket_path.take() {
                let _ = std::fs::remove_file(path);
            }
            Ok(())
        })
    }

    fn service_bootout(&self) -> PResult<bool> {
        self.call(Op::ServiceBootout, |st| {
            let was = st.service_loaded;
            st.service_loaded = false;
            Ok(was)
        })
    }
}
