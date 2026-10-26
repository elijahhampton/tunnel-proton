//! The boundary between the engine and the operating system. Every privileged or observable
//! action goes through [`Platform`]; [`crate::fake::FakePlatform`] implements it for tests and
//! [`crate::macos::MacPlatform`] for real.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixListener;

use serde::{Deserialize, Serialize};
use vpnui_proto::{ErrorCode, UnixMillis};

use crate::net::net::{DefaultRoute, IfName, IpNet};
use crate::policy;
use crate::profile::profile::Profile;
use crate::secret::PublicKey;
use crate::uapi::uapi::{DeviceConfig, DeviceStatus};
use crate::policy::policy::ANCHOR;
use crate::policy::policy::SELFTEST_ANCHOR;

/// Milliseconds on a clock that never jumps. On macOS it also stops while the machine sleeps,
/// which is how wake-ups are detected against the wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Mono(pub u64);

impl Mono {
    pub fn plus_ms(self, ms: u64) -> Self {
        Self(self.0.saturating_add(ms))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    pub wall: UnixMillis,
    pub mono: Mono,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Anchor {
    KillSwitch,
    SelfTest,
}

impl Anchor {
    pub fn name(self) -> &'static str {
        match self {
            Self::KillSwitch => ANCHOR,
            Self::SelfTest => SELFTEST_ANCHOR,
        }
    }
}

/// A pf enable reference from `pfctl -E`. Digits only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PfToken(String);

impl PfToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PfToken {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !value.is_empty() && value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err("pf token must be digits")
        }
    }
}

impl From<PfToken> for String {
    fn from(token: PfToken) -> Self {
        token.0
    }
}

impl fmt::Debug for PfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PfToken({})", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgInstance {
    pub ifname: IfName,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    LoadState,
    SaveState,
    LoadProfiles,
    PfLoad,
    PfFlush,
    PfFlushStates,
    PfEnable,
    PfRelease,
    PfStatus,
    PfDisable,
    PfCounters,
    Probe,
    DefaultRoute,
    InterfaceMtu,
    InterfaceExists,
    RouteAddHost,
    RouteDeleteHost,
    RouteAddNet,
    RouteDeleteNet,
    InterfaceConfigure,
    DnsSet,
    DnsClear,
    WgVerify,
    WgSpawn,
    WgAlive,
    WgStop,
    UapiConfigure,
    UapiRefresh,
    UapiStatus,
    BindSocket,
    RemoveSocket,
    ServiceBootout,
}

impl Op {
    pub fn error_code(self) -> ErrorCode {
        match self {
            Self::PfLoad
            | Self::PfFlush
            | Self::PfFlushStates
            | Self::PfEnable
            | Self::PfRelease
            | Self::PfStatus
            | Self::PfDisable
            | Self::PfCounters
            | Self::Probe => ErrorCode::PfFailed,
            Self::DefaultRoute
            | Self::RouteAddHost
            | Self::RouteDeleteHost
            | Self::RouteAddNet
            | Self::RouteDeleteNet => ErrorCode::RouteFailed,
            Self::DnsSet | Self::DnsClear => ErrorCode::DnsFailed,
            Self::WgVerify => ErrorCode::BinaryUntrusted,
            Self::InterfaceMtu
            | Self::InterfaceExists
            | Self::InterfaceConfigure
            | Self::WgSpawn
            | Self::WgAlive
            | Self::WgStop
            | Self::UapiConfigure
            | Self::UapiRefresh
            | Self::UapiStatus => ErrorCode::WgFailed,
            Self::LoadState
            | Self::SaveState
            | Self::LoadProfiles
            | Self::BindSocket
            | Self::RemoveSocket
            | Self::ServiceBootout => ErrorCode::Internal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{op:?}: {detail}")]
pub struct PlatformError {
    pub op: Op,
    pub detail: String,
}

impl PlatformError {
    pub fn new(op: Op, detail: impl Into<String>) -> Self {
        Self {
            op,
            detail: detail.into(),
        }
    }
}

pub type PResult<T> = Result<T, PlatformError>;

pub trait Platform: Send + 'static {
    fn now(&self) -> Now;

    fn load_state(&self) -> PResult<Option<String>>;
    fn save_state(&self, json: &str) -> PResult<()>;
    fn load_profiles(&self) -> PResult<Vec<Profile>>;

    /// Atomically replaces the anchor's ruleset (`pfctl -a <anchor> -f -`).
    fn pf_load(&self, anchor: Anchor, ruleset: &str) -> PResult<()>;
    fn pf_flush(&self, anchor: Anchor) -> PResult<()>;
    fn pf_flush_states(&self) -> PResult<()>;
    fn pf_enable(&self) -> PResult<PfToken>;
    /// Tolerates a token the kernel no longer knows.
    fn pf_release(&self, token: &PfToken) -> PResult<()>;
    fn pf_is_enabled(&self) -> PResult<bool>;
    fn pf_disable(&self) -> PResult<()>;
    fn pf_anchor_packets(&self, anchor: Anchor) -> PResult<u64>;
    /// One UDP datagram to 192.0.2.1:9 for the pf self-test.
    fn send_probe(&self) -> PResult<()>;

    fn default_route(&self) -> PResult<Option<DefaultRoute>>;
    fn interface_mtu(&self, ifname: &IfName) -> PResult<Option<u16>>;
    fn interface_exists(&self, ifname: &IfName) -> PResult<bool>;
    /// Replaces any existing host route to `dest`.
    fn route_add_host(&self, dest: IpAddr, gateway: Ipv4Addr) -> PResult<()>;
    /// Tolerates a route that is already gone.
    fn route_delete_host(&self, dest: IpAddr) -> PResult<()>;
    fn route_add_net(&self, net: IpNet, ifname: &IfName) -> PResult<()>;
    /// Tolerates a route that is already gone.
    fn route_delete_net(&self, net: IpNet, ifname: &IfName) -> PResult<()>;
    /// Assigns addresses and MTU and brings the interface up, as wg-quick does on macOS.
    fn interface_configure(&self, ifname: &IfName, addresses: &[IpNet], mtu: u16) -> PResult<()>;

    fn dns_set(&self, servers: &[IpAddr]) -> PResult<()>;
    /// Tolerates an override that is already gone.
    fn dns_clear(&self) -> PResult<()>;

    /// Checks the pinned wireguard-go binary (hash and ownership) without running it.
    fn wg_verify(&self) -> PResult<()>;
    fn wg_spawn(&self) -> PResult<WgInstance>;
    fn wg_alive(&self, instance: &WgInstance) -> PResult<bool>;
    /// Stops our wireguard-go: the current child, or an orphan whose pidfile and executable path
    /// match. Tolerates one that is already gone.
    fn wg_stop(&self, ifname: Option<&IfName>) -> PResult<()>;
    fn uapi_configure(&self, ifname: &IfName, config: &DeviceConfig<'_>) -> PResult<()>;
    fn uapi_refresh(
        &self,
        ifname: &IfName,
        peer: &PublicKey,
        endpoint: SocketAddr,
        keepalive: u16,
    ) -> PResult<()>;
    fn uapi_status(&self, ifname: &IfName) -> PResult<DeviceStatus>;

    fn bind_socket(&self) -> PResult<UnixListener>;
    fn remove_socket(&self) -> PResult<()>;
    /// `launchctl bootout` of the installed service. Returns whether it was loaded.
    fn service_bootout(&self) -> PResult<bool>;
}
