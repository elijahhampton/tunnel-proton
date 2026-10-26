//! The real [`Platform`] for macOS: pfctl, route, ifconfig, scutil, and a pinned wireguard-go.
//! Nothing here can be exercised without root; see docs/MANUAL_TEST.md.

use std::fs::{self, Permissions};
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use vpnui_proto::UnixMillis;
use zeroize::Zeroizing;

use crate::exec::{Cmd, ExecError, Guarded};
use crate::net::net::{DefaultRoute, IfName, IpNet};
use crate::net::paths::{self, DNS_SERVICE_ID, Paths};
use crate::platform::{
    Anchor, Mono, Now, Op, PResult, PfToken, Platform, PlatformError, WgInstance,
};
use crate::profile::profile::Profile;
use crate::secret::PublicKey;
use crate::store::store::{ProfileStore, atomic_write, read_secret_file};
use crate::trust::{self, Pinned};
use crate::uapi::uapi::{self, DeviceConfig, DeviceStatus};

const NAME_FILE_WAIT: Duration = Duration::from_secs(5);
const STOP_WAIT: Duration = Duration::from_secs(2);
const UAPI_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_STATE_BYTES: u64 = 1024 * 1024;

pub struct MacPlatform {
    paths: Paths,
    wireguard: Option<Pinned>,
    store: ProfileStore,
    socket_gid: Option<u32>,
    started: Instant,
    child: Mutex<Option<Guarded>>,
    dns_session: Mutex<Option<Guarded>>,
}

fn err(op: Op) -> impl Fn(ExecError) -> PlatformError {
    move |e| PlatformError::new(op, e.to_string())
}

fn io_err(op: Op) -> impl Fn(std::io::Error) -> PlatformError {
    move |e| PlatformError::new(op, e.to_string())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl MacPlatform {
    /// `socket_gid` is the group allowed to open the socket (the installed user's group).
    pub fn new(paths: Paths, wireguard: Option<Pinned>, socket_gid: Option<u32>) -> Self {
        Self {
            store: ProfileStore::new(paths.profiles_dir.clone(), 0),
            paths,
            wireguard,
            socket_gid,
            started: Instant::now(),
            child: Mutex::new(None),
            dns_session: Mutex::new(None),
        }
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    fn ensure_private_dir(&self, op: Op, dir: &Path) -> PResult<()> {
        match fs::symlink_metadata(dir) {
            Ok(meta) => {
                if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != 0 {
                    return Err(PlatformError::new(
                        op,
                        format!("{} must be a root-owned directory", dir.display()),
                    ));
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                fs::create_dir_all(dir).map_err(io_err(op))?;
            }
            Err(e) => return Err(io_err(op)(e)),
        }
        fs::set_permissions(dir, Permissions::from_mode(0o700)).map_err(io_err(op))
    }

    fn uapi_socket(&self, ifname: &IfName) -> PathBuf {
        self.paths.uapi_dir.join(format!("{ifname}.sock"))
    }

    fn pf(&self, op: Op, args: &[&str]) -> PResult<crate::exec::Output> {
        Cmd::new(paths::PFCTL)
            .args(args.iter().copied())
            .run()
            .map_err(err(op))
    }

    fn scutil(&self, op: Op, script: String) -> PResult<crate::exec::Output> {
        Cmd::new(paths::SCUTIL)
            .stdin(Zeroizing::new(script.into_bytes()))
            .output()
            .map_err(err(op))
    }

    fn dns_key() -> String {
        format!("State:/Network/Service/{DNS_SERVICE_ID}/DNS")
    }

    /// The executable path of `pid`, as `ps` reports it.
    fn exe_of(pid: u32) -> Option<PathBuf> {
        let out = Cmd::new(paths::PS)
            .args(["-o", "comm=", "-p"])
            .arg(pid.to_string())
            .run()
            .ok()?;
        let line = out.stdout.trim();
        (!line.is_empty()).then(|| PathBuf::from(line))
    }

    fn stop_pid(pid: u32) -> bool {
        let Ok(raw) = i32::try_from(pid) else {
            return false;
        };
        let target = Pid::from_raw(raw);
        if kill(target, Signal::SIGTERM).is_err() {
            return true;
        }
        let deadline = Instant::now() + STOP_WAIT;
        while Instant::now() < deadline {
            if kill(target, None).is_err() {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        kill(target, Signal::SIGKILL).is_ok()
    }
}

impl Platform for MacPlatform {
    fn now(&self) -> Now {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let mono = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Now {
            wall: UnixMillis(wall),
            mono: Mono(mono),
        }
    }

    fn load_state(&self) -> PResult<Option<String>> {
        match read_secret_file(&self.paths.state_file, MAX_STATE_BYTES) {
            Ok(bytes) => String::from_utf8(bytes.to_vec())
                .map(Some)
                .map_err(|_| PlatformError::new(Op::LoadState, "state file is not UTF-8")),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(Op::LoadState)(e)),
        }
    }

    fn save_state(&self, json: &str) -> PResult<()> {
        self.ensure_private_dir(Op::SaveState, &self.paths.db_dir)?;
        atomic_write(&self.paths.state_file, json.as_bytes(), 0o600).map_err(io_err(Op::SaveState))
    }

    fn load_profiles(&self) -> PResult<Vec<Profile>> {
        self.store
            .list()
            .map_err(|e| PlatformError::new(Op::LoadProfiles, e.to_string()))
    }

    fn pf_load(&self, anchor: Anchor, ruleset: &str) -> PResult<()> {
        Cmd::new(paths::PFCTL)
            .args(["-a", anchor.name(), "-f", "-"])
            .stdin(Zeroizing::new(ruleset.as_bytes().to_vec()))
            .run()
            .map(|_| ())
            .map_err(err(Op::PfLoad))
    }

    fn pf_flush(&self, anchor: Anchor) -> PResult<()> {
        self.pf(Op::PfFlush, &["-a", anchor.name(), "-F", "all"])
            .map(|_| ())
    }

    fn pf_flush_states(&self) -> PResult<()> {
        self.pf(Op::PfFlushStates, &["-F", "states"]).map(|_| ())
    }

    fn pf_enable(&self) -> PResult<PfToken> {
        let out = self.pf(Op::PfEnable, &["-E"])?;
        parse_pf_token(&out.combined())
            .ok_or_else(|| PlatformError::new(Op::PfEnable, "pfctl -E printed no token"))
    }

    fn pf_release(&self, token: &PfToken) -> PResult<()> {
        if let Err(e) = self.pf(Op::PfRelease, &["-X", token.as_str()]) {
            tracing::warn!(%e, "pf token release failed; it may already be gone");
        }
        Ok(())
    }

    fn pf_is_enabled(&self) -> PResult<bool> {
        let out = self.pf(Op::PfStatus, &["-s", "info"])?;
        Ok(parse_pf_enabled(&out.combined()))
    }

    fn pf_disable(&self) -> PResult<()> {
        self.pf(Op::PfDisable, &["-d"]).map(|_| ())
    }

    fn pf_anchor_packets(&self, anchor: Anchor) -> PResult<u64> {
        let out = self.pf(Op::PfCounters, &["-a", anchor.name(), "-v", "-s", "rules"])?;
        Ok(parse_rule_packets(&out.stdout))
    }

    fn send_probe(&self) -> PResult<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(io_err(Op::Probe))?;
        let _ = socket.send_to(b"vpnui doctor probe", "192.0.2.1:9");
        Ok(())
    }

    fn default_route(&self) -> PResult<Option<DefaultRoute>> {
        let out = Cmd::new(paths::ROUTE)
            .args(["-n", "get", "default"])
            .output()
            .map_err(err(Op::DefaultRoute))?;
        if !out.status.success() {
            return Ok(None);
        }
        let Some((gateway, interface)) = parse_route_get(&out.stdout) else {
            return Ok(None);
        };
        let address = Cmd::new(paths::IFCONFIG)
            .arg(interface.as_str())
            .run()
            .ok()
            .and_then(|o| parse_ifconfig_inet(&o.stdout));
        Ok(Some(DefaultRoute {
            gateway,
            interface,
            address,
        }))
    }

    fn interface_mtu(&self, ifname: &IfName) -> PResult<Option<u16>> {
        let out = Cmd::new(paths::IFCONFIG)
            .arg(ifname.as_str())
            .run()
            .map_err(err(Op::InterfaceMtu))?;
        Ok(parse_ifconfig_mtu(&out.stdout))
    }

    fn interface_exists(&self, ifname: &IfName) -> PResult<bool> {
        let out = Cmd::new(paths::IFCONFIG)
            .arg(ifname.as_str())
            .output()
            .map_err(err(Op::InterfaceExists))?;
        Ok(out.status.success())
    }

    fn route_add_host(&self, dest: IpAddr, gateway: Ipv4Addr) -> PResult<()> {
        let add = || {
            Cmd::new(paths::ROUTE)
                .args(["-q", "-n", "add", family(dest)])
                .arg(dest.to_string())
                .arg("-gateway")
                .arg(gateway.to_string())
                .output()
                .map_err(err(Op::RouteAddHost))
        };
        let out = add()?;
        if out.status.success() {
            return Ok(());
        }
        if out.combined().contains("File exists") {
            self.route_delete_host(dest)?;
            let retry = add()?;
            if retry.status.success() {
                return Ok(());
            }
            return Err(PlatformError::new(
                Op::RouteAddHost,
                retry.combined().trim().to_owned(),
            ));
        }
        Err(PlatformError::new(
            Op::RouteAddHost,
            out.combined().trim().to_owned(),
        ))
    }

    fn route_delete_host(&self, dest: IpAddr) -> PResult<()> {
        let out = Cmd::new(paths::ROUTE)
            .args(["-q", "-n", "delete", family(dest)])
            .arg(dest.to_string())
            .output()
            .map_err(err(Op::RouteDeleteHost))?;
        tolerate_missing(Op::RouteDeleteHost, &out)
    }

    fn route_add_net(&self, net: IpNet, ifname: &IfName) -> PResult<()> {
        Cmd::new(paths::ROUTE)
            .args(["-q", "-n", "add", family(net.addr)])
            .arg(net.to_string())
            .args(["-interface", ifname.as_str()])
            .run()
            .map(|_| ())
            .map_err(err(Op::RouteAddNet))
    }

    fn route_delete_net(&self, net: IpNet, ifname: &IfName) -> PResult<()> {
        let out = Cmd::new(paths::ROUTE)
            .args(["-q", "-n", "delete", family(net.addr)])
            .arg(net.to_string())
            .args(["-interface", ifname.as_str()])
            .output()
            .map_err(err(Op::RouteDeleteNet))?;
        tolerate_missing(Op::RouteDeleteNet, &out)
    }

    fn interface_configure(&self, ifname: &IfName, addresses: &[IpNet], mtu: u16) -> PResult<()> {
        for net in addresses {
            let cmd = match net.addr {
                IpAddr::V4(addr) => Cmd::new(paths::IFCONFIG)
                    .args([ifname.as_str(), "inet"])
                    .arg(net.to_string())
                    .arg(addr.to_string())
                    .arg("alias"),
                IpAddr::V6(_) => Cmd::new(paths::IFCONFIG)
                    .args([ifname.as_str(), "inet6"])
                    .arg(net.to_string())
                    .arg("alias"),
            };
            cmd.run().map_err(err(Op::InterfaceConfigure))?;
        }
        Cmd::new(paths::IFCONFIG)
            .args([ifname.as_str(), "mtu"])
            .arg(mtu.to_string())
            .arg("up")
            .run()
            .map(|_| ())
            .map_err(err(Op::InterfaceConfigure))
    }

    fn dns_set(&self, servers: &[IpAddr]) -> PResult<()> {
        self.dns_clear()?;
        let mut child = Command::new(paths::SCUTIL)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(io_err(Op::DnsSet))?;
        let script = dns_script(servers);
        let written = child.stdin.as_mut().map(|stdin| {
            stdin
                .write_all(script.as_bytes())
                .and_then(|()| stdin.flush())
        });
        let mut guarded = Guarded::new(child);
        if !matches!(written, Some(Ok(()))) {
            return Err(PlatformError::new(Op::DnsSet, "could not write to scutil"));
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let shown = self.scutil(Op::DnsSet, format!("show {}\nquit\n", Self::dns_key()))?;
            if shown.stdout.contains("ServerAddresses") {
                break;
            }
            if Instant::now() >= deadline
                || guarded
                    .child()
                    .is_some_and(|c| matches!(c.try_wait(), Ok(Some(_))))
            {
                return Err(PlatformError::new(
                    Op::DnsSet,
                    "the DNS override did not appear",
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
        *lock(&self.dns_session) = Some(guarded);
        Ok(())
    }

    fn dns_clear(&self) -> PResult<()> {
        if let Some(mut session) = lock(&self.dns_session).take()
            && let Some(child) = session.child()
        {
            drop(child.stdin.take());
            let _ = child.wait();
        }
        let out = self.scutil(Op::DnsClear, format!("remove {}\nquit\n", Self::dns_key()))?;
        let text = out.combined();
        if out.status.success() || text.contains("No such key") {
            Ok(())
        } else {
            Err(PlatformError::new(Op::DnsClear, text.trim().to_owned()))
        }
    }

    fn wg_verify(&self) -> PResult<()> {
        let pinned = self.wireguard.as_ref().ok_or_else(|| {
            PlatformError::new(
                Op::WgVerify,
                "no pinned wireguard-go; run: sudo vpnuid install",
            )
        })?;
        trust::verify(pinned, &[0]).map_err(|e| PlatformError::new(Op::WgVerify, e.to_string()))
    }

    fn wg_spawn(&self) -> PResult<WgInstance> {
        self.wg_verify()
            .map_err(|e| PlatformError::new(Op::WgSpawn, e.detail))?;
        let pinned = self
            .wireguard
            .as_ref()
            .ok_or_else(|| PlatformError::new(Op::WgSpawn, "no pinned wireguard-go"))?;
        self.ensure_private_dir(Op::WgSpawn, &self.paths.wg_runtime)?;
        let name_file = self.paths.wg_name_file();
        let _ = fs::remove_file(&name_file);

        let child = Command::new(&pinned.path)
            .args(["-f", "utun"])
            .env_clear()
            .env("WG_TUN_NAME_FILE", &name_file)
            .env("LOG_LEVEL", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(io_err(Op::WgSpawn))?;
        let pid = child.id();
        let mut guarded = Guarded::new(child);
        atomic_write(
            &self.paths.wg_pidfile(),
            format!("{pid}\n").as_bytes(),
            0o600,
        )
        .map_err(io_err(Op::WgSpawn))?;

        let deadline = Instant::now() + NAME_FILE_WAIT;
        let ifname = loop {
            if let Ok(text) = fs::read_to_string(&name_file)
                && let Ok(name) = text.trim().parse::<IfName>()
            {
                break name;
            }
            let exited = guarded
                .child()
                .is_some_and(|c| matches!(c.try_wait(), Ok(Some(_))));
            if exited || Instant::now() >= deadline {
                return Err(PlatformError::new(
                    Op::WgSpawn,
                    "wireguard-go did not report an interface within 5s",
                ));
            }
            thread::sleep(Duration::from_millis(25));
        };
        if !ifname.is_tunnel() {
            return Err(PlatformError::new(
                Op::WgSpawn,
                "wireguard-go reported a non-utun interface",
            ));
        }
        let socket = self.uapi_socket(&ifname);
        while !fs::symlink_metadata(&socket).is_ok_and(|m| m.file_type().is_socket()) {
            if Instant::now() >= deadline {
                return Err(PlatformError::new(
                    Op::WgSpawn,
                    "wireguard-go did not open its UAPI socket",
                ));
            }
            thread::sleep(Duration::from_millis(25));
        }
        *lock(&self.child) = Some(guarded);
        Ok(WgInstance { ifname, pid })
    }

    fn wg_alive(&self, instance: &WgInstance) -> PResult<bool> {
        let mut guard = lock(&self.child);
        let Some(child) = guard.as_mut().and_then(Guarded::child) else {
            return Ok(false);
        };
        Ok(child.id() == instance.pid && matches!(child.try_wait(), Ok(None)))
    }

    fn wg_stop(&self, ifname: Option<&IfName>) -> PResult<()> {
        if let Some(ifname) = ifname {
            let _ = fs::remove_file(self.uapi_socket(ifname));
        }
        if let Some(mut guarded) = lock(&self.child).take() {
            if let Some(child) = guarded.child() {
                let deadline = Instant::now() + STOP_WAIT;
                while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(25));
                }
                if matches!(child.try_wait(), Ok(None)) {
                    let pid = child.id();
                    Self::stop_pid(pid);
                    let _ = child.wait();
                }
            }
            guarded.take();
        } else if let Ok(text) = fs::read_to_string(self.paths.wg_pidfile())
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            let pinned = self.wireguard.as_ref().map(|p| p.path.clone());
            let ours = Self::exe_of(pid).is_some_and(|exe| Some(&exe) == pinned.as_ref());
            if ours {
                Self::stop_pid(pid);
            } else {
                tracing::warn!(
                    pid,
                    "pidfile does not point at the pinned wireguard-go; leaving it"
                );
            }
        }
        let _ = fs::remove_file(self.paths.wg_pidfile());
        let _ = fs::remove_file(self.paths.wg_name_file());
        Ok(())
    }

    fn uapi_configure(&self, ifname: &IfName, config: &DeviceConfig<'_>) -> PResult<()> {
        let request = uapi::encode_configure(config);
        let response = uapi::transact(&self.uapi_socket(ifname), &request, UAPI_TIMEOUT)
            .map_err(|e| PlatformError::new(Op::UapiConfigure, e.to_string()))?;
        uapi::parse_set_response(&response)
            .map_err(|e| PlatformError::new(Op::UapiConfigure, e.to_string()))
    }

    fn uapi_refresh(
        &self,
        ifname: &IfName,
        peer: &PublicKey,
        endpoint: SocketAddr,
        keepalive: u16,
    ) -> PResult<()> {
        let request = uapi::encode_refresh(peer, endpoint, keepalive);
        let response = uapi::transact(&self.uapi_socket(ifname), &request, UAPI_TIMEOUT)
            .map_err(|e| PlatformError::new(Op::UapiRefresh, e.to_string()))?;
        uapi::parse_set_response(&response)
            .map_err(|e| PlatformError::new(Op::UapiRefresh, e.to_string()))
    }

    fn uapi_status(&self, ifname: &IfName) -> PResult<DeviceStatus> {
        let response = uapi::transact(&self.uapi_socket(ifname), uapi::GET_REQUEST, UAPI_TIMEOUT)
            .map_err(|e| PlatformError::new(Op::UapiStatus, e.to_string()))?;
        uapi::parse_get_response(&response)
            .map_err(|e| PlatformError::new(Op::UapiStatus, e.to_string()))
    }

    fn bind_socket(&self) -> PResult<UnixListener> {
        let dir = &self.paths.runtime_dir;
        self.ensure_private_dir(Op::BindSocket, dir)?;
        let socket = &self.paths.socket;
        match fs::symlink_metadata(socket) {
            Ok(meta) if meta.file_type().is_socket() => {
                if UnixStream::connect(socket).is_ok() {
                    return Err(PlatformError::new(
                        Op::BindSocket,
                        "another vpnuid is already running",
                    ));
                }
                fs::remove_file(socket).map_err(io_err(Op::BindSocket))?;
            }
            Ok(_) => {
                return Err(PlatformError::new(
                    Op::BindSocket,
                    format!("{} exists and is not a socket", socket.display()),
                ));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(Op::BindSocket)(e)),
        }
        let listener = UnixListener::bind(socket).map_err(io_err(Op::BindSocket))?;
        if let Some(gid) = self.socket_gid {
            std::os::unix::fs::chown(socket, Some(0), Some(gid)).map_err(io_err(Op::BindSocket))?;
        }
        fs::set_permissions(socket, Permissions::from_mode(0o660))
            .map_err(io_err(Op::BindSocket))?;
        fs::set_permissions(dir, Permissions::from_mode(0o755)).map_err(io_err(Op::BindSocket))?;
        Ok(listener)
    }

    fn remove_socket(&self) -> PResult<()> {
        match fs::remove_file(&self.paths.socket) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(Op::RemoveSocket)(e)),
        }
    }

    fn service_bootout(&self) -> PResult<bool> {
        if !self.paths.plist.exists() {
            return Ok(false);
        }
        let target = format!("system/{}", paths::SERVICE_LABEL);
        let out = Cmd::new(paths::LAUNCHCTL)
            .args(["bootout", target.as_str()])
            .output()
            .map_err(err(Op::ServiceBootout))?;
        Ok(out.status.success())
    }
}

fn family(addr: IpAddr) -> &'static str {
    if addr.is_ipv4() { "-inet" } else { "-inet6" }
}

fn tolerate_missing(op: Op, out: &crate::exec::Output) -> PResult<()> {
    let text = out.combined();
    if out.status.success() || text.contains("not in table") {
        Ok(())
    } else {
        Err(PlatformError::new(op, text.trim().to_owned()))
    }
}

/// Input for the scutil session that holds the override. `add ... temporary` keys live only as
/// long as that scutil process, which exits when the daemon's end of its stdin closes.
pub fn dns_script(servers: &[IpAddr]) -> String {
    let addresses: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
    format!(
        "d.init\nd.add ServerAddresses * {}\nd.add SupplementalMatchDomains * \"\"\n\
         d.add SupplementalMatchOrders * # 1\nadd State:/Network/Service/{DNS_SERVICE_ID}/DNS temporary\n",
        addresses.join(" ")
    )
}

pub fn parse_pf_token(text: &str) -> Option<PfToken> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("Token").map(str::trim))
        .and_then(|rest| rest.strip_prefix(':'))
        .map(str::trim)
        .and_then(|digits| PfToken::try_from(digits.to_owned()).ok())
}

pub fn parse_pf_enabled(text: &str) -> bool {
    text.lines()
        .any(|l| l.trim_start().starts_with("Status: Enabled"))
}

pub fn parse_rule_packets(text: &str) -> u64 {
    text.split("Packets:")
        .skip(1)
        .filter_map(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
        .sum()
}

pub fn parse_route_get(text: &str) -> Option<(Ipv4Addr, IfName)> {
    let field = |name: &str| {
        text.lines().find_map(|l| {
            l.trim()
                .strip_prefix(name)
                .map(str::trim)
                .map(str::to_owned)
        })
    };
    let gateway = field("gateway:")?.parse::<Ipv4Addr>().ok()?;
    let interface = field("interface:")?.parse::<IfName>().ok()?;
    Some((gateway, interface))
}

pub fn parse_ifconfig_inet(text: &str) -> Option<Ipv4Addr> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("inet "))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|a| a.parse().ok())
}

pub fn parse_ifconfig_mtu(text: &str) -> Option<u16> {
    text.split("mtu ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|m| m.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE_GET: &str = "   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";

    #[test]
    fn parses_route_get_default() {
        assert_eq!(
            parse_route_get(ROUTE_GET),
            Some((Ipv4Addr::new(192, 168, 1, 1), "en0".parse().unwrap()))
        );
        assert_eq!(
            parse_route_get("route: writing to routing socket: not in table\n"),
            None
        );
        assert_eq!(
            parse_route_get(&ROUTE_GET.replace("192.168.1.1", "link#14")),
            None
        );
        assert_eq!(
            parse_route_get(&ROUTE_GET.replace("en0", "en0; rm -rf /")),
            None
        );
    }

    #[test]
    fn parses_ifconfig() {
        let text = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                    \toptions=6460<TSO4,TSO6,CHANNEL_IO>\n\tether 00:00:5e:00:53:01\n\
                    \tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0xb\n\
                    \tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255\n";
        assert_eq!(parse_ifconfig_mtu(text), Some(1500));
        assert_eq!(
            parse_ifconfig_inet(text),
            Some(Ipv4Addr::new(192, 168, 1, 23))
        );
        assert_eq!(
            parse_ifconfig_inet("utun4: flags=8051<UP> mtu 1420\n"),
            None
        );
    }

    #[test]
    fn parses_pfctl_output() {
        let enabled = "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 1234567890123\n";
        assert_eq!(
            parse_pf_token(enabled).map(|t| t.as_str().to_owned()),
            Some("1234567890123".to_owned())
        );
        assert_eq!(parse_pf_token("pf already enabled\n"), None);
        assert_eq!(
            parse_pf_token("Token : 12; rm -rf /\n"),
            None,
            "tokens are digits only"
        );

        assert!(parse_pf_enabled(
            "Status: Enabled for 0 days 00:01:02           Debug: Urgent\n"
        ));
        assert!(!parse_pf_enabled(
            "Status: Disabled                              Debug: Urgent\n"
        ));

        let rules = "block drop quick proto udp from any to 192.0.2.1 port = 9\n  \
                     [ Evaluations: 12        Packets: 3         Bytes: 87          States: 0     ]\n  \
                     [ Inserted: uid 0 pid 1234 State Creations: 0     ]\n";
        assert_eq!(parse_rule_packets(rules), 3);
        assert_eq!(parse_rule_packets(""), 0);
    }

    #[test]
    fn dns_script_uses_typed_values_only() {
        let script = dns_script(&["10.2.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]);
        assert_eq!(
            script,
            format!(
                "d.init\nd.add ServerAddresses * 10.2.0.1 fd00::1\nd.add SupplementalMatchDomains * \"\"\n\
                 d.add SupplementalMatchOrders * # 1\nadd State:/Network/Service/{DNS_SERVICE_ID}/DNS temporary\n"
            )
        );
    }
}
