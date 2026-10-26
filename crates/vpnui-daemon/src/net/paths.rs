//! Every filesystem location the daemon uses.

use std::path::PathBuf;

pub const SERVICE_LABEL: &str = "dev.vpnui.daemon";

/// Fixed id for the synthetic SystemConfiguration service that carries the DNS override.
pub const DNS_SERVICE_ID: &str = "6A1C9E8B-3D4F-4E2A-9B7C-5D8E0F1A2B3C";

pub const PFCTL: &str = "/sbin/pfctl";
pub const ROUTE: &str = "/sbin/route";
pub const IFCONFIG: &str = "/sbin/ifconfig";
pub const SCUTIL: &str = "/usr/sbin/scutil";
pub const PS: &str = "/bin/ps";
pub const LAUNCHCTL: &str = "/bin/launchctl";
pub const CURL: &str = "/usr/bin/curl";

#[derive(Debug, Clone)]
pub struct Paths {
    pub runtime_dir: PathBuf,
    pub socket: PathBuf,
    pub wg_runtime: PathBuf,
    pub uapi_dir: PathBuf,
    pub db_dir: PathBuf,
    pub profiles_dir: PathBuf,
    pub state_file: PathBuf,
    pub install_file: PathBuf,
    pub libexec: PathBuf,
    pub plist: PathBuf,
    pub log_dir: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            runtime_dir: "/var/run/vpnui".into(),
            socket: vpnui_proto::DAEMON_SOCKET_PATH.into(),
            wg_runtime: "/var/run/vpnui/wg".into(),
            uapi_dir: "/var/run/wireguard".into(),
            db_dir: "/var/db/vpnui".into(),
            profiles_dir: "/var/db/vpnui/profiles".into(),
            state_file: "/var/db/vpnui/state.json".into(),
            install_file: "/var/db/vpnui/install.json".into(),
            libexec: "/usr/local/libexec/vpnui".into(),
            plist: format!("/Library/LaunchDaemons/{SERVICE_LABEL}.plist").into(),
            log_dir: "/var/log/vpnui".into(),
        }
    }
}

impl Paths {
    pub fn with_socket(mut self, socket: PathBuf) -> Self {
        if let Some(parent) = socket.parent() {
            self.runtime_dir = parent.to_path_buf();
        }
        self.socket = socket;
        self
    }

    pub fn pinned_wireguard_go(&self) -> PathBuf {
        self.libexec.join("wireguard-go")
    }

    pub fn pinned_vpnuid(&self) -> PathBuf {
        self.libexec.join("vpnuid")
    }

    pub fn wg_pidfile(&self) -> PathBuf {
        self.wg_runtime.join("wireguard-go.pid")
    }

    pub fn wg_name_file(&self) -> PathBuf {
        self.wg_runtime.join("utun.name")
    }
}
