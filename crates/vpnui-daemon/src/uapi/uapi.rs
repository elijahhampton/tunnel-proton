//! The WireGuard cross-platform userspace API (UAPI): newline-separated `key=value` lines over a
//! UNIX socket, a request ending with an empty line, a response ending with `errno=N` and an
//! empty line.
//!
//! A `get=1` response includes the device private key in hex, so responses are held in
//! zeroizing buffers and the parser never retains that line.

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use vpnui_proto::UnixMillis;
use zeroize::Zeroizing;

use crate::net::net::IpNet;
use crate::secret::{PublicKey, SecretKey};

pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UapiError {
    #[error("UAPI socket: {0}")]
    Io(String),
    #[error("UAPI returned errno={0}")]
    Errno(i64),
    #[error("UAPI response is malformed: {0}")]
    Malformed(&'static str),
}

/// Everything needed to configure the device and its single peer.
pub struct DeviceConfig<'a> {
    pub private_key: &'a SecretKey,
    pub peer: &'a PublicKey,
    pub preshared_key: Option<&'a SecretKey>,
    pub endpoint: SocketAddr,
    pub keepalive: u16,
    pub allowed_ips: &'a [IpNet],
}

/// `set=1` replacing every peer with `config.peer`.
pub fn encode_configure(config: &DeviceConfig<'_>) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(512));
    out.push_str("set=1\n");
    out.push_str("private_key=");
    out.push_str(&config.private_key.to_hex());
    out.push('\n');
    out.push_str("replace_peers=true\n");
    out.push_str(&format!("public_key={}\n", config.peer.to_hex()));
    if let Some(psk) = config.preshared_key {
        out.push_str("preshared_key=");
        out.push_str(&psk.to_hex());
        out.push('\n');
    }
    out.push_str(&format!("endpoint={}\n", config.endpoint));
    out.push_str(&format!(
        "persistent_keepalive_interval={}\n",
        config.keepalive
    ));
    out.push_str("replace_allowed_ips=true\n");
    for net in config.allowed_ips {
        out.push_str(&format!("allowed_ip={net}\n"));
    }
    out.push('\n');
    out
}

/// `set=1` re-sending the endpoint of an existing peer and toggling its keepalive off and on.
/// wireguard-go sends a keepalive immediately only when the interval changes from 0 to non-zero,
/// and that keepalive starts a handshake if the session has expired. `update_only` must follow
/// `public_key` directly.
pub fn encode_refresh(peer: &PublicKey, endpoint: SocketAddr, keepalive: u16) -> String {
    format!(
        "set=1\npublic_key={}\nupdate_only=true\nendpoint={endpoint}\n\
         persistent_keepalive_interval=0\npersistent_keepalive_interval={}\n\n",
        peer.to_hex(),
        keepalive.max(1)
    )
}

pub const GET_REQUEST: &str = "get=1\n\n";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceStatus {
    /// `None` until the first handshake completes.
    pub last_handshake: Option<UnixMillis>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

fn errno(response: &str) -> Result<(), UapiError> {
    let value = response
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix("errno="))
        .ok_or(UapiError::Malformed("no errno line"))?;
    let code: i64 = value
        .trim()
        .parse()
        .map_err(|_| UapiError::Malformed("errno is not a number"))?;
    if code == 0 {
        Ok(())
    } else {
        Err(UapiError::Errno(code))
    }
}

pub fn parse_set_response(response: &str) -> Result<(), UapiError> {
    errno(response)
}

pub fn parse_get_response(response: &str) -> Result<DeviceStatus, UapiError> {
    errno(response)?;
    let mut sec: u64 = 0;
    let mut nsec: u64 = 0;
    let mut status = DeviceStatus::default();
    for line in response.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let number = || {
            value
                .parse::<u64>()
                .map_err(|_| UapiError::Malformed("counter is not a number"))
        };
        match key {
            "last_handshake_time_sec" => sec = sec.max(number()?),
            "last_handshake_time_nsec" => nsec = number()?,
            "rx_bytes" => status.rx_bytes = status.rx_bytes.saturating_add(number()?),
            "tx_bytes" => status.tx_bytes = status.tx_bytes.saturating_add(number()?),
            _ => {}
        }
    }
    if sec > 0 {
        status.last_handshake = Some(UnixMillis(
            sec.saturating_mul(1000).saturating_add(nsec / 1_000_000),
        ));
    }
    Ok(status)
}

/// Sends `request` and reads the response up to and including the terminating empty line.
pub fn transact(
    socket: &Path,
    request: &str,
    timeout: Duration,
) -> Result<Zeroizing<String>, UapiError> {
    let io = |e: std::io::Error| UapiError::Io(e.to_string());
    let mut stream = UnixStream::connect(socket).map_err(io)?;
    stream.set_read_timeout(Some(timeout)).map_err(io)?;
    stream.set_write_timeout(Some(timeout)).map_err(io)?;
    stream.write_all(request.as_bytes()).map_err(io)?;
    stream.flush().map_err(io)?;

    let mut reader = BufReader::new(stream);
    let mut response = Zeroizing::new(String::new());
    loop {
        let mut line = Zeroizing::new(String::new());
        let read = reader.read_line(&mut line).map_err(io)?;
        if read == 0 {
            return Err(UapiError::Malformed(
                "connection closed before the response ended",
            ));
        }
        if line.as_str() == "\n" {
            break;
        }
        if response.len() + line.len() > MAX_RESPONSE_BYTES {
            return Err(UapiError::Malformed("response too large"));
        }
        response.push_str(&line);
    }
    Ok(response)
}
