use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio_util::codec::LinesCodec;

/// Upper bound on one encoded message, excluding the trailing newline.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// macOS `sun_path` is 104 bytes including the NUL terminator.
pub const MAX_SOCKET_PATH_BYTES: usize = 103;

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("invalid JSON message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("encoded message is {len} bytes; the limit is {MAX_LINE_BYTES}")]
    TooLarge { len: usize },
    #[error(
        "socket path {path} is {len} bytes; Unix socket paths must be at most {MAX_SOCKET_PATH_BYTES} bytes"
    )]
    SocketPathTooLong { path: PathBuf, len: usize },
}

/// Line codec enforcing [`MAX_LINE_BYTES`]. `FramedRead` yields the error for an over-limit line
/// and then ends the stream, closing the connection.
pub fn codec() -> LinesCodec {
    LinesCodec::new_with_max_length(MAX_LINE_BYTES)
}

/// Serializes `msg` as a single line of compact JSON (no trailing newline).
pub fn encode<T: Serialize>(msg: &T) -> Result<String, ProtoError> {
    let line = serde_json::to_string(msg)?;
    if line.len() > MAX_LINE_BYTES {
        return Err(ProtoError::TooLarge { len: line.len() });
    }
    Ok(line)
}

pub fn decode<T: DeserializeOwned>(line: &str) -> Result<T, ProtoError> {
    Ok(serde_json::from_str(line)?)
}

/// Where `vpnuid` listens.
pub const DAEMON_SOCKET_PATH: &str = "/var/run/vpnui/vpnui.sock";

pub fn default_socket_path() -> PathBuf {
    PathBuf::from(DAEMON_SOCKET_PATH)
}

/// Default for the unprivileged mock daemon.
pub fn mock_socket_path() -> PathBuf {
    std::env::temp_dir().join("vpnui.sock")
}

pub fn validate_socket_path(path: &Path) -> Result<(), ProtoError> {
    let len = path.as_os_str().len();
    if len > MAX_SOCKET_PATH_BYTES {
        return Err(ProtoError::SocketPathTooLong {
            path: path.to_path_buf(),
            len,
        });
    }
    Ok(())
}
