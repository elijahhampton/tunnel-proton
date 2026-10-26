//! Wire protocol between the unprivileged `vpnui` client and the daemon that owns the tunnel.
//!
//! Transport is newline-delimited JSON over a Unix domain socket. 
//! Note: Every enum that can grow in future protocol versions has an `Unknown` 
//! variant that unrecognized values decode into.

#![forbid(unsafe_code)]

mod framing;
mod ids;
mod messages;
mod types;

pub use framing::{
    DAEMON_SOCKET_PATH, MAX_LINE_BYTES, MAX_SOCKET_PATH_BYTES, ProtoError, codec, decode,
    default_socket_path, encode, mock_socket_path, validate_socket_path,
};
pub use ids::{ProtocolVersion, RequestId, ServerId, UnixMillis};
pub use messages::{
    Command, DaemonMessage, ErrorBody, ErrorCode, Event, LogLevel, Request, Response, Snapshot,
};
pub use types::{
    ConnectPhase, Feature, IpInfo, KillSwitchState, Server, Settings, SettingsPatch, Stats,
    TunnelState,
};

/// Protocol version spoken by this build. Bumped on any incompatible wire change.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(2);
