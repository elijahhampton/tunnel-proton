//! A minimal blocking client for the CLI subcommands that talk to a running daemon.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use vpnui_proto::{
    Command, DaemonMessage, Event, PROTOCOL_VERSION, Request, RequestId, Snapshot, decode, encode,
};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach vpnuid at {path}: {reason}")]
    Connect { path: String, reason: String },
    #[error("daemon: {0}")]
    Daemon(String),
    #[error("protocol: {0}")]
    Protocol(String),
}

pub struct Client {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
    next: u64,
}

impl Client {
    pub fn connect(path: &Path) -> Result<Self, ClientError> {
        let fail = |e: std::io::Error| ClientError::Connect {
            path: path.display().to_string(),
            reason: e.to_string(),
        };
        let stream = UnixStream::connect(path).map_err(fail)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(fail)?;
        let reader = BufReader::new(stream.try_clone().map_err(fail)?);
        let mut client = Self {
            writer: stream,
            reader,
            next: 1,
        };
        client.call(Command::Hello {
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: PROTOCOL_VERSION,
        })?;
        Ok(client)
    }

    fn read(&mut self) -> Result<DaemonMessage, ClientError> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        if n == 0 {
            return Err(ClientError::Protocol("daemon closed the connection".into()));
        }
        decode(line.trim_end()).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// Sends a command and waits for its response, skipping events.
    pub fn call(&mut self, cmd: Command) -> Result<(), ClientError> {
        let id = RequestId(self.next);
        self.next += 1;
        let line =
            encode(&Request { id, cmd }).map_err(|e| ClientError::Protocol(e.to_string()))?;
        writeln!(self.writer, "{line}").map_err(|e| ClientError::Protocol(e.to_string()))?;
        loop {
            match self.read()? {
                DaemonMessage::Response(r) if r.id == id || r.id == RequestId(0) => {
                    return match r.error {
                        None => Ok(()),
                        Some(e) => Err(ClientError::Daemon(format!(
                            "{}: {}",
                            e.code.as_str(),
                            e.message
                        ))),
                    };
                }
                DaemonMessage::Response(_) | DaemonMessage::Event { .. } => {}
            }
        }
    }

    pub fn snapshot(&mut self) -> Result<Snapshot, ClientError> {
        self.call(Command::Subscribe)?;
        loop {
            if let DaemonMessage::Event {
                event: Event::Snapshot(snapshot),
            } = self.read()?
            {
                return Ok(*snapshot);
            }
        }
    }
}
