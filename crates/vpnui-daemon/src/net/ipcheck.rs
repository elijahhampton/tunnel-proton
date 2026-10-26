//! Optional public-IP check: one HTTPS GET per connection, run as `nobody`, only while
//! connected. Off unless `--ip-check-url` is given.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Duration;

use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};
use vpnui_proto::{Event, TunnelState};

use crate::engine::engine::Input;
use crate::net::paths;
use crate::shared::Shared;

const TIMEOUT: Duration = Duration::from_secs(5);
const NOBODY: u32 = 4_294_967_294;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("--ip-check-url must be an https:// URL without spaces or control characters")]
pub struct BadUrl;

/// A URL safe to pass as one argv element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckUrl(String);

impl CheckUrl {
    pub fn parse(url: &str) -> Result<Self, BadUrl> {
        let ok = url.starts_with("https://")
            && url.len() > "https://".len()
            && url.len() <= 2048
            && url.chars().all(|c| c.is_ascii_graphic());
        if ok {
            Ok(Self(url.to_owned()))
        } else {
            Err(BadUrl)
        }
    }
}

pub fn parse_body(body: &str) -> Option<IpAddr> {
    body.trim().parse().ok()
}

pub async fn run(url: CheckUrl, shared: Arc<Shared>, inbox: Sender<Input>) {
    let (_, mut events) = shared.subscribe();
    loop {
        match events.recv().await {
            Ok(Event::TunnelChanged {
                tunnel: TunnelState::Connected { .. },
            }) => {
                let ip = fetch(&url).await;
                if let Some(ip) = ip {
                    info!(%ip, "public IP checked");
                    let _ = inbox.send(Input::PublicIp(Some(ip)));
                }
            }
            Ok(_) | Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => return,
        }
    }
}

async fn fetch(url: &CheckUrl) -> Option<IpAddr> {
    let output = tokio::time::timeout(
        TIMEOUT + Duration::from_secs(1),
        tokio::process::Command::new(paths::CURL)
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--proto",
                "=https",
                "--max-time",
                "5",
                "--max-filesize",
                "256",
                "--url",
            ])
            .arg(&url.0)
            .env_clear()
            .uid(NOBODY)
            .gid(NOBODY)
            .kill_on_drop(true)
            .output(),
    )
    .await;
    match output {
        Ok(Ok(out)) if out.status.success() => {
            let ip = parse_body(&String::from_utf8_lossy(&out.stdout));
            if ip.is_none() {
                warn!("IP check returned something other than a plain IP address");
            }
            ip
        }
        Ok(Ok(out)) => {
            warn!(status = %out.status, "IP check failed");
            None
        }
        Ok(Err(e)) => {
            warn!(%e, "IP check could not run");
            None
        }
        Err(_) => {
            warn!("IP check timed out");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_urls_without_spaces() {
        assert!(CheckUrl::parse("https://ip.example/plain").is_ok());
        for bad in [
            "http://ip.example",
            "https://",
            "https://a b",
            "file:///etc/passwd",
            "https://x\n",
            "-K /etc/x",
            "",
        ] {
            assert_eq!(CheckUrl::parse(bad), Err(BadUrl), "{bad:?}");
        }
    }

    #[test]
    fn parses_plain_ip_bodies() {
        assert_eq!(
            parse_body("198.51.100.7\n"),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(
            parse_body("2001:db8::7"),
            Some("2001:db8::7".parse().unwrap())
        );
        assert_eq!(parse_body("<html>"), None);
    }
}
