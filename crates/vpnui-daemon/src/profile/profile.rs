//! Strict parser for WireGuard `.conf` files and the profile identity derived from them.
//!
//! Error messages name keys and line numbers but never echo values, so a parse failure cannot
//! print key material.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use sha2::{Digest, Sha256};
use vpnui_proto::UnixMillis;

use crate::country;
use crate::net::net::IpNet;
use crate::secret::{PublicKey, SecretKey, hex};

const MAX_NAME_LEN: usize = 64;
const MIN_MTU: u16 = 1280;
const MAX_MTU: u16 = 9000;

/// Keys that make wg-quick run commands or touch routing tables as root.
const HARD_REJECT: &[&str] = &[
    "PreUp",
    "PostUp",
    "PreDown",
    "PostDown",
    "SaveConfig",
    "Table",
    "FwMark",
];

#[derive(Debug, Clone)]
pub struct Interface {
    pub private_key: SecretKey,
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub public_key: PublicKey,
    pub preshared_key: Option<SecretKey>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: SocketAddr,
    pub persistent_keepalive: Option<u16>,
}

/// A parsed config before it is named and stored.
#[derive(Debug, Clone)]
pub struct ParsedConfig {
    pub interface: Interface,
    pub peer: Peer,
    /// The first full-line comment inside `[Peer]`, e.g. `CO#4`.
    pub peer_comment: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub imported_at: UnixMillis,
    pub interface: Interface,
    pub peer: Peer,
}

impl Profile {
    pub fn endpoint(&self) -> SocketAddr {
        self.peer.endpoint
    }

    pub fn country_name(&self) -> Option<&'static str> {
        self.country_code
            .as_deref()
            .and_then(country::lookup)
            .map(|c| c.name)
    }

    /// Whether AllowedIPs sends all IPv4 traffic through the tunnel.
    pub fn is_full_tunnel(&self) -> bool {
        self.peer
            .allowed_ips
            .iter()
            .any(|n| n.is_default() && n.is_ipv4())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: Option<usize>,
    pub kind: ParseErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    HardRejected(&'static str),
    OutsideSection,
    UnknownSection,
    DuplicateSection(&'static str),
    MultiplePeers,
    MissingSection(&'static str),
    MissingKey(&'static str),
    DuplicateKey(&'static str),
    NotKeyValue,
    InvalidKey(&'static str, String),
    InvalidValue(&'static str, &'static str),
    HostnameEndpoint,
    Ipv6Endpoint,
    NotUtf8,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.line {
            write!(f, "line {line}: ")?;
        }
        match &self.kind {
            ParseErrorKind::HardRejected(key) => write!(
                f,
                "{key} is not allowed: it would let the config run commands or change routing \
                 as root. Remove the line and import again"
            ),
            ParseErrorKind::OutsideSection => {
                f.write_str("setting outside an [Interface] or [Peer] section")
            }
            ParseErrorKind::UnknownSection => {
                f.write_str("unknown section; expected [Interface] or [Peer]")
            }
            ParseErrorKind::DuplicateSection(name) => write!(f, "second [{name}] section"),
            ParseErrorKind::MultiplePeers => {
                f.write_str("more than one [Peer]; a profile must have exactly one peer")
            }
            ParseErrorKind::MissingSection(name) => write!(f, "missing [{name}] section"),
            ParseErrorKind::MissingKey(key) => write!(f, "missing {key}"),
            ParseErrorKind::DuplicateKey(key) => write!(f, "{key} appears more than once"),
            ParseErrorKind::NotKeyValue => f.write_str("expected `Key = Value`"),
            ParseErrorKind::InvalidKey(key, reason) => write!(f, "{key} is not valid: {reason}"),
            ParseErrorKind::InvalidValue(key, expected) => {
                write!(f, "{key} is not valid: expected {expected}")
            }
            ParseErrorKind::HostnameEndpoint => f.write_str(
                "Endpoint must be a literal IP address and port; hostnames are rejected because \
                 resolving them happens outside the tunnel",
            ),
            ParseErrorKind::Ipv6Endpoint => {
                f.write_str("IPv6 endpoints are not supported; use an IPv4 server config")
            }
            ParseErrorKind::NotUtf8 => f.write_str("file is not UTF-8 text"),
        }
    }
}

impl std::error::Error for ParseError {}

fn err(line: usize, kind: ParseErrorKind) -> ParseError {
    ParseError {
        line: Some(line),
        kind,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

#[derive(Default)]
struct Raw {
    private_key: Option<SecretKey>,
    addresses: Vec<IpNet>,
    dns: Vec<IpAddr>,
    mtu: Option<u16>,
    public_key: Option<PublicKey>,
    preshared_key: Option<SecretKey>,
    allowed_ips: Vec<IpNet>,
    endpoint: Option<SocketAddr>,
    keepalive: Option<u16>,
    seen: Vec<&'static str>,
}

impl Raw {
    fn once(&mut self, key: &'static str, line: usize) -> Result<(), ParseError> {
        if self.seen.contains(&key) {
            return Err(err(line, ParseErrorKind::DuplicateKey(key)));
        }
        self.seen.push(key);
        Ok(())
    }
}

pub fn parse_bytes(bytes: &[u8]) -> Result<ParsedConfig, ParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError {
        line: None,
        kind: ParseErrorKind::NotUtf8,
    })?;
    parse(text)
}

pub fn parse(text: &str) -> Result<ParsedConfig, ParseError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut section = Section::None;
    let mut interfaces = 0;
    let mut peers = 0;
    let mut raw = Raw::default();
    let mut peer_comment = None;
    let mut warnings = Vec::new();

    for (index, line) in text.split('\n').enumerate() {
        let n = index + 1;
        let line = line.strip_suffix('\r').unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#').or_else(|| line.strip_prefix(';')) {
            if section == Section::Peer && peer_comment.is_none() {
                let comment = clean_name(comment);
                if !comment.is_empty() {
                    peer_comment = Some(comment);
                }
            }
            continue;
        }
        if line.starts_with('[') {
            let name = line.trim_start_matches('[').trim_end_matches(']').trim();
            if name.eq_ignore_ascii_case("Interface") {
                interfaces += 1;
                if interfaces > 1 {
                    return Err(err(n, ParseErrorKind::DuplicateSection("Interface")));
                }
                section = Section::Interface;
            } else if name.eq_ignore_ascii_case("Peer") {
                peers += 1;
                if peers > 1 {
                    return Err(err(n, ParseErrorKind::MultiplePeers));
                }
                section = Section::Peer;
            } else {
                return Err(err(n, ParseErrorKind::UnknownSection));
            }
            continue;
        }

        let content = line.split_once('#').map_or(line, |(before, _)| before);
        let Some((key, value)) = content.split_once('=') else {
            return Err(err(n, ParseErrorKind::NotKeyValue));
        };
        let key = key.trim();
        let value = value.trim();
        if let Some(rejected) = HARD_REJECT.iter().find(|k| k.eq_ignore_ascii_case(key)) {
            return Err(err(n, ParseErrorKind::HardRejected(rejected)));
        }
        match section {
            Section::None => return Err(err(n, ParseErrorKind::OutsideSection)),
            Section::Interface => interface_key(&mut raw, key, value, n, &mut warnings)?,
            Section::Peer => peer_key(&mut raw, key, value, n, &mut warnings)?,
        }
    }

    if interfaces == 0 {
        return Err(missing(ParseErrorKind::MissingSection("Interface")));
    }
    if peers == 0 {
        return Err(missing(ParseErrorKind::MissingSection("Peer")));
    }
    let private_key = raw
        .private_key
        .ok_or_else(|| missing(ParseErrorKind::MissingKey("PrivateKey")))?;
    if raw.addresses.is_empty() {
        return Err(missing(ParseErrorKind::MissingKey("Address")));
    }
    let public_key = raw
        .public_key
        .ok_or_else(|| missing(ParseErrorKind::MissingKey("PublicKey")))?;
    let endpoint = raw
        .endpoint
        .ok_or_else(|| missing(ParseErrorKind::MissingKey("Endpoint")))?;
    if raw.allowed_ips.is_empty() {
        return Err(missing(ParseErrorKind::MissingKey("AllowedIPs")));
    }
    if raw.dns.is_empty() {
        warnings.push(
            "no DNS servers: while connected, name lookups use the system resolver and may \
             bypass the tunnel"
                .to_owned(),
        );
    }
    if !raw
        .allowed_ips
        .iter()
        .any(|n| n.is_default() && n.is_ipv4())
    {
        warnings.push(
            "AllowedIPs does not include 0.0.0.0/0: traffic outside it leaves directly unless \
             the kill switch is armed"
                .to_owned(),
        );
    }

    Ok(ParsedConfig {
        interface: Interface {
            private_key,
            addresses: raw.addresses,
            dns: raw.dns,
            mtu: raw.mtu,
        },
        peer: Peer {
            public_key,
            preshared_key: raw.preshared_key,
            allowed_ips: raw.allowed_ips,
            endpoint,
            persistent_keepalive: raw.keepalive,
        },
        peer_comment,
        warnings,
    })
}

fn missing(kind: ParseErrorKind) -> ParseError {
    ParseError { line: None, kind }
}

fn interface_key(
    raw: &mut Raw,
    key: &str,
    value: &str,
    n: usize,
    warnings: &mut Vec<String>,
) -> Result<(), ParseError> {
    if key.eq_ignore_ascii_case("PrivateKey") {
        raw.once("PrivateKey", n)?;
        let parsed = SecretKey::from_base64(value)
            .map_err(|e| err(n, ParseErrorKind::InvalidKey("PrivateKey", e.to_string())))?;
        raw.private_key = Some(parsed);
    } else if key.eq_ignore_ascii_case("Address") {
        for item in list(value) {
            let net = item
                .parse::<IpNet>()
                .map_err(|_| err(n, ParseErrorKind::InvalidValue("Address", "IP/prefix")))?;
            raw.addresses.push(net);
        }
    } else if key.eq_ignore_ascii_case("DNS") {
        for item in list(value) {
            let ip = item.parse::<IpAddr>().map_err(|_| {
                err(
                    n,
                    ParseErrorKind::InvalidValue("DNS", "IP addresses only (no search domains)"),
                )
            })?;
            raw.dns.push(ip);
        }
    } else if key.eq_ignore_ascii_case("MTU") {
        raw.once("MTU", n)?;
        let mtu = value
            .parse::<u16>()
            .ok()
            .filter(|m| (MIN_MTU..=MAX_MTU).contains(m))
            .ok_or_else(|| {
                err(
                    n,
                    ParseErrorKind::InvalidValue("MTU", "a number from 1280 to 9000"),
                )
            })?;
        raw.mtu = Some(mtu);
    } else {
        warnings.push(format!(
            "line {n}: ignored unsupported [Interface] key {}",
            safe_key(key)
        ));
    }
    Ok(())
}

fn peer_key(
    raw: &mut Raw,
    key: &str,
    value: &str,
    n: usize,
    warnings: &mut Vec<String>,
) -> Result<(), ParseError> {
    if key.eq_ignore_ascii_case("PublicKey") {
        raw.once("PublicKey", n)?;
        let parsed = PublicKey::from_base64(value)
            .map_err(|e| err(n, ParseErrorKind::InvalidKey("PublicKey", e.to_string())))?;
        raw.public_key = Some(parsed);
    } else if key.eq_ignore_ascii_case("PresharedKey") {
        raw.once("PresharedKey", n)?;
        let parsed = SecretKey::from_base64(value)
            .map_err(|e| err(n, ParseErrorKind::InvalidKey("PresharedKey", e.to_string())))?;
        raw.preshared_key = Some(parsed);
    } else if key.eq_ignore_ascii_case("AllowedIPs") {
        for item in list(value) {
            let net = item
                .parse::<IpNet>()
                .map_err(|_| err(n, ParseErrorKind::InvalidValue("AllowedIPs", "IP/prefix")))?;
            raw.allowed_ips.push(net);
        }
    } else if key.eq_ignore_ascii_case("Endpoint") {
        raw.once("Endpoint", n)?;
        raw.endpoint = Some(endpoint(value, n)?);
    } else if key.eq_ignore_ascii_case("PersistentKeepalive") {
        raw.once("PersistentKeepalive", n)?;
        let keepalive = if value.eq_ignore_ascii_case("off") {
            0
        } else {
            value.parse::<u16>().map_err(|_| {
                err(
                    n,
                    ParseErrorKind::InvalidValue("PersistentKeepalive", "seconds or off"),
                )
            })?
        };
        raw.keepalive = Some(keepalive);
    } else {
        warnings.push(format!(
            "line {n}: ignored unsupported [Peer] key {}",
            safe_key(key)
        ));
    }
    Ok(())
}

fn endpoint(value: &str, n: usize) -> Result<SocketAddr, ParseError> {
    match value.parse::<SocketAddr>() {
        Ok(SocketAddr::V4(v4)) if v4.port() != 0 => Ok(SocketAddr::V4(v4)),
        Ok(SocketAddr::V4(_)) => Err(err(
            n,
            ParseErrorKind::InvalidValue("Endpoint", "a non-zero port"),
        )),
        Ok(SocketAddr::V6(_)) => Err(err(n, ParseErrorKind::Ipv6Endpoint)),
        Err(_) => {
            let looks_like_host = value
                .rsplit_once(':')
                .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
            if looks_like_host {
                Err(err(n, ParseErrorKind::HostnameEndpoint))
            } else {
                Err(err(
                    n,
                    ParseErrorKind::InvalidValue("Endpoint", "IPv4:port"),
                ))
            }
        }
    }
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// Unknown key names are echoed in warnings; keep them short and printable.
fn safe_key(key: &str) -> String {
    let cleaned: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "(unnamed)".to_owned()
    } else {
        cleaned
    }
}

fn clean_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_NAME_LEN)
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    pub name: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub country_code: Option<String>,
    pub city: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OverrideError {
    #[error("--country must be two letters (ISO 3166-1 alpha-2)")]
    Country,
    #[error("--name must not be empty")]
    Name,
}

/// Name precedence: `--name`, then the `[Peer]` comment, then the file stem. Country: `--country`,
/// else the name's leading two upper-case letters when they are a known ISO code.
pub fn identity(
    peer_comment: Option<&str>,
    file_stem: Option<&str>,
    overrides: &Overrides,
) -> Result<Identity, OverrideError> {
    let name = match &overrides.name {
        Some(name) => {
            let name = clean_name(name);
            if name.is_empty() {
                return Err(OverrideError::Name);
            }
            name
        }
        None => peer_comment
            .map(clean_name)
            .filter(|s| !s.is_empty())
            .or_else(|| file_stem.map(clean_name).filter(|s| !s.is_empty()))
            .unwrap_or_else(|| "profile".to_owned()),
    };
    let country_code = match &overrides.country {
        Some(code) => {
            let code = code.trim();
            if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_alphabetic()) {
                return Err(OverrideError::Country);
            }
            Some(country::canonical(code).map_or_else(|| code.to_ascii_uppercase(), str::to_owned))
        }
        None => country_from_name(&name).map(str::to_owned),
    };
    let city = overrides
        .city
        .as_deref()
        .map(clean_name)
        .filter(|s| !s.is_empty());
    Ok(Identity {
        name,
        country_code,
        city,
    })
}

/// `CO#4` and `US-NY#123` yield `CO` and `US`; `my-vpn` yields nothing.
pub fn country_from_name(name: &str) -> Option<&'static str> {
    let bytes = name.as_bytes();
    let lead = bytes.get(..2)?;
    if !lead.iter().all(u8::is_ascii_uppercase) {
        return None;
    }
    if bytes.get(2).is_some_and(u8::is_ascii_alphabetic) {
        return None;
    }
    country::canonical(std::str::from_utf8(lead).ok()?)
}

/// `slug(name)-xxxxxx`, where the suffix is the first six hex digits of SHA-256 of the peer key.
pub fn profile_id(name: &str, peer: &PublicKey) -> String {
    profile_id_with(name, peer, 6)
}

pub fn profile_id_with(name: &str, peer: &PublicKey, hex_len: usize) -> String {
    let digest = Sha256::digest(peer.as_bytes());
    let fingerprint = hex(&digest);
    format!(
        "{}-{}",
        slug(name),
        &fingerprint[..hex_len.min(fingerprint.len())]
    )
}

pub fn slug(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out = out.trim_end_matches('-');
    let out: String = out.chars().take(32).collect();
    let out = out.trim_end_matches('-').to_owned();
    if out.is_empty() {
        "profile".to_owned()
    } else {
        out
    }
}
