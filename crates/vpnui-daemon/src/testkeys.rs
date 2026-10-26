//! Synthetic key fixtures for tests. These are fixed byte patterns, not real WireGuard keys.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use vpnui_proto::UnixMillis;

use crate::profile::profile::{Overrides, Profile, identity, parse, profile_id};
use crate::secret::hex;

pub fn private_bytes(n: u8) -> [u8; 32] {
    std::array::from_fn(|i| n.wrapping_mul(31).wrapping_add(i as u8).wrapping_mul(7) | 0x01)
}

pub fn public_bytes(n: u8) -> [u8; 32] {
    std::array::from_fn(|i| n.wrapping_mul(17).wrapping_add(i as u8).wrapping_mul(13) ^ 0xa5)
}

pub fn key_bytes(n: u8) -> [u8; 32] {
    std::array::from_fn(|i| n.wrapping_mul(53).wrapping_add(i as u8).wrapping_mul(3) ^ 0x3c)
}

pub fn private_b64(n: u8) -> String {
    STANDARD.encode(private_bytes(n))
}

pub fn public_b64(n: u8) -> String {
    STANDARD.encode(public_bytes(n))
}

pub fn key_b64(n: u8) -> String {
    STANDARD.encode(key_bytes(n))
}

/// Every textual form in which fixture secret `n` could leak: base64, hex, and long
/// prefixes of each.
pub fn secret_forms(n: u8) -> Vec<String> {
    let mut forms = Vec::new();
    for bytes in [private_bytes(n), key_bytes(n)] {
        let b64 = STANDARD.encode(bytes);
        let hexed = hex(&bytes);
        forms.push(b64[..24].to_owned());
        forms.push(hexed[..24].to_owned());
        forms.push(b64);
        forms.push(hexed);
    }
    forms
}

/// A WireGuard config built from fixture keys.
pub fn config(n: u8, comment: &str, endpoint: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.2.0.{n}/32\nDNS = 10.2.0.1\n\n\
         [Peer]\n# {comment}\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\n\
         Endpoint = {endpoint}\n",
        private_b64(n),
        public_b64(n),
        key_b64(n),
    )
}

/// A stored profile built from fixture keys `n`, named by `comment`.
pub fn profile(n: u8, comment: &str, endpoint: &str, imported_at: u64) -> Profile {
    let Ok(parsed) = parse(&config(n, comment, endpoint)) else {
        panic!("fixture config {n} does not parse");
    };
    let Ok(id) = identity(parsed.peer_comment.as_deref(), None, &Overrides::default()) else {
        panic!("fixture identity {n} is invalid");
    };
    Profile {
        id: profile_id(&id.name, &parsed.peer.public_key),
        name: id.name,
        country_code: id.country_code,
        city: id.city,
        imported_at: UnixMillis(imported_at),
        interface: parsed.interface,
        peer: parsed.peer,
    }
}

/// A uniquely named directory under the system temp dir, removed on drop.
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> std::io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vpnuid-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
