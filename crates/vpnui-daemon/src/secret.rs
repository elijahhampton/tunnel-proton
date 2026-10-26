//! WireGuard key material. Secret keys have a redacting `Debug`, are wiped on drop, and
//! deliberately implement neither `Display` nor `Serialize`.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("not valid base64")]
    Base64,
    #[error("decodes to {0} bytes; a WireGuard key is exactly 32")]
    Length(usize),
}

/// Decodes base64 into exactly 32 bytes, wiping every intermediate buffer.
fn decode32(text: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, KeyError> {
    let mut buf = Zeroizing::new([0u8; 48]);
    let len = STANDARD
        .decode_slice(text.trim().as_bytes(), buf.as_mut())
        .map_err(|_| KeyError::Base64)?;
    if len != KEY_LEN {
        return Err(KeyError::Length(len));
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&buf[..KEY_LEN]);
    Ok(out)
}

/// A private or preshared key.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_base64(text: &str) -> Result<Self, KeyError> {
        decode32(text).map(|bytes| Self(*bytes))
    }

    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.0))
    }

    /// Lowercase hex, as the UAPI protocol expects.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex(&self.0))
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// A peer's public key. Not secret; printed as base64.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_base64(text: &str) -> Result<Self, KeyError> {
        decode32(text).map(|bytes| Self(*bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_base64())
    }
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    #[test]
    fn roundtrips_base64_and_hex() {
        let key = SecretKey::from_bytes(SAMPLE);
        let b64 = key.to_base64();
        assert_eq!(SecretKey::from_base64(&b64), Ok(key.clone()));
        assert_eq!(&key.to_hex()[..8], "01020304");
        assert_eq!(key.to_hex().len(), 64);
    }

    #[test]
    fn rejects_wrong_lengths_and_garbage() {
        let short = STANDARD.encode([7u8; 31]);
        let long = STANDARD.encode([7u8; 33]);
        assert_eq!(SecretKey::from_base64(&short), Err(KeyError::Length(31)));
        assert_eq!(PublicKey::from_base64(&long), Err(KeyError::Length(33)));
        assert_eq!(SecretKey::from_base64("not base64!"), Err(KeyError::Base64));
        assert_eq!(SecretKey::from_base64(""), Err(KeyError::Length(0)));
    }

    #[test]
    fn debug_never_shows_secret_bytes() {
        let key = SecretKey::from_bytes(SAMPLE);
        let shown = format!("{key:?} {:?}", Some(&key));
        assert!(!shown.contains(key.to_base64().as_str()));
        assert!(!shown.contains(key.to_hex().as_str()));
        assert!(shown.contains("redacted"));
    }
}
