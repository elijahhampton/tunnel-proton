//! On-disk profile store: one normalized JSON file per profile, written atomically.

use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use vpnui_proto::UnixMillis;
use zeroize::Zeroizing;

use crate::net::net::IpNet;
use crate::profile::profile::{self, Identity, Interface, ParsedConfig, Peer, Profile};
use crate::secret::{PublicKey, SecretKey};

const FORMAT: u32 = 1;
const MAX_PROFILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{path}: not a valid stored profile ({reason})")]
    Corrupt { path: PathBuf, reason: String },
    #[error("{path} must be a directory owned by uid {uid} with mode 0700")]
    NotPrivate { path: PathBuf, uid: u32 },
    #[error("no profile with id {0}")]
    NotFound(String),
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Writes `bytes` to `path` via a temp file in the same directory, fsync, and rename, so readers
/// see either the old or the new contents.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}-{}",
        name.to_string_lossy(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Reads a file into a zeroizing buffer, refusing anything over `limit` bytes.
pub fn read_secret_file(path: &Path, limit: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    if len > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is too large",
        ));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(usize::try_from(len).unwrap_or(0)));
    file.take(limit + 1).read_to_end(&mut buf)?;
    Ok(buf)
}

#[derive(Serialize, Deserialize)]
struct StoredProfile {
    format: u32,
    id: String,
    name: String,
    country_code: Option<String>,
    city: Option<String>,
    imported_at_ms: u64,
    interface: StoredInterface,
    peer: StoredPeer,
}

#[derive(Serialize, Deserialize)]
struct StoredInterface {
    #[serde(with = "secret_b64")]
    private_key: SecretKey,
    addresses: Vec<IpNet>,
    dns: Vec<IpAddr>,
    mtu: Option<u16>,
}

#[derive(Serialize, Deserialize)]
struct StoredPeer {
    #[serde(with = "public_b64")]
    public_key: PublicKey,
    #[serde(default, with = "opt_secret_b64")]
    preshared_key: Option<SecretKey>,
    allowed_ips: Vec<IpNet>,
    endpoint: SocketAddr,
    persistent_keepalive: Option<u16>,
}

mod secret_b64 {
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};

    use crate::secret::SecretKey;

    pub fn serialize<S: Serializer>(key: &SecretKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&key.to_base64())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretKey, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = SecretKey;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a base64 WireGuard key")
            }
            fn visit_str<E: Error>(self, v: &str) -> Result<SecretKey, E> {
                SecretKey::from_base64(v).map_err(E::custom)
            }
        }
        d.deserialize_str(V)
    }
}

mod opt_secret_b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::secret::SecretKey;

    pub fn serialize<S: Serializer>(key: &Option<SecretKey>, s: S) -> Result<S::Ok, S::Error> {
        match key {
            Some(key) => super::secret_b64::serialize(key, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SecretKey>, D::Error> {
        #[derive(Deserialize)]
        struct Wrap(#[serde(with = "super::secret_b64")] SecretKey);
        Ok(Option::<Wrap>::deserialize(d)?.map(|w| w.0))
    }
}

mod public_b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::secret::PublicKey;

    pub fn serialize<S: Serializer>(key: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&key.to_base64())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        let text = String::deserialize(d)?;
        PublicKey::from_base64(&text).map_err(serde::de::Error::custom)
    }
}

impl StoredProfile {
    fn from_profile(p: &Profile) -> Self {
        Self {
            format: FORMAT,
            id: p.id.clone(),
            name: p.name.clone(),
            country_code: p.country_code.clone(),
            city: p.city.clone(),
            imported_at_ms: p.imported_at.0,
            interface: StoredInterface {
                private_key: p.interface.private_key.clone(),
                addresses: p.interface.addresses.clone(),
                dns: p.interface.dns.clone(),
                mtu: p.interface.mtu,
            },
            peer: StoredPeer {
                public_key: p.peer.public_key,
                preshared_key: p.peer.preshared_key.clone(),
                allowed_ips: p.peer.allowed_ips.clone(),
                endpoint: p.peer.endpoint,
                persistent_keepalive: p.peer.persistent_keepalive,
            },
        }
    }

    fn into_profile(self) -> Profile {
        Profile {
            id: self.id,
            name: self.name,
            country_code: self.country_code,
            city: self.city,
            imported_at: UnixMillis(self.imported_at_ms),
            interface: Interface {
                private_key: self.interface.private_key,
                addresses: self.interface.addresses,
                dns: self.interface.dns,
                mtu: self.interface.mtu,
            },
            peer: Peer {
                public_key: self.peer.public_key,
                preshared_key: self.peer.preshared_key,
                allowed_ips: self.peer.allowed_ips,
                endpoint: self.peer.endpoint,
                persistent_keepalive: self.peer.persistent_keepalive,
            },
        }
    }
}

#[derive(Debug)]
pub struct ImportOutcome {
    pub profile: Profile,
    /// A profile with the same peer key existed and was updated in place.
    pub replaced: bool,
}

#[derive(Debug, Clone)]
pub struct ProfileStore {
    dir: PathBuf,
    owner: u32,
}

impl ProfileStore {
    /// `owner` is the uid that must own the directory and files (root in production).
    pub fn new(dir: impl Into<PathBuf>, owner: u32) -> Self {
        Self {
            dir: dir.into(),
            owner,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Creates the directory with mode 0700, or checks an existing one.
    pub fn ensure_dir(&self) -> Result<(), StoreError> {
        match fs::symlink_metadata(&self.dir) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.dir).map_err(io_err(&self.dir))?;
                fs::set_permissions(&self.dir, Permissions::from_mode(0o700))
                    .map_err(io_err(&self.dir))?;
            }
            Err(e) => return Err(io_err(&self.dir)(e)),
        }
        self.check_private()
    }

    pub fn check_private(&self) -> Result<(), StoreError> {
        let meta = fs::symlink_metadata(&self.dir).map_err(io_err(&self.dir))?;
        let private = meta.is_dir() && meta.uid() == self.owner && meta.mode() & 0o077 == 0;
        if private {
            Ok(())
        } else {
            Err(StoreError::NotPrivate {
                path: self.dir.clone(),
                uid: self.owner,
            })
        }
    }

    fn path_for(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    pub fn list(&self) -> Result<Vec<Profile>, StoreError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_err(&self.dir)(e)),
        };
        let mut profiles = Vec::new();
        for entry in entries {
            let path = entry.map_err(io_err(&self.dir))?.path();
            let is_profile = path.extension().is_some_and(|e| e == "json")
                && !path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'));
            if is_profile {
                profiles.push(self.read(&path)?);
            }
        }
        profiles.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(profiles)
    }

    fn read(&self, path: &Path) -> Result<Profile, StoreError> {
        let bytes = read_secret_file(path, MAX_PROFILE_BYTES).map_err(io_err(path))?;
        let stored: StoredProfile =
            serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
        if stored.format != FORMAT {
            return Err(StoreError::Corrupt {
                path: path.to_path_buf(),
                reason: format!("unsupported format {}", stored.format),
            });
        }
        Ok(stored.into_profile())
    }

    /// Stores `parsed` under `identity`. A stored profile with the same peer key keeps its id and
    /// is overwritten.
    pub fn import(
        &self,
        parsed: ParsedConfig,
        identity: Identity,
        now: UnixMillis,
    ) -> Result<ImportOutcome, StoreError> {
        self.ensure_dir()?;
        let existing = self.list()?;
        let same_peer = existing
            .iter()
            .find(|p| p.peer.public_key == parsed.peer.public_key);
        let id = match same_peer {
            Some(p) => p.id.clone(),
            None => {
                let id = profile::profile_id(&identity.name, &parsed.peer.public_key);
                if existing.iter().any(|p| p.id == id) {
                    profile::profile_id_with(&identity.name, &parsed.peer.public_key, 12)
                } else {
                    id
                }
            }
        };
        let profile = Profile {
            id,
            name: identity.name,
            country_code: identity.country_code,
            city: identity.city,
            imported_at: now,
            interface: parsed.interface,
            peer: parsed.peer,
        };
        self.write(&profile)?;
        Ok(ImportOutcome {
            replaced: same_peer.is_some(),
            profile,
        })
    }

    pub fn write(&self, profile: &Profile) -> Result<(), StoreError> {
        let path = self.path_for(&profile.id);
        let json = Zeroizing::new(
            serde_json::to_vec_pretty(&StoredProfile::from_profile(profile)).map_err(|e| {
                StoreError::Corrupt {
                    path: path.clone(),
                    reason: e.to_string(),
                }
            })?,
        );
        atomic_write(&path, &json, 0o600).map_err(io_err(&path))
    }

    pub fn remove(&self, id: &str) -> Result<Profile, StoreError> {
        let profile = self
            .list()?
            .into_iter()
            .find(|p| p.id == id)
            .ok_or_else(|| StoreError::NotFound(id.to_owned()))?;
        let path = self.path_for(&profile.id);
        fs::remove_file(&path).map_err(io_err(&path))?;
        Ok(profile)
    }
}