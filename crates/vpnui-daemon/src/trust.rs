//! Binary pinning. A binary that root executes must sit in a path where every component is
//! owned by a trusted uid and writable by no one else, and must match its recorded SHA-256.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::secret::hex;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pinned {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    #[error("{0} is not an absolute path")]
    NotAbsolute(PathBuf),
    #[error("{0} does not exist")]
    Missing(PathBuf),
    #[error("{0} contains a symlink or is not in canonical form")]
    NotCanonical(PathBuf),
    #[error("{0} is not a regular file")]
    NotRegular(PathBuf),
    #[error("{path} is owned by uid {uid}, not root")]
    Owner { path: PathBuf, uid: u32 },
    #[error("{0} is writable by group or others")]
    Writable(PathBuf),
    #[error("{path} has SHA-256 {actual}, expected {expected}")]
    Hash {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("{path}: {reason}")]
    Io { path: PathBuf, reason: String },
}

/// Checks `path` and each parent directory: canonical, owned by one of `owners`, not group- or
/// world-writable. The file itself must be a regular file.
pub fn check_path(path: &Path, owners: &[u32]) -> Result<(), TrustError> {
    if !path.is_absolute() {
        return Err(TrustError::NotAbsolute(path.to_path_buf()));
    }
    let canonical = fs::canonicalize(path).map_err(|_| TrustError::Missing(path.to_path_buf()))?;
    if canonical != path {
        return Err(TrustError::NotCanonical(path.to_path_buf()));
    }
    let meta = fs::symlink_metadata(path).map_err(|e| TrustError::Io {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    if !meta.file_type().is_file() {
        return Err(TrustError::NotRegular(path.to_path_buf()));
    }
    for component in path.ancestors() {
        let meta = fs::symlink_metadata(component).map_err(|e| TrustError::Io {
            path: component.to_path_buf(),
            reason: e.to_string(),
        })?;
        if !owners.contains(&meta.uid()) {
            return Err(TrustError::Owner {
                path: component.to_path_buf(),
                uid: meta.uid(),
            });
        }
        if meta.mode() & 0o022 != 0 {
            return Err(TrustError::Writable(component.to_path_buf()));
        }
    }
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String, TrustError> {
    let io = |e: std::io::Error| TrustError::Io {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    let mut file = fs::File::open(path).map_err(io)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Re-verifies location, ownership, and hash. Call before every execution.
pub fn verify(pinned: &Pinned, owners: &[u32]) -> Result<(), TrustError> {
    check_path(&pinned.path, owners)?;
    let actual = sha256_file(&pinned.path)?;
    if actual != pinned.sha256 {
        return Err(TrustError::Hash {
            path: pinned.path.clone(),
            expected: pinned.sha256.clone(),
            actual,
        });
    }
    Ok(())
}

/// Pins a binary that is already in a trusted location, hashing it now.
pub fn pin(path: &Path, owners: &[u32]) -> Result<Pinned, TrustError> {
    check_path(path, owners)?;
    Ok(Pinned {
        path: path.to_path_buf(),
        sha256: sha256_file(path)?,
    })
}

#[cfg(test)]
mod tests {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::testkeys::TempDir;

    fn owners() -> Vec<u32> {
        vec![0, nix::unistd::geteuid().as_raw()]
    }

    fn binary(dir: &TempDir) -> PathBuf {
        let root = fs::canonicalize(dir.path()).unwrap();
        let bin = root.join("libexec");
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&bin, Permissions::from_mode(0o755)).unwrap();
        let path = bin.join("wireguard-go");
        fs::write(&path, b"#!/bin/false\n").unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn pins_and_verifies() {
        let dir = TempDir::new("trust").unwrap();
        let path = binary(&dir);
        fs::set_permissions(
            path.parent().unwrap().parent().unwrap(),
            Permissions::from_mode(0o755),
        )
        .unwrap();
        let pinned = pin(&path, &owners()).unwrap();
        assert_eq!(pinned.sha256.len(), 64);
        verify(&pinned, &owners()).unwrap();

        fs::write(&path, b"#!/bin/true\n").unwrap();
        assert!(
            matches!(verify(&pinned, &owners()), Err(TrustError::Hash { .. })),
            "a swapped binary is refused"
        );
    }

    #[test]
    fn refuses_untrusted_locations() {
        let dir = TempDir::new("trust").unwrap();
        let path = binary(&dir);
        let parent = path.parent().unwrap().to_path_buf();

        assert!(
            matches!(check_path(&path, &[0]), Err(TrustError::Owner { .. })),
            "user-owned is not root-owned"
        );

        fs::set_permissions(&parent, Permissions::from_mode(0o775)).unwrap();
        assert!(
            matches!(check_path(&path, &owners()), Err(TrustError::Writable(p)) if p == parent)
        );
        fs::set_permissions(&parent, Permissions::from_mode(0o755)).unwrap();

        let link = parent.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            check_path(&link, &owners()),
            Err(TrustError::NotCanonical(_))
        ));

        assert!(matches!(
            check_path(Path::new("wireguard-go"), &owners()),
            Err(TrustError::NotAbsolute(_))
        ));
        assert!(matches!(
            check_path(&parent.join("missing"), &owners()),
            Err(TrustError::Missing(_))
        ));
        assert!(matches!(
            check_path(&parent, &owners()),
            Err(TrustError::NotRegular(_))
        ));
    }
}
