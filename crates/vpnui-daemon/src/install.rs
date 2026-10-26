//! `vpnuid install` and `uninstall`, expressed as a plan of steps so `--dry-run` prints exactly
//! what a real run would do.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::exec::Cmd;
use crate::net::paths::{self, Paths, SERVICE_LABEL};
use crate::store::store::atomic_write;
use crate::trust::{self, Pinned};

/// Written by `install`, read by `run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallRecord {
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub wireguard_go: Pinned,
    pub vpnuid: Pinned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    CreateDir {
        path: PathBuf,
        mode: u32,
    },
    Copy {
        from: PathBuf,
        to: PathBuf,
        mode: u32,
    },
    Write {
        path: PathBuf,
        contents: String,
        mode: u32,
    },
    Remove {
        path: PathBuf,
    },
    RemoveDir {
        path: PathBuf,
    },
    Launchctl {
        args: Vec<String>,
    },
    Rescue,
}

impl Step {
    pub fn describe(&self) -> String {
        match self {
            Self::CreateDir { path, mode } => {
                format!("mkdir -p {} && chmod {mode:o} (root:wheel)", path.display())
            }
            Self::Copy { from, to, mode } => {
                format!(
                    "copy {} -> {} (root:wheel {mode:o})",
                    from.display(),
                    to.display()
                )
            }
            Self::Write { path, mode, .. } => {
                format!("write {} (root:wheel {mode:o})", path.display())
            }
            Self::Remove { path } => format!("rm -f {}", path.display()),
            Self::RemoveDir { path } => format!("rmdir {} (if empty)", path.display()),
            Self::Launchctl { args } => format!("{} {}", paths::LAUNCHCTL, args.join(" ")),
            Self::Rescue => "vpnuid rescue".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub record: Option<InstallRecord>,
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error(
        "wireguard-go not found; pass --wireguard-go PATH (for example from `brew install wireguard-go`)"
    )]
    NoWireguardGo,
    #[error("{0}")]
    Trust(#[from] trust::TrustError),
    #[error("{path}: {reason}")]
    Io { path: PathBuf, reason: String },
    #[error("{0}")]
    Command(#[from] crate::exec::ExecError),
    #[error(
        "{0} must be owned by root and not writable by others; pinned binaries cannot live under it"
    )]
    UntrustedParent(PathBuf),
}

pub fn plist(paths: &Paths) -> String {
    let log = paths.log_dir.join("vpnuid.log");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{SERVICE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{}</string>
    <key>StandardErrorPath</key>
    <string>{}</string>
</dict>
</plist>
"#,
        paths.pinned_vpnuid().display(),
        log.display(),
        log.display()
    )
}

/// Finds wireguard-go to copy from: the given path, else the usual Homebrew locations.
pub fn find_wireguard_go(given: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = given {
        return Some(path.to_path_buf());
    }
    [
        "/opt/homebrew/bin/wireguard-go",
        "/usr/local/bin/wireguard-go",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
    .and_then(|p| fs::canonicalize(p).ok())
}

pub struct InstallInput<'a> {
    pub paths: &'a Paths,
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub wireguard_go: &'a Path,
    pub vpnuid: &'a Path,
}

pub fn install_plan(input: &InstallInput<'_>) -> Result<Plan, InstallError> {
    let paths = input.paths;
    let wg_hash = trust::sha256_file(input.wireguard_go)?;
    let vpnuid_hash = trust::sha256_file(input.vpnuid)?;
    let record = InstallRecord {
        user: input.user.clone(),
        uid: input.uid,
        gid: input.gid,
        wireguard_go: Pinned {
            path: paths.pinned_wireguard_go(),
            sha256: wg_hash,
        },
        vpnuid: Pinned {
            path: paths.pinned_vpnuid(),
            sha256: vpnuid_hash,
        },
    };
    let record_json = serde_json::to_string_pretty(&record).map_err(|e| InstallError::Io {
        path: paths.install_file.clone(),
        reason: e.to_string(),
    })?;
    let target = format!("system/{SERVICE_LABEL}");
    let steps = vec![
        Step::CreateDir {
            path: paths.libexec.clone(),
            mode: 0o755,
        },
        Step::Copy {
            from: input.wireguard_go.to_path_buf(),
            to: paths.pinned_wireguard_go(),
            mode: 0o755,
        },
        Step::Copy {
            from: input.vpnuid.to_path_buf(),
            to: paths.pinned_vpnuid(),
            mode: 0o755,
        },
        Step::CreateDir {
            path: paths.db_dir.clone(),
            mode: 0o700,
        },
        Step::CreateDir {
            path: paths.profiles_dir.clone(),
            mode: 0o700,
        },
        Step::Write {
            path: paths.install_file.clone(),
            contents: record_json,
            mode: 0o600,
        },
        Step::CreateDir {
            path: paths.log_dir.clone(),
            mode: 0o750,
        },
        Step::Write {
            path: paths.plist.clone(),
            contents: plist(paths),
            mode: 0o644,
        },
        Step::Launchctl {
            args: vec!["bootout".into(), target],
        },
        Step::Launchctl {
            args: vec![
                "bootstrap".into(),
                "system".into(),
                paths.plist.display().to_string(),
            ],
        },
    ];
    Ok(Plan {
        steps,
        record: Some(record),
    })
}

pub fn uninstall_plan(paths: &Paths) -> Plan {
    Plan {
        steps: vec![
            Step::Rescue,
            Step::Launchctl {
                args: vec!["bootout".into(), format!("system/{SERVICE_LABEL}")],
            },
            Step::Remove {
                path: paths.plist.clone(),
            },
            Step::Remove {
                path: paths.pinned_wireguard_go(),
            },
            Step::Remove {
                path: paths.pinned_vpnuid(),
            },
            Step::RemoveDir {
                path: paths.libexec.clone(),
            },
            Step::Remove {
                path: paths.install_file.clone(),
            },
            Step::Remove {
                path: paths.log_dir.join("vpnuid.log"),
            },
            Step::RemoveDir {
                path: paths.log_dir.clone(),
            },
        ],
        record: None,
    }
}

/// Every existing ancestor of `dir` must be root-owned and not writable by others.
pub fn check_parents(dir: &Path) -> Result<(), InstallError> {
    for ancestor in dir.ancestors().skip(1) {
        if let Ok(meta) = fs::symlink_metadata(ancestor) {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.file_type().is_symlink() {
                return Err(InstallError::UntrustedParent(ancestor.to_path_buf()));
            }
        }
    }
    Ok(())
}

/// Executes a plan as root. `rescue` runs the rescue step.
pub fn execute(plan: &Plan, rescue: &mut dyn FnMut()) -> Result<(), InstallError> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |e: std::io::Error| InstallError::Io {
            path: path.clone(),
            reason: e.to_string(),
        }
    };
    for step in &plan.steps {
        println!("  {}", step.describe());
        match step {
            Step::CreateDir { path, mode } => {
                fs::create_dir_all(path).map_err(io(path))?;
                std::os::unix::fs::chown(path, Some(0), Some(0)).map_err(io(path))?;
                fs::set_permissions(path, Permissions::from_mode(*mode)).map_err(io(path))?;
            }
            Step::Copy { from, to, mode } => {
                let bytes = fs::read(from).map_err(io(from))?;
                atomic_write(to, &bytes, *mode).map_err(io(to))?;
                std::os::unix::fs::chown(to, Some(0), Some(0)).map_err(io(to))?;
                fs::set_permissions(to, Permissions::from_mode(*mode)).map_err(io(to))?;
            }
            Step::Write {
                path,
                contents,
                mode,
            } => {
                atomic_write(path, contents.as_bytes(), *mode).map_err(io(path))?;
                std::os::unix::fs::chown(path, Some(0), Some(0)).map_err(io(path))?;
            }
            Step::Remove { path } => match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io(path)(e)),
            },
            Step::RemoveDir { path } => {
                let _ = fs::remove_dir(path);
            }
            Step::Launchctl { args } => {
                let out = Cmd::new(paths::LAUNCHCTL).args(args.iter()).output()?;
                if !out.status.success() && args.first().is_some_and(|a| a == "bootstrap") {
                    return Err(InstallError::Command(crate::exec::ExecError::Failed {
                        program: paths::LAUNCHCTL.to_owned(),
                        status: out.status,
                        stderr: out.stderr.trim().to_owned(),
                    }));
                }
            }
            Step::Rescue => rescue(),
        }
    }
    Ok(())
}

pub fn read_record(paths: &Paths) -> Option<InstallRecord> {
    let text = fs::read_to_string(&paths.install_file).ok()?;
    serde_json::from_str(&text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkeys::TempDir;

    #[test]
    fn install_plan_pins_both_binaries_and_writes_the_service() {
        let dir = TempDir::new("install").unwrap();
        let wg = dir.path().join("wireguard-go");
        let me = dir.path().join("vpnuid");
        fs::write(&wg, b"fake wireguard-go").unwrap();
        fs::write(&me, b"fake vpnuid").unwrap();
        let paths = Paths::default();
        let plan = install_plan(&InstallInput {
            paths: &paths,
            user: "alice".into(),
            uid: 501,
            gid: 20,
            wireguard_go: &wg,
            vpnuid: &me,
        })
        .unwrap();
        let text: Vec<String> = plan.steps.iter().map(Step::describe).collect();
        assert!(
            text.iter()
                .any(|t| t.contains("/usr/local/libexec/vpnui/wireguard-go"))
        );
        assert!(
            text.iter()
                .any(|t| t.contains("/usr/local/libexec/vpnui/vpnuid"))
        );
        assert!(
            text.iter()
                .any(|t| t
                    .contains("bootstrap system /Library/LaunchDaemons/dev.vpnui.daemon.plist"))
        );
        let record = plan.record.unwrap();
        assert_eq!(record.uid, 501);
        assert_eq!(record.wireguard_go.sha256, trust::sha256_file(&wg).unwrap());
        assert_eq!(
            record.wireguard_go.path,
            PathBuf::from("/usr/local/libexec/vpnui/wireguard-go")
        );

        let plist = plist(&paths);
        assert!(plist.contains("<string>dev.vpnui.daemon</string>"));
        assert!(plist.contains("<string>/usr/local/libexec/vpnui/vpnuid</string>"));
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
        assert!(plist.contains("/var/log/vpnui/vpnuid.log"));
    }

    #[test]
    fn uninstall_rescues_first_and_removes_what_install_created() {
        let plan = uninstall_plan(&Paths::default());
        assert_eq!(plan.steps.first(), Some(&Step::Rescue));
        let text: Vec<String> = plan.steps.iter().map(Step::describe).collect();
        for created in [
            "dev.vpnui.daemon.plist",
            "libexec/vpnui/wireguard-go",
            "libexec/vpnui/vpnuid",
            "install.json",
        ] {
            assert!(text.iter().any(|t| t.contains(created)), "{created}");
        }
        assert!(
            !text.iter().any(|t| t.contains("profiles")),
            "imported profiles are the user's to remove"
        );
    }

    #[test]
    fn parent_checks_reject_user_owned_trees() {
        let dir = TempDir::new("install-parent").unwrap();
        let inside = fs::canonicalize(dir.path()).unwrap().join("libexec");
        assert!(matches!(
            check_parents(&inside),
            Err(InstallError::UntrustedParent(_))
        ));
        assert!(check_parents(Path::new("/usr/libexec/vpnui-test")).is_ok());
    }
}
