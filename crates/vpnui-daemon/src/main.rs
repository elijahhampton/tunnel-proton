#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use vpnui_daemon::net::client::Client;
use vpnui_daemon::doctor::{self, SelfTest};
use vpnui_daemon::engine::engine::EngineOptions;
use vpnui_daemon::exec::Cmd;
use vpnui_daemon::install::{self, InstallInput};
use vpnui_daemon::net::ipcheck::{self, CheckUrl};
use vpnui_daemon::macos::MacPlatform;
use vpnui_daemon::net::paths::{self, Paths};
use vpnui_daemon::platform::{Anchor, Platform};
use vpnui_daemon::profile::profile::{self, Overrides};
use vpnui_daemon::server::{MAX_CLIENTS, ServerConfig};
use vpnui_daemon::store::store::{ProfileStore, read_secret_file};
use vpnui_daemon::trust::{self, Pinned};
use vpnui_daemon::{country, daemon, rescue};
use vpnui_proto::{Command as Wire, Server, Snapshot, UnixMillis};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "vpnuid",
    version,
    about = "Privileged daemon and tools for vpnui"
)]
struct Cli {
    #[command(subcommand)]
    command: Sub,
}

#[derive(Debug, Subcommand)]
enum Sub {
    /// Run the daemon in the foreground (root).
    Run {
        #[arg(long)]
        socket: Option<PathBuf>,
        /// A wireguard-go binary in a root-owned, non-writable location.
        #[arg(long)]
        wireguard_go: Option<PathBuf>,
        /// Run a full rescue and exit after this many seconds (for first runs).
        #[arg(long, value_name = "SECS")]
        auto_rescue_after: Option<u64>,
        /// Check the public IP over HTTPS while connected. Off by default.
        #[arg(long, value_name = "URL")]
        ip_check_url: Option<String>,
    },
    /// Validate and store WireGuard configs (root).
    Import {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        country: Option<String>,
        #[arg(long)]
        city: Option<String>,
        /// Delete each source file after it is stored.
        #[arg(long)]
        delete_source: bool,
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// List stored profiles by country.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Delete a stored profile (root).
    Remove { id: String },
    /// Show a running daemon's state.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Install the pinned binaries and the launchd service (root).
    Install {
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        wireguard_go: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove everything install created, after a rescue (root).
    Uninstall {
        #[arg(long)]
        dry_run: bool,
    },
    /// Diagnostics and a pf self-test (root).
    Doctor,
    /// Restore a clean network state without the daemon (root).
    Rescue,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    match dispatch(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vpnuid: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Sub) -> anyhow::Result<()> {
    let paths = Paths::default();
    match command {
        Sub::Run {
            socket,
            wireguard_go,
            auto_rescue_after,
            ip_check_url,
        } => {
            let paths = match socket {
                Some(socket) => paths.with_socket(socket),
                None => paths,
            };
            run(paths, wireguard_go, auto_rescue_after, ip_check_url)
        }
        Sub::Import {
            name,
            country,
            city,
            delete_source,
            files,
        } => import(
            &paths,
            Overrides {
                name,
                country,
                city,
            },
            delete_source,
            &files,
        ),
        Sub::List { json } => list(&paths, json),
        Sub::Remove { id } => remove(&paths, &id),
        Sub::Status { json } => status(&paths, json),
        Sub::Install {
            user,
            wireguard_go,
            yes,
            dry_run,
        } => install_cmd(&paths, user, wireguard_go, yes, dry_run),
        Sub::Uninstall { dry_run } => uninstall_cmd(&paths, dry_run),
        Sub::Doctor => doctor_cmd(&paths),
        Sub::Rescue => {
            require_root("rescue")?;
            for line in rescue::rescue(&platform(&paths)) {
                println!("rescue: {line}");
            }
            Ok(())
        }
    }
}

fn require_root(what: &str) -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        bail!("`vpnuid {what}` must run as root (use sudo)");
    }
    Ok(())
}

fn platform(paths: &Paths) -> MacPlatform {
    let record = install::read_record(paths);
    MacPlatform::new(
        paths.clone(),
        record.as_ref().map(|r| r.wireguard_go.clone()),
        record.map(|r| r.gid),
    )
}

fn run(
    paths: Paths,
    wireguard_go: Option<PathBuf>,
    auto_rescue: Option<u64>,
    ip_check: Option<String>,
) -> anyhow::Result<()> {
    require_root("run")?;
    let record = install::read_record(&paths);
    let pinned: Option<Pinned> = match wireguard_go {
        Some(path) => Some(trust::pin(&path, &[0]).with_context(|| {
            format!(
                "refusing to run {} as root: it must be root-owned and in a directory no one else can \
                 write. Install it with: sudo vpnuid install --wireguard-go {}",
                path.display(),
                path.display()
            )
        })?),
        None => record.as_ref().map(|r| r.wireguard_go.clone()),
    };
    if pinned.is_none() {
        warn!("no pinned wireguard-go; connects will fail until `sudo vpnuid install` is run");
    }
    let mut allowed = BTreeSet::new();
    if let Some(r) = &record {
        allowed.insert(r.uid);
    }
    if let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
    {
        allowed.insert(uid);
    }
    let gid = record
        .as_ref()
        .map(|r| r.gid)
        .or_else(|| std::env::var("SUDO_GID").ok().and_then(|v| v.parse().ok()));
    let ip_check = ip_check.map(|u| CheckUrl::parse(&u)).transpose()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let platform = MacPlatform::new(paths.clone(), pinned.clone(), gid);
        let config = ServerConfig {
            allowed_uids: allowed.clone(),
            max_clients: MAX_CLIENTS,
        };
        let daemon = daemon::start(platform, EngineOptions::default(), config)?;
        info!(socket = %paths.socket.display(), allowed = ?allowed, "vpnuid running");
        if let Some(url) = ip_check {
            tokio::spawn(ipcheck::run(url, daemon.shared(), daemon.inbox()));
        }
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        let rescue_after = async {
            match auto_rescue {
                Some(secs) => tokio::time::sleep(Duration::from_secs(secs)).await,
                None => std::future::pending().await,
            }
        };
        let rescue_now = tokio::select! {
            _ = interrupt.recv() => { info!("SIGINT"); false }
            _ = terminate.recv() => { info!("SIGTERM"); false }
            () = rescue_after => { warn!("auto-rescue timer expired"); true }
        };
        daemon.stop(true).await;
        let platform = MacPlatform::new(paths.clone(), pinned, gid);
        if rescue_now {
            for line in rescue::rescue(&platform) {
                info!("rescue: {line}");
            }
        } else if let Err(e) = platform.remove_socket() {
            error!(%e, "could not remove the socket");
        }
        anyhow::Ok(())
    })
}

fn import(
    paths: &Paths,
    overrides: Overrides,
    delete_source: bool,
    files: &[PathBuf],
) -> anyhow::Result<()> {
    require_root("import")?;
    if overrides.name.is_some() && files.len() > 1 {
        bail!("--name applies to one file at a time");
    }
    let store = ProfileStore::new(&paths.profiles_dir, 0);
    let mut failures = 0;
    for file in files {
        match import_one(&store, &overrides, file) {
            Ok(()) => {
                if delete_source {
                    match std::fs::remove_file(file) {
                        Ok(()) => println!("  deleted {}", file.display()),
                        Err(e) => println!("  could not delete {}: {e}", file.display()),
                    }
                } else {
                    println!(
                        "  note: {} still contains a private key. Remove it: rm '{}'",
                        file.display(),
                        file.display()
                    );
                }
            }
            Err(e) => {
                failures += 1;
                println!("{}: not imported: {e:#}", file.display());
            }
        }
    }
    notify_daemon(paths);
    if failures > 0 {
        bail!("{failures} of {} file(s) failed", files.len());
    }
    Ok(())
}

fn import_one(store: &ProfileStore, overrides: &Overrides, file: &Path) -> anyhow::Result<()> {
    let bytes = read_secret_file(file, MAX_CONFIG_BYTES)
        .with_context(|| format!("reading {}", file.display()))?;
    let parsed = profile::parse_bytes(&bytes)?;
    let stem = file.file_stem().map(|s| s.to_string_lossy().into_owned());
    let identity = profile::identity(parsed.peer_comment.as_deref(), stem.as_deref(), overrides)?;
    for warning in &parsed.warnings {
        println!("  warning: {warning}");
    }
    let outcome = store.import(parsed, identity, UnixMillis::now())?;
    let p = &outcome.profile;
    let country = p.country_code.as_deref().map_or_else(
        || "no country".to_owned(),
        |c| format!("{} ({c})", country::lookup(c).map_or(c, |x| x.name)),
    );
    println!(
        "{} {} as {}: {}, entry {}",
        if outcome.replaced {
            "updated"
        } else {
            "imported"
        },
        file.display(),
        p.id,
        country,
        p.endpoint()
    );
    Ok(())
}

fn notify_daemon(paths: &Paths) {
    if let Ok(mut client) = Client::connect(&paths.socket)
        && client.call(Wire::ReloadProfiles).is_ok()
    {
        println!("the running daemon reloaded its profiles");
    }
}

fn list(paths: &Paths, json: bool) -> anyhow::Result<()> {
    let servers: Vec<Server> = if nix::unistd::geteuid().is_root() {
        let store = ProfileStore::new(&paths.profiles_dir, 0);
        store
            .list()?
            .iter()
            .map(vpnui_daemon::engine::engine::server_of)
            .collect()
    } else {
        Client::connect(&paths.socket)
            .and_then(|mut c| c.snapshot())
            .map(|s| s.servers)
            .context("listing needs root, or a running daemon to ask")?
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&servers)?);
        return Ok(());
    }
    if servers.is_empty() {
        println!(
            "No profiles yet. Download WireGuard configs from your account, then run: sudo vpnuid import <files>"
        );
        return Ok(());
    }
    let mut groups: BTreeMap<(String, String), Vec<&Server>> = BTreeMap::new();
    for s in &servers {
        groups
            .entry((s.country.clone(), s.country_code.clone()))
            .or_default()
            .push(s);
    }
    for ((country, code), members) in groups {
        println!("{country} ({code})");
        for s in members {
            let entry = s
                .entry_ip
                .map_or_else(|| "—".to_owned(), |ip| ip.to_string());
            println!("  {:<28} {:<20} entry {entry}", s.id, s.name);
        }
    }
    Ok(())
}

fn remove(paths: &Paths, id: &str) -> anyhow::Result<()> {
    require_root("remove")?;
    let removed = ProfileStore::new(&paths.profiles_dir, 0).remove(id)?;
    println!("removed {} ({})", removed.id, removed.name);
    notify_daemon(paths);
    Ok(())
}

fn status(paths: &Paths, json: bool) -> anyhow::Result<()> {
    let snapshot: Snapshot = Client::connect(&paths.socket)?.snapshot()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
        return Ok(());
    }
    println!("protocol    v{}", snapshot.protocol_version.0);
    println!("tunnel      {:?}", snapshot.tunnel);
    println!("kill switch {:?}", snapshot.kill_switch);
    println!(
        "settings    allow_lan={} block_ipv6={} auto_reconnect={}",
        snapshot.settings.allow_lan, snapshot.settings.block_ipv6, snapshot.settings.auto_reconnect
    );
    println!("profiles    {}", snapshot.profiles_count);
    Ok(())
}

fn install_cmd(
    paths: &Paths,
    user: Option<String>,
    wireguard_go: Option<PathBuf>,
    yes: bool,
    dry_run: bool,
) -> anyhow::Result<()> {
    if !dry_run {
        require_root("install")?;
    }
    let user_name = user
        .or_else(|| std::env::var("SUDO_USER").ok())
        .context("pass --user NAME (the account that will run vpnui)")?;
    let account = nix::unistd::User::from_name(&user_name)?
        .with_context(|| format!("no user named {user_name}"))?;
    let source = install::find_wireguard_go(wireguard_go.as_deref())
        .ok_or(install::InstallError::NoWireguardGo)?;
    let me = std::env::current_exe().context("locating this vpnuid binary")?;
    let plan = install::install_plan(&InstallInput {
        paths,
        user: user_name.clone(),
        uid: account.uid.as_raw(),
        gid: account.gid.as_raw(),
        wireguard_go: &source,
        vpnuid: &me,
    })?;
    if let Some(record) = &plan.record {
        println!(
            "wireguard-go  {}  sha256 {}",
            source.display(),
            record.wireguard_go.sha256
        );
        println!(
            "vpnuid        {}  sha256 {}",
            me.display(),
            record.vpnuid.sha256
        );
        println!("allowed user  {user_name} (uid {})", record.uid);
    }
    if let Err(e) = install::check_parents(&paths.libexec) {
        println!("warning: install would refuse: {e}");
    }
    println!("{} steps:", if dry_run { "would run" } else { "running" });
    if dry_run {
        for step in &plan.steps {
            println!("  {}", step.describe());
        }
        return Ok(());
    }
    if !yes {
        bail!("review the hashes above, then rerun with --yes");
    }
    install::check_parents(&paths.libexec)?;
    install::execute(&plan, &mut || {})?;
    println!("installed; the daemon starts now and at every boot");
    Ok(())
}

fn uninstall_cmd(paths: &Paths, dry_run: bool) -> anyhow::Result<()> {
    if !dry_run {
        require_root("uninstall")?;
    }
    let plan = install::uninstall_plan(paths);
    if dry_run {
        println!("would run steps:");
        for step in &plan.steps {
            println!("  {}", step.describe());
        }
        return Ok(());
    }
    let platform = platform(paths);
    install::execute(&plan, &mut || {
        for line in rescue::rescue(&platform) {
            println!("    rescue: {line}");
        }
    })?;
    println!(
        "uninstalled. Imported profiles remain in {}; remove them with sudo rm -r",
        paths.profiles_dir.display()
    );
    Ok(())
}

fn doctor_cmd(paths: &Paths) -> anyhow::Result<()> {
    require_root("doctor")?;
    let platform = platform(paths);
    let check = |ok: bool, text: String| println!("[{}] {text}", if ok { " ok " } else { "warn" });

    match platform.pf_is_enabled() {
        Ok(enabled) => check(
            true,
            format!("pf is {}", if enabled { "enabled" } else { "disabled" }),
        ),
        Err(e) => check(false, format!("pf status unavailable: {e}")),
    }
    let state =
        platform.load_state().ok().flatten().and_then(|json| {
            serde_json::from_str::<vpnui_daemon::state::PersistedState>(&json).ok()
        });
    let armed = state.as_ref().is_some_and(|s| s.armed);
    check(
        true,
        format!(
            "kill switch is {}",
            if armed { "armed" } else { "disarmed" }
        ),
    );
    check(
        true,
        format!(
            "pf token held: {}",
            state.as_ref().and_then(|s| s.pf_token.as_ref()).is_some()
        ),
    );
    let rules = Cmd::new(paths::PFCTL)
        .args(["-a", Anchor::KillSwitch.name(), "-s", "rules"])
        .output();
    let loaded = rules.as_ref().is_ok_and(|o| !o.stdout.trim().is_empty());
    check(
        loaded == armed,
        format!("anchor {} has rules: {loaded}", Anchor::KillSwitch.name()),
    );

    match install::read_record(paths) {
        Some(record) => {
            for pinned in [&record.wireguard_go, &record.vpnuid] {
                match trust::verify(pinned, &[0]) {
                    Ok(()) => check(
                        true,
                        format!(
                            "{} matches its pinned sha256 {}",
                            pinned.path.display(),
                            pinned.sha256
                        ),
                    ),
                    Err(e) => check(false, format!("{e}")),
                }
            }
        }
        None => check(
            false,
            "not installed (no install record); connects need `sudo vpnuid install`".into(),
        ),
    }
    let store = ProfileStore::new(&paths.profiles_dir, 0);
    match store.check_private() {
        Ok(()) => check(true, format!("{} is private", paths.profiles_dir.display())),
        Err(e) => check(false, format!("{e}")),
    }
    let journal = state.as_ref().map_or(0, |s| s.journal.len());
    check(journal == 0, format!("journal entries pending: {journal}"));

    let connected = Client::connect(&paths.socket)
        .and_then(|mut c| c.snapshot())
        .is_ok_and(|s| s.tunnel.is_connected());
    if connected {
        match Cmd::new(paths::SCUTIL).arg("--dns").run() {
            Ok(out) => {
                let ours = out.stdout.contains(paths::DNS_SERVICE_ID)
                    || out.stdout.contains("Supplemental");
                check(
                    ours,
                    "scutil --dns shows a supplemental match-all resolver".into(),
                );
            }
            Err(e) => check(false, format!("scutil --dns failed: {e}")),
        }
    }

    match doctor::self_test(&platform) {
        SelfTest::Passed { before, after } => check(
            true,
            format!("pf self-test passed: probe counted ({before} -> {after})"),
        ),
        SelfTest::Failed(reason) => check(false, format!("pf self-test FAILED: {reason}")),
        SelfTest::RefusedArmed => check(
            false,
            "pf self-test skipped: disarm the kill switch first".into(),
        ),
        SelfTest::SkippedNoRoute => check(false, "pf self-test skipped: no default route".into()),
    }
    Ok(())
}
