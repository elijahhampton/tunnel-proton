#![forbid(unsafe_code)]

use std::fs::{self, Permissions};
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::{Parser, ValueEnum};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tracing::info;
use tracing_subscriber::EnvFilter;
use vpnui_mockd::{Config, Control, Scenario, serve};
use vpnui_proto::{mock_socket_path, validate_socket_path};

const HELP: &str = "\
commands:
  drop       drop the tunnel as if the peer went away
  fail-next  make the next handshake fail
  ks-error   put the kill switch into an error state
  ks-clear   clear the kill-switch error and re-apply the policy
  crash      exit immediately without cleanup (socket file is left behind)
  help       show this list";

#[derive(Debug, Parser)]
#[command(
    name = "vpnui-mockd",
    version,
    about = "Mock vpnui daemon on a Unix domain socket"
)]
struct Args {
    /// Socket path [default: $TMPDIR/vpnui.sock]
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Seed for the server catalog and all simulated randomness.
    #[arg(long, default_value_t = 1)]
    seed: u64,
    #[arg(long, value_enum, default_value_t = ScenarioArg::Calm)]
    scenario: ScenarioArg,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ScenarioArg {
    Calm,
    Flaky,
}

impl From<ScenarioArg> for Scenario {
    fn from(arg: ScenarioArg) -> Self {
        match arg {
            ScenarioArg::Calm => Self::Calm,
            ScenarioArg::Flaky => Self::Flaky,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let path = args.socket.unwrap_or_else(mock_socket_path);
    validate_socket_path(&path)?;
    let listener = bind(&path)?;
    fs::set_permissions(&path, Permissions::from_mode(0o600))
        .with_context(|| format!("setting permissions on {}", path.display()))?;

    let (control_tx, control_rx) = mpsc::channel(16);
    tokio::spawn(read_operator_commands(control_tx));

    let scenario = Scenario::from(args.scenario);
    println!(
        "vpnui-mockd listening on {} (seed {}, scenario {:?}). Type `help` for commands.",
        path.display(),
        args.seed,
        scenario
    );
    let config = Config::new(args.seed, scenario).with_control(control_rx);

    let result = tokio::select! {
        served = serve(listener, config) => served.map_err(anyhow::Error::from),
        signal = shutdown_signal() => signal,
    };
    if let Err(err) = fs::remove_file(&path)
        && err.kind() != ErrorKind::NotFound
    {
        eprintln!("vpnui-mockd: could not remove {}: {err}", path.display());
    }
    info!("shut down");
    result
}

/// Binds `path`, replacing a socket file only when nothing is listening on it.
fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                bail!(
                    "{} exists and is not a socket; refusing to replace it",
                    path.display()
                );
            }
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                bail!("another daemon is already listening on {}", path.display());
            }
            fs::remove_file(path)
                .with_context(|| format!("removing stale socket {}", path.display()))?;
            info!(path = %path.display(), "removed stale socket");
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", path.display()));
        }
    }
    UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))
}

async fn shutdown_signal() -> anyhow::Result<()> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = interrupt.recv() => info!("SIGINT"),
        _ = terminate.recv() => info!("SIGTERM"),
    }
    Ok(())
}

async fn read_operator_commands(control: mpsc::Sender<Control>) {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let command = match line.trim() {
            "" => continue,
            "drop" => Control::Drop,
            "fail-next" => Control::FailNext,
            "ks-error" => Control::KillSwitchError,
            "ks-clear" => Control::KillSwitchClear,
            "crash" => {
                eprintln!("vpnui-mockd: crashing on request");
                std::process::exit(101);
            }
            "help" => {
                println!("{HELP}");
                continue;
            }
            other => {
                println!("unknown command {other:?}\n{HELP}");
                continue;
            }
        };
        if control.send(command).await.is_err() {
            return;
        }
        println!("ok: {command:?}");
    }
}
