#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, ValueEnum};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use vpnui_proto::{default_socket_path, validate_socket_path};
use vpnui_tui::terminal::{self, EXIT_MESSAGE};
use vpnui_tui::theme::{ColorMode, Theme};

#[derive(Debug, Parser)]
#[command(
    name = "vpnui",
    version,
    about = "Terminal client for the vpnui daemon"
)]
struct Args {
    /// Daemon socket [default: /var/run/vpnui/vpnui.sock]
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Draw borders, bars, and symbols with ASCII only.
    #[arg(long)]
    ascii: bool,
    /// Color output. `auto` honors NO_COLOR and COLORTERM.
    #[arg(long, value_enum, default_value_t = ColorArg::Auto)]
    color: ColorArg,
    /// Log file [default: ~/Library/Logs/vpnui/vpnui.log on macOS]
    #[arg(long)]
    log_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ColorArg {
    Auto,
    Truecolor,
    #[value(name = "16")]
    Ansi16,
    Never,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => {
            println!("{EXIT_MESSAGE}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("vpnui: {err:#}");
            println!("{EXIT_MESSAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> anyhow::Result<()> {
    let socket = args.socket.unwrap_or_else(default_socket_path);
    validate_socket_path(&socket)?;
    let log_file = args.log_file.map_or_else(default_log_file, Ok)?;
    let _log_guard = init_logging(&log_file)?;
    tracing::info!(socket = %socket.display(), "starting");

    let mode = match args.color {
        ColorArg::Auto => ColorMode::detect(
            std::env::var("NO_COLOR").ok().as_deref(),
            std::env::var("COLORTERM").ok().as_deref(),
        ),
        ColorArg::Truecolor => ColorMode::TrueColor,
        ColorArg::Ansi16 => ColorMode::Ansi16,
        ColorArg::Never => ColorMode::None,
    };
    let theme = Theme::new(mode, args.ascii);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting async runtime")?;
    let mut tui = terminal::enter().context("setting up the terminal")?;
    let result = runtime.block_on(vpnui_tui::runtime::run(&mut tui, socket, theme));
    terminal::restore();
    runtime.shutdown_timeout(Duration::from_millis(200));
    tracing::info!("exited");
    result
}

fn default_log_file() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set; pass --log-file")?;
    let home = PathBuf::from(home);
    let dir = if cfg!(target_os = "macos") {
        home.join("Library/Logs/vpnui")
    } else {
        std::env::var_os("XDG_STATE_HOME")
            .map_or_else(|| home.join(".local/state"), PathBuf::from)
            .join("vpnui")
    };
    Ok(dir.join("vpnui.log"))
}

fn init_logging(path: &std::path::Path) -> anyhow::Result<WorkerGuard> {
    let dir = path.parent().context("log file has no parent directory")?;
    let name = path.file_name().context("log file has no name")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let (writer, guard) =
        tracing_appender::non_blocking(tracing_appender::rolling::never(dir, name));
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(writer)
        .with_ansi(false)
        .init();
    Ok(guard)
}
