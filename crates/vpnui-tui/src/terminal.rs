//! Raw mode and the alternate screen, restored on every exit path.

use std::io::{self, Stdout, stdout};

use crossterm::cursor::{Hide, Show};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

pub const EXIT_MESSAGE: &str = "vpnui: exited; tunnel and kill switch left unchanged.";

pub type Tui = Terminal<CrosstermBackend<Stdout>>;

pub fn enter() -> io::Result<Tui> {
    install_panic_hook();
    enable_raw_mode()?;
    if let Err(err) = execute!(stdout(), EnterAlternateScreen, EnableMouseCapture, Hide) {
        restore();
        return Err(err);
    }
    Terminal::new(CrosstermBackend::new(stdout())).inspect_err(|_| restore())
}

/// Idempotent and infallible; also runs from the panic hook.
pub fn restore() {
    let _ = execute!(stdout(), DisableMouseCapture, LeaveAlternateScreen, Show);
    let _ = disable_raw_mode();
}

/// A panic on any thread restores the terminal, prints the report, and exits.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        previous(info);
        eprintln!("{EXIT_MESSAGE}");
        std::process::exit(101);
    }));
}
