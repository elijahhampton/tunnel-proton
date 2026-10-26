//! The impure shell around [`update`]: feeds it events from the terminal, the daemon link,
//! signals, and a timer, and carries out the effects it returns.

use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{Event as TermEvent, EventStream, MouseEventKind};
use futures::StreamExt;
use ratatui::Terminal;
use ratatui::backend::Backend;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};
use tracing::{debug, error, info, warn};
use vpnui_proto::{Request, UnixMillis};

use crate::app::{AppState, Effect, Event, Severity, update};
use crate::link;
use crate::theme::Theme;
use crate::view::view;

const ANIMATION_TICK: Duration = Duration::from_millis(100);
const IDLE_TICK: Duration = Duration::from_secs(1);
const EVENT_QUEUE: usize = 1024;

/// State plus the outbound command channel; everything needed to run the reducer headless.
pub struct Core {
    state: AppState,
    commands: mpsc::UnboundedSender<Request>,
}

impl Core {
    pub fn new(state: AppState, commands: mpsc::UnboundedSender<Request>) -> Self {
        Self { state, commands }
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Applies `event` and performs its effects. Returns true when the app should exit.
    pub fn dispatch(&mut self, event: Event) -> bool {
        let mut quit = false;
        for effect in update(&mut self.state, event) {
            match effect {
                Effect::Send(request) => {
                    debug!(id = %request.id, cmd = request.cmd.name(), "send");
                    if self.commands.send(request).is_err() {
                        error!("daemon link task has stopped");
                    }
                }
                Effect::Log(Severity::Error, message) => error!("{message}"),
                Effect::Log(Severity::Warn, message) => warn!("{message}"),
                Effect::Log(Severity::Info | Severity::Success, message) => info!("{message}"),
                Effect::Quit => quit = true,
            }
        }
        quit
    }

    pub fn tick_interval(&self) -> Duration {
        if self.state.animating() {
            ANIMATION_TICK
        } else {
            IDLE_TICK
        }
    }
}

/// Spawns the daemon link on `socket` and returns the event channel plus a ready [`Core`].
pub fn start(
    socket: PathBuf,
    theme: Theme,
    width: u16,
    height: u16,
) -> (
    Core,
    mpsc::Sender<Event>,
    mpsc::Receiver<Event>,
    tokio::task::JoinHandle<()>,
) {
    let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
    let (commands_tx, commands_rx) = mpsc::unbounded_channel();
    let link = tokio::spawn(link::run(socket, commands_rx, events_tx.clone()));
    let state = AppState::new(theme, UnixMillis::now(), width, height);
    (Core::new(state, commands_tx), events_tx, events_rx, link)
}

pub async fn run<B: Backend>(
    terminal: &mut Terminal<B>,
    socket: PathBuf,
    theme: Theme,
) -> anyhow::Result<()>
where
    B::Error: Send + Sync + 'static,
{
    let size = terminal.size()?;
    let (mut core, events_tx, mut events, link) = start(socket, theme, size.width, size.height);
    let input = tokio::spawn(forward_input(events_tx.clone()));
    let signals = tokio::spawn(forward_signals(events_tx));

    core.dispatch(Event::Tick(UnixMillis::now()));
    terminal.draw(|frame| view(core.state(), frame))?;
    let mut next_tick = Instant::now() + core.tick_interval();

    loop {
        let event = tokio::select! {
            event = events.recv() => match event {
                Some(event) => event,
                None => break,
            },
            () = sleep_until(next_tick) => {
                next_tick = Instant::now() + core.tick_interval();
                Event::Tick(UnixMillis::now())
            }
        };
        let mut quit = core.dispatch(event);
        while !quit && let Ok(event) = events.try_recv() {
            quit = core.dispatch(event);
        }
        if quit {
            break;
        }
        next_tick = next_tick.min(Instant::now() + core.tick_interval());
        terminal.draw(|frame| view(core.state(), frame))?;
    }

    input.abort();
    signals.abort();
    link.abort();
    Ok(())
}

async fn forward_input(events: mpsc::Sender<Event>) {
    let mut stream = EventStream::new();
    while let Some(next) = stream.next().await {
        let event = match next {
            Ok(TermEvent::Key(key)) => Event::Key(key),
            Ok(TermEvent::Mouse(mouse)) => match mouse.kind {
                MouseEventKind::Moved | MouseEventKind::Drag(_) => continue,
                MouseEventKind::Down(_)
                | MouseEventKind::Up(_)
                | MouseEventKind::ScrollDown
                | MouseEventKind::ScrollUp
                | MouseEventKind::ScrollLeft
                | MouseEventKind::ScrollRight => Event::Mouse(mouse),
            },
            Ok(TermEvent::Resize(width, height)) => Event::Resize(width, height),
            Ok(TermEvent::FocusGained | TermEvent::FocusLost | TermEvent::Paste(_)) => continue,
            Err(err) => {
                error!(%err, "terminal input failed");
                Event::Shutdown
            }
        };
        if events.send(event).await.is_err() {
            return;
        }
    }
}

async fn forward_signals(events: mpsc::Sender<Event>) {
    let (Ok(mut interrupt), Ok(mut terminate), Ok(mut hangup)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
        signal(SignalKind::hangup()),
    ) else {
        error!("could not install signal handlers");
        return;
    };
    let name = tokio::select! {
        _ = interrupt.recv() => "SIGINT",
        _ = terminate.recv() => "SIGTERM",
        _ = hangup.recv() => "SIGHUP",
    };
    info!(signal = name, "shutting down");
    let _ = events.send(Event::Shutdown).await;
}
