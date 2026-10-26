use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Block;
use vpnui_proto::{KillSwitchState, UnixMillis};

use crate::app::{AppState, DaemonLink, Severity, Slot};
use crate::format;
use crate::theme::Theme;

pub fn block<'a>(theme: &Theme, title: impl Into<Line<'a>>) -> Block<'a> {
    Block::bordered()
        .border_set(theme.sym.border)
        .border_style(theme.border)
        .title(title)
}

pub fn title(theme: &Theme, text: impl Into<String>) -> Span<'static> {
    Span::styled(format!(" {} ", text.into()), theme.title)
}

/// `cells`-wide bar colored by load threshold, then the percentage; `—` alone when unknown.
pub fn load_bar(theme: &Theme, pct: Option<u8>, cells: usize, stale: bool) -> Vec<Span<'static>> {
    match pct {
        Some(pct) => known_load_bar(theme, pct, cells, stale),
        None => vec![missing(theme, stale)],
    }
}

/// Like [`load_bar`], but an unknown load keeps the bar's column width so rows stay aligned.
pub fn load_column(
    theme: &Theme,
    pct: Option<u8>,
    cells: usize,
    stale: bool,
) -> Vec<Span<'static>> {
    match pct {
        Some(pct) => known_load_bar(theme, pct, cells, stale),
        None => {
            let pad = if cells > 0 { cells + 1 } else { 0 };
            vec![
                Span::raw(" ".repeat(pad)),
                Span::styled(
                    format::pad_left(theme.sym.missing, 3),
                    if stale { theme.stale } else { theme.dim },
                ),
            ]
        }
    }
}

pub fn missing(theme: &Theme, stale: bool) -> Span<'static> {
    Span::styled(
        theme.sym.missing,
        if stale { theme.stale } else { theme.dim },
    )
}

fn known_load_bar(theme: &Theme, pct: u8, cells: usize, stale: bool) -> Vec<Span<'static>> {
    let filled = (usize::from(pct.min(100)) * cells + 50) / 100;
    let style = if stale { theme.stale } else { theme.load(pct) };
    let mut spans = Vec::with_capacity(3);
    if cells > 0 {
        spans.push(Span::styled(theme.sym.bar_full.repeat(filled), style));
        spans.push(Span::styled(
            theme.sym.bar_empty.repeat(cells - filled),
            if stale { theme.stale } else { theme.dim },
        ));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(format!("{pct:>2}%"), style));
    spans
}

/// The daemon is reachable (or was) and reports that nothing has been imported.
pub fn no_profiles(state: &AppState) -> bool {
    state.daemon.as_ref().is_some_and(|p| p.profiles_count == 0)
}

pub fn no_profiles_text(theme: &Theme) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled("No profiles yet.", theme.title)),
        Line::from(Span::styled(
            "Download WireGuard configs from your account, then run:",
            theme.text,
        )),
        Line::from(Span::styled("  sudo vpnuid import <files>", theme.key)),
        Line::default(),
        Line::from(Span::styled(
            "Only countries you import profiles for appear here.",
            theme.dim,
        )),
    ]
}

pub fn spinner(theme: &Theme, now: UnixMillis) -> &'static str {
    let frames = theme.sym.spinner;
    let index = (now.0 / 100) as usize % frames.len().max(1);
    frames.get(index).copied().unwrap_or("")
}

pub fn severity_style(theme: &Theme, severity: Severity) -> Style {
    match severity {
        Severity::Info => theme.text,
        Severity::Success => theme.ok,
        Severity::Warn => theme.warn,
        Severity::Error => theme.error,
    }
}

pub fn severity_glyph(theme: &Theme, severity: Severity) -> &'static str {
    match severity {
        Severity::Info => theme.sym.separator,
        Severity::Success => theme.sym.protected,
        Severity::Warn => theme.sym.warning,
        Severity::Error => theme.sym.exposed,
    }
}

/// `stale (12s ago)` while showing data from a link that is no longer live.
pub fn stale_label(state: &AppState) -> Option<String> {
    if !state.is_stale() {
        return None;
    }
    let since = match state.link {
        DaemonLink::Lost { since, .. } => since,
        DaemonLink::Connecting | DaemonLink::Live => state.lost_since.unwrap_or(state.now),
    };
    Some(format!("stale ({})", format::ago(state.now.since(since))))
}

/// The clock to measure daemon-reported times against, frozen at the moment the data went
/// stale.
pub fn data_now(state: &AppState) -> UnixMillis {
    if state.is_stale() {
        state.lost_since.unwrap_or(state.now)
    } else {
        state.now
    }
}

/// Text style, or the stale style when the data is not current.
pub fn data_style(state: &AppState, style: Style) -> Style {
    if state.is_stale() {
        state.theme.stale
    } else {
        style
    }
}

pub fn pending_label(state: &AppState, slot: Slot) -> Option<Span<'static>> {
    state.pending(slot).map(|_| {
        Span::styled(
            format!(" pending{}", state.theme.sym.ellipsis),
            state.theme.warn,
        )
    })
}

pub fn kill_switch_span(state: &AppState, kill_switch: &KillSwitchState) -> Span<'static> {
    let theme = &state.theme;
    let (text, style) = match kill_switch {
        KillSwitchState::Armed => (format!("{} ARMED", theme.sym.blocked), theme.ok),
        KillSwitchState::Off => ("OFF".to_owned(), theme.dim),
        KillSwitchState::Error { .. } => (format!("{} ERROR", theme.sym.warning), theme.error),
        KillSwitchState::Unknown => ("UNKNOWN".to_owned(), theme.dim),
    };
    Span::styled(text, data_style(state, style))
}

pub fn key_hints<K: AsRef<str>, D: AsRef<str>>(
    theme: &Theme,
    hints: &[(K, D)],
    max_width: usize,
) -> Line<'static> {
    let mut spans = Vec::new();
    let mut used = 0;
    for (key, desc) in hints {
        let (key, desc) = (key.as_ref(), desc.as_ref());
        let piece = format::width(key) + 1 + format::width(desc) + 2;
        if used + piece > max_width {
            break;
        }
        used += piece;
        spans.push(Span::styled(key.to_owned(), theme.key));
        spans.push(Span::styled(format!(" {desc}  "), theme.dim));
    }
    Line::from(spans)
}
