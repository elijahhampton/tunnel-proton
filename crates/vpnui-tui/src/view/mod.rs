//! Rendering. Every function here reads `AppState` and writes to the frame; nothing blocks or
//! mutates.

mod home;
mod modal;
mod rail;
mod servers;
mod settings;
mod stats;
mod widgets;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

pub use stats::HANDSHAKE_STALE_AFTER;

use crate::app::{AppState, DaemonLink, Modal, VersionMismatch, View};
use crate::format;
use crate::layout::{self, Mode, ViewAreas};

pub fn view(state: &AppState, frame: &mut Frame) {
    let area = frame.area();
    let layout = layout::compute(area, state.ui.view);
    match layout.mode {
        Mode::TooSmall => return too_small(frame, area, state),
        Mode::Wide | Mode::Narrow => {}
    }
    if let Some(mismatch) = state.version_mismatch {
        return version_mismatch(frame, area, state, mismatch);
    }

    header(frame, layout.header, state);
    if let Some(rail) = layout.rail {
        rail::render(frame, rail, state);
    }
    if let Some(bar) = layout.status_bar {
        rail::status_bar(frame, bar, state);
    }
    tabs(frame, &layout, state);
    match layout.view {
        Some(ViewAreas::Home { map, recents, help }) => {
            home::render(frame, state, map, recents, help);
        }
        Some(ViewAreas::Servers { tree, detail }) => {
            servers::render(frame, state, &layout, tree, detail);
        }
        Some(ViewAreas::Stats {
            rx,
            tx,
            session,
            log,
        }) => stats::render(frame, state, rx, tx, session, log),
        Some(ViewAreas::Settings { list, detail }) => {
            settings::render(frame, state, list, detail);
        }
        None => {}
    }
    footer(frame, layout.footer, state);

    match &state.ui.modal {
        Some(Modal::Help { scroll }) => modal::help(frame, area, state, *scroll),
        Some(Modal::Confirm { kind, selected }) => {
            modal::confirm(frame, area, state, kind, *selected);
        }
        None => {}
    }
}

fn header(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = &state.theme;
    let left = Line::from(vec![
        Span::styled(" vpnui ", theme.title),
        Span::styled("personal VPN client", theme.dim),
    ]);
    let badge = match state.link {
        DaemonLink::Live => Span::styled(format!("{} daemon live ", theme.sym.live), theme.ok),
        DaemonLink::Connecting => Span::styled(
            format!(
                "{} connecting to daemon{} ",
                theme.sym.live, theme.sym.ellipsis
            ),
            theme.warn,
        ),
        DaemonLink::Lost {
            since,
            next_retry_at,
        } => {
            let remaining = state.now.until(next_retry_at);
            let retry = if remaining.is_zero() {
                format!("retrying{}", theme.sym.ellipsis)
            } else {
                format!("retry in {}", format::countdown(remaining))
            };
            Span::styled(
                format!(
                    "{} daemon lost {} {} {retry} ",
                    theme.sym.exposed,
                    format::duration(state.now.since(since)),
                    theme.sym.separator,
                ),
                theme.error,
            )
        }
    };
    let badge_width = format::width(&badge.content) as u16;
    let [left_area, right_area] = area.layout(&Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(badge_width),
    ]));
    frame.render_widget(Paragraph::new(left), left_area);
    frame.render_widget(
        Paragraph::new(Line::from(badge)).right_aligned(),
        right_area,
    );
}

fn tabs(frame: &mut Frame, layout: &layout::AppLayout, state: &AppState) {
    let theme = &state.theme;
    let mut spans = vec![Span::raw(" ")];
    for view in View::ALL {
        let style = if view == state.ui.view {
            theme.tab_active
        } else {
            theme.tab_inactive
        };
        spans.push(Span::styled(layout::tab_label(view), style));
        spans.push(Span::raw(" "));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), layout.tabs);

    if let Some(stale) = widgets::stale_label(state) {
        let text = format!("{stale} ");
        let width = format::width(&text) as u16;
        let used = layout.tab_hits().last().map_or(0, |(_, r)| r.right());
        if layout.tabs.right().saturating_sub(used) > width {
            let area = Rect {
                x: layout.tabs.right() - width,
                width,
                ..layout.tabs
            };
            frame.render_widget(Paragraph::new(Span::styled(text, theme.warn)), area);
        }
    }
}

fn footer(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = &state.theme;
    let toast = state.toast.as_ref().map(|toast| {
        let glyph = widgets::severity_glyph(theme, toast.severity);
        (
            format!("{glyph} {} ", toast.text),
            widgets::severity_style(theme, toast.severity),
        )
    });
    let max_toast = usize::from(area.width) * 3 / 5;
    let toast_width = toast
        .as_ref()
        .map_or(0, |(text, _)| format::width(text).min(max_toast)) as u16;
    let [hints_area, toast_area] = area.layout(&Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(toast_width),
    ]));

    let hints = footer_hints(state);
    let line = widgets::key_hints(
        theme,
        &hints,
        usize::from(hints_area.width.saturating_sub(1)),
    );
    frame.render_widget(
        Paragraph::new(Line::from([vec![Span::raw(" ")], line.spans].concat())),
        hints_area,
    );
    if let Some((text, style)) = toast {
        let text = format::truncate(&text, usize::from(toast_width), theme.sym.ellipsis);
        frame.render_widget(
            Paragraph::new(Span::styled(text.into_owned(), style)).right_aligned(),
            toast_area,
        );
    }
}

fn footer_hints(state: &AppState) -> Vec<(&'static str, String)> {
    footer_keys(state)
        .into_iter()
        .map(|(key, desc)| match (key, quick_connect_target(state)) {
            ("c", Some(name)) => (key, format!("{desc} ({name})")),
            (_, _) => (key, desc.to_owned()),
        })
        .collect()
}

fn quick_connect_target(state: &AppState) -> Option<String> {
    let server = state.live()?.quick_connect_target()?;
    Some(format::truncate(&server.name, 16, state.theme.sym.ellipsis).into_owned())
}

fn footer_keys(state: &AppState) -> Vec<(&'static str, &'static str)> {
    match &state.ui.modal {
        Some(Modal::Confirm { .. }) => {
            return vec![("j/k", "choose"), ("Enter", "confirm"), ("Esc", "cancel")];
        }
        Some(Modal::Help { .. }) => return vec![("j/k", "scroll"), ("Esc", "close")],
        None => {}
    }
    if state.ui.browser.typing && state.ui.view == View::Servers {
        return vec![
            ("type", "to filter"),
            ("Enter", "done"),
            ("Esc", "clear"),
            ("Up/Down", "move"),
        ];
    }
    match state.ui.view {
        View::Home => vec![
            ("c", "quick connect"),
            ("d", "disconnect"),
            ("s", "kill switch"),
            ("Enter", "connect recent"),
            ("2", "servers"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::Servers => vec![
            ("j/k", "move"),
            ("h/l", "fold"),
            ("Enter", "connect"),
            ("/", "search"),
            ("o", "sort"),
            ("?", "help"),
        ],
        View::Stats => vec![
            ("j/k", "scroll log"),
            ("1-4", "views"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::Settings => vec![
            ("j/k", "move"),
            ("Enter", "toggle"),
            ("s", "kill switch"),
            ("?", "help"),
        ],
    }
}

fn too_small(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = &state.theme;
    let message = format!(
        "terminal too small (have {}x{}, need {}x{})",
        area.width,
        area.height,
        layout::MIN_WIDTH,
        layout::MIN_HEIGHT
    );
    let width = usize::from(area.width);
    let mut lines: Vec<Line<'_>> = format::wrap(&message, width)
        .into_iter()
        .map(|l| Line::from(Span::styled(l, theme.warn)))
        .collect();
    lines.extend(
        format::wrap("press q to quit", width)
            .into_iter()
            .map(|l| Line::from(Span::styled(l, theme.dim))),
    );
    let height = (lines.len() as u16).min(area.height);
    let target = Rect {
        y: area.y + (area.height - height) / 2,
        height,
        ..area
    };
    frame.render_widget(Paragraph::new(lines).centered(), target);
}

fn version_mismatch(frame: &mut Frame, area: Rect, state: &AppState, mismatch: VersionMismatch) {
    let theme = &state.theme;
    let daemon = mismatch
        .daemon
        .map_or_else(|| "an unknown version".to_owned(), |v| v.to_string());
    let lines = vec![
        Line::from(Span::styled("Protocol version mismatch", theme.error)),
        Line::default(),
        Line::from(format!(
            "This client speaks protocol {}. The daemon speaks {daemon}.",
            mismatch.client
        )),
        Line::from("Install matching versions of vpnui and its daemon, then restart vpnui."),
        Line::default(),
        Line::from(Span::styled(
            "Nothing was changed. Press q to quit.",
            theme.dim,
        )),
    ];
    let block = widgets::block(theme, widgets::title(theme, "vpnui")).border_style(theme.error);
    let width = area.width.min(76);
    let height = area.height.min(10);
    let popup = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: true })
            .centered(),
        popup,
    );
}

#[cfg(test)]
mod tests;
