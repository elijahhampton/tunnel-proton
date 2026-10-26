use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use vpnui_proto::KillSwitchState;

use super::widgets::{self, data_style};
use crate::app::{AppState, SettingKey, SettingRow, Slot};
use crate::format;
use crate::layout;

pub fn render(frame: &mut Frame, state: &AppState, list: Rect, detail: Rect) {
    let theme = &state.theme;
    let mut title = vec![widgets::title(theme, "Settings")];
    if let Some(stale) = widgets::stale_label(state) {
        title.push(Span::styled(format!("{stale}, read-only "), theme.warn));
    }
    frame.render_widget(widgets::block(theme, Line::from(title)), list);
    let rows = layout::inner(list);

    let label_width = usize::from(rows.width).saturating_sub(24).clamp(12, 34);
    let lines: Vec<Line<'_>> = SettingRow::ALL
        .iter()
        .enumerate()
        .map(|(index, &row)| {
            let selected = index == state.ui.settings_cursor;
            let pointer = if selected { theme.sym.pointer } else { " " };
            let mut spans = vec![
                Span::styled(format!("{pointer} "), theme.accent),
                Span::styled(
                    format::fit(row.label(), label_width, theme.sym.ellipsis),
                    theme.text,
                ),
                Span::raw(" "),
            ];
            spans.extend(value(state, row));
            let line = Line::from(spans);
            if selected {
                line.style(theme.selected)
            } else {
                line
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), rows);

    let row = SettingRow::ALL
        .get(state.ui.settings_cursor)
        .copied()
        .unwrap_or(SettingRow::KillSwitch);
    let block = widgets::block(theme, widgets::title(theme, row.label()));
    let inner = layout::inner(detail);
    frame.render_widget(block, detail);
    let (enter, enter_style) = enter_action(state, row);
    let text = vec![
        Line::from(Span::styled(row.description(), theme.text)),
        Line::default(),
        Line::from(vec![
            Span::styled("Enter ", theme.key),
            Span::styled(enter, enter_style),
        ]),
    ];
    frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), inner);
}

/// The daemon-confirmed value, followed by `pending…` while a change is in flight.
fn value(state: &AppState, row: SettingRow) -> Vec<Span<'static>> {
    let theme = &state.theme;
    let Some(projection) = state.daemon.as_ref() else {
        return vec![Span::styled("unknown", theme.dim)];
    };
    let (mut spans, slot) = match row.setting_key() {
        None => (
            vec![widgets::kill_switch_span(state, &projection.kill_switch)],
            Slot::KillSwitch,
        ),
        Some(key) => {
            let on = key.get(&projection.settings);
            let style = if protective(key, on) {
                theme.ok
            } else {
                theme.warn
            };
            (
                vec![Span::styled(
                    if on { "on" } else { "off" },
                    data_style(state, style),
                )],
                Slot::Setting(key),
            )
        }
    };
    if let Some(pending) = widgets::pending_label(state, slot) {
        spans.push(pending);
    }
    spans
}

/// Whether this value is the more protective of the two.
fn protective(key: SettingKey, on: bool) -> bool {
    match key {
        SettingKey::AllowLan => !on,
        SettingKey::BlockIpv6 | SettingKey::AutoReconnect => on,
    }
}

fn enter_action(state: &AppState, row: SettingRow) -> (String, Style) {
    let theme = &state.theme;
    let Some(projection) = state.live() else {
        return (
            "unavailable while the daemon is unreachable".to_owned(),
            theme.dim,
        );
    };
    let Some(key) = row.setting_key() else {
        return match &projection.kill_switch {
            KillSwitchState::Off => ("arm the kill switch".to_owned(), theme.text),
            KillSwitchState::Armed => ("disarm (asks to confirm)".to_owned(), theme.warn),
            KillSwitchState::Error { .. } => {
                ("retry or turn off (asks to confirm)".to_owned(), theme.warn)
            }
            KillSwitchState::Unknown => ("unavailable: state unknown".to_owned(), theme.dim),
        };
    };
    let on = key.get(&projection.settings);
    let target = if on { "off" } else { "on" };
    if protective(key, on) && key != SettingKey::AutoReconnect {
        (
            format!("turn {target} (lowers protection, asks to confirm)"),
            theme.warn,
        )
    } else {
        (format!("turn {target}"), theme.text)
    }
}
