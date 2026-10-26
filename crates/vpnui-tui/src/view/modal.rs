use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};

use super::widgets;
use crate::app::{AppState, ConfirmKind};
use crate::format;
use crate::layout;

/// Every binding, grouped. Rendered verbatim by the `?` overlay.
pub const KEYBINDINGS: &[(&str, &[(&str, &str)])] = &[
    (
        "Tunnel",
        &[
            ("c", "quick connect (least busy server)"),
            ("Enter", "connect to the highlighted server"),
            ("d", "disconnect (confirms if armed)"),
            ("r", "reconnect now, skipping backoff"),
            ("Esc", "cancel an in-progress connect"),
            ("s", "arm or disarm the kill switch"),
        ],
    ),
    (
        "Navigation",
        &[
            ("1-4", "Home, Servers, Stats, Settings"),
            ("Tab S-Tab", "next / previous view"),
            ("j k Down Up", "move the selection"),
            ("PgDn PgUp", "move by ten"),
            ("g G Home End", "first / last"),
            ("h l Left Right", "collapse / expand the tree"),
        ],
    ),
    (
        "Servers",
        &[
            ("/", "search country, city, or name"),
            ("Esc", "clear the search"),
            ("o", "sort by name, load, latency"),
            ("p2p str mh", "peer-to-peer, streaming, multihop"),
        ],
    ),
    (
        "Dialogs",
        &[
            ("j k Tab", "choose an option"),
            ("Enter Space", "confirm"),
            ("Esc", "cancel"),
        ],
    ),
    (
        "General",
        &[
            ("?", "toggle this help"),
            ("q Ctrl-C", "quit; tunnel stays as it is"),
            ("mouse", "click tabs, rows, buttons; wheel"),
        ],
    ),
];

pub fn confirm(
    frame: &mut Frame,
    area: Rect,
    state: &AppState,
    kind: &ConfirmKind,
    selected: usize,
) {
    let theme = &state.theme;
    let geometry = layout::confirm(area, kind);
    frame.render_widget(Clear, geometry.popup);
    let block = widgets::block(theme, widgets::title(theme, kind.title())).border_style(theme.warn);
    frame.render_widget(block, geometry.popup);

    let message: Vec<Line<'_>> = geometry
        .message
        .iter()
        .map(|line| Line::from(Span::styled(line.clone(), theme.text)))
        .collect();
    frame.render_widget(Paragraph::new(message), geometry.message_area);

    for (index, (choice, rect)) in kind.choices().iter().zip(&geometry.choices).enumerate() {
        let is_selected = index == selected;
        let pointer = if is_selected { theme.sym.pointer } else { " " };
        let line = Line::from(format!("{pointer} {}", choice.label()));
        let line = if is_selected {
            line.style(theme.selected)
        } else {
            line.style(theme.text)
        };
        frame.render_widget(Paragraph::new(line), *rect);
    }
    frame.render_widget(
        Paragraph::new(widgets::key_hints(
            theme,
            &[("j/k", "choose"), ("Enter", "confirm"), ("Esc", "cancel")],
            usize::from(geometry.hint.width),
        )),
        geometry.hint,
    );
}

pub fn help(frame: &mut Frame, area: Rect, state: &AppState, scroll: u16) {
    let theme = &state.theme;
    let key_width = KEYBINDINGS
        .iter()
        .flat_map(|(_, keys)| keys.iter())
        .map(|(key, _)| format::width(key))
        .max()
        .unwrap_or(0)
        + 2;
    let mut lines = Vec::new();
    for (section, keys) in KEYBINDINGS {
        if !lines.is_empty() {
            lines.push(Line::default());
        }
        lines.push(Line::from(Span::styled((*section).to_owned(), theme.title)));
        for (key, desc) in *keys {
            lines.push(Line::from(vec![
                Span::styled(format!("  {}", format::fit(key, key_width, "")), theme.key),
                Span::styled((*desc).to_owned(), theme.text),
            ]));
        }
    }

    let popup = layout::help(area, lines.len());
    let visible = usize::from(popup.height.saturating_sub(2));
    let max_scroll = lines.len().saturating_sub(visible);
    let scroll = usize::from(scroll).min(max_scroll);
    let more = if max_scroll > 0 {
        format!(
            " {}/{} j/k scroll ",
            scroll + visible.min(lines.len()),
            lines.len()
        )
    } else {
        String::new()
    };
    let block = widgets::block(theme, widgets::title(theme, "Keys"))
        .title_bottom(Line::from(Span::styled(more, theme.dim)).right_aligned())
        .border_style(theme.accent);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((scroll as u16, 0)),
        popup,
    );
}
