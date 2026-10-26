use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use vpnui_proto::{IpInfo, TunnelState};

use super::widgets::{self, data_style};
use crate::app::{
    AppState, Posture, PrimaryAction, Projection, Slot, View, kill_switch_warning, posture,
};
use crate::format;
use crate::layout::Rail;

const LABEL_WIDTH: usize = 8;

pub fn render(frame: &mut Frame, rail: Rail, state: &AppState) {
    posture_card(frame, rail.posture, state);
    primary_button(frame, rail.action, state);
    kill_switch_row(frame, rail.kill_switch, state);
    recents(frame, rail.recents, state);
}

fn posture_card(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = &state.theme;
    let posture = posture(state);
    let block =
        widgets::block(theme, widgets::title(theme, "Status")).border_style(theme.posture(posture));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [banner, explanation, notice, details] = inner.layout(&Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Fill(1),
    ]));

    let banner_style = theme.posture_banner(posture);
    frame.render_widget(Block::new().style(banner_style), banner);
    let word = format!("{}  {}", theme.posture_symbol(posture), posture.word());
    frame.render_widget(
        Paragraph::new(word).style(banner_style).centered(),
        Rect {
            y: banner.y + banner.height / 2,
            height: 1,
            ..banner
        },
    );

    frame.render_widget(
        Paragraph::new(explain(state, posture))
            .style(theme.text)
            .wrap(Wrap { trim: true }),
        explanation,
    );

    frame.render_widget(Paragraph::new(notice_line(state, notice.width)), notice);
    frame.render_widget(Paragraph::new(detail_lines(state, posture)), details);
}

/// Kill-switch failure takes priority over the stale label.
pub(super) fn notice_line(state: &AppState, width: u16) -> Line<'static> {
    let theme = &state.theme;
    if let Some(message) = kill_switch_warning(state) {
        let text = format!("{} KILL SWITCH FAILED: {message}", theme.sym.warning);
        return Line::from(Span::styled(
            format::truncate(&text, usize::from(width), theme.sym.ellipsis).into_owned(),
            theme.error,
        ));
    }
    if let Some(stale) = widgets::stale_label(state) {
        return Line::from(Span::styled(
            format!("Last known state, {stale}"),
            theme.warn,
        ));
    }
    Line::default()
}

pub(super) fn explain(state: &AppState, posture: Posture) -> &'static str {
    let Some(projection) = state.daemon.as_ref() else {
        return "Waiting for the daemon. State unknown.";
    };
    match posture {
        Posture::Protected => "Traffic is encrypted through the tunnel.",
        Posture::Unknown => "Daemon unreachable. Real state unknown.",
        Posture::Exposed => match projection.tunnel {
            TunnelState::Connecting { .. } => "Connecting. Traffic is unprotected until it's up.",
            TunnelState::Reconnecting { .. } => "Tunnel down. Traffic leaves unencrypted.",
            TunnelState::Disconnecting => "Disconnecting. Traffic is not protected.",
            TunnelState::Disconnected { .. }
            | TunnelState::Connected { .. }
            | TunnelState::Unknown => "Not connected. Traffic leaves unencrypted.",
        },
        Posture::Blocked => match projection.tunnel {
            TunnelState::Connecting { .. } => "Kill switch holds all traffic until it's up.",
            TunnelState::Reconnecting { .. } => "Tunnel down. Kill switch blocks all traffic.",
            TunnelState::Disconnected { .. }
            | TunnelState::Connected { .. }
            | TunnelState::Disconnecting
            | TunnelState::Unknown => "Not connected. Kill switch blocks all traffic.",
        },
    }
}

fn label(state: &AppState, text: &str) -> Span<'static> {
    Span::styled(
        format::fit(text, LABEL_WIDTH, ""),
        data_style(state, state.theme.dim),
    )
}

/// `City, Country` from whichever parts are known; empty when neither is.
pub(super) fn place_name(ip: &IpInfo) -> String {
    [ip.city.as_str(), ip.country.as_str()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Endpoint address of the tunnel's server, or the missing glyph.
pub(super) fn entry_span(state: &AppState, projection: &Projection) -> Span<'static> {
    let entry = projection
        .tunnel
        .server_id()
        .and_then(|id| projection.server(id))
        .and_then(|s| s.entry_ip);
    match entry {
        Some(ip) => Span::styled(ip.to_string(), data_style(state, state.theme.text)),
        None => widgets::missing(&state.theme, state.is_stale()),
    }
}

fn detail_lines(state: &AppState, posture: Posture) -> Vec<Line<'static>> {
    let theme = &state.theme;
    let Some(projection) = state.daemon.as_ref() else {
        return vec![Line::from(Span::styled("No state received yet", theme.dim))];
    };
    let text = data_style(state, theme.text);
    let mut lines = Vec::with_capacity(5);

    match &projection.public_ip {
        Some(ip) => {
            let qualifier = match posture {
                Posture::Protected => "tunnel exit",
                Posture::Exposed => "exposed",
                Posture::Blocked => "not leaving",
                Posture::Unknown => "last known",
            };
            lines.push(Line::from(vec![
                label(state, "IP"),
                Span::styled(ip.ip.to_string(), text),
                Span::styled(
                    format!(" {qualifier}"),
                    data_style(state, theme.posture(posture)),
                ),
            ]));
            let place = place_name(ip);
            if place.is_empty() {
                lines.push(Line::from(vec![
                    label(state, "Entry"),
                    entry_span(state, projection),
                ]));
            } else {
                lines.push(Line::from(vec![
                    label(state, ""),
                    Span::styled(place, text),
                ]));
            }
        }
        None => {
            lines.push(Line::from(vec![
                label(state, "IP"),
                Span::styled("not checked", data_style(state, theme.dim)),
            ]));
            lines.push(Line::from(vec![
                label(state, "Entry"),
                entry_span(state, projection),
            ]));
        }
    }

    let server = projection
        .tunnel
        .server_id()
        .and_then(|id| projection.server(id));
    match (&projection.tunnel, server) {
        (
            TunnelState::Disconnected {
                last_error: Some(error),
            },
            _,
        ) => {
            lines.push(Line::from(vec![
                label(state, "Error"),
                Span::styled(error.clone(), data_style(state, theme.error)),
            ]));
            lines.push(Line::default());
        }
        (_, Some(server)) => {
            lines.push(Line::from(vec![
                label(state, "Server"),
                Span::styled(format!("{} {}", server.name, server.country_code), text),
            ]));
            let mut load = vec![label(state, "Load")];
            load.extend(widgets::load_bar(
                theme,
                server.load_pct,
                12,
                state.is_stale(),
            ));
            lines.push(Line::from(load));
        }
        (_, None) => {
            lines.push(Line::from(vec![
                label(state, "Server"),
                Span::styled("none", text),
            ]));
            lines.push(Line::default());
        }
    }
    lines.push(timing_line(state, projection));
    lines
}

/// Label and value describing where the tunnel is in its lifecycle.
pub(super) fn timing(
    state: &AppState,
    projection: &Projection,
) -> Option<(&'static str, String, Style)> {
    let theme = &state.theme;
    let now = widgets::data_now(state);
    let spin = if state.is_stale() {
        theme.sym.separator
    } else {
        widgets::spinner(theme, now)
    };
    let style = data_style(state, theme.text);
    match &projection.tunnel {
        TunnelState::Connected { since_ms, .. } => {
            Some(("Uptime", format::duration(now.since(*since_ms)), style))
        }
        TunnelState::Connecting {
            phase,
            started_at_ms,
            ..
        } => Some((
            "Elapsed",
            format!(
                "{} {spin} {}",
                format::duration(now.since(*started_at_ms)),
                phase.label()
            ),
            style,
        )),
        TunnelState::Reconnecting {
            attempt,
            retry_at_ms: Some(at),
            ..
        } => Some((
            "Backoff",
            format!(
                "retry in {}, attempt {attempt}",
                format::countdown(now.until(*at))
            ),
            data_style(state, theme.warn),
        )),
        TunnelState::Reconnecting {
            attempt,
            retry_at_ms: None,
            ..
        } => Some((
            "Backoff",
            format!("{spin} attempt {attempt} in progress"),
            style,
        )),
        TunnelState::Disconnecting => Some(("Tunnel", format!("{spin} disconnecting"), style)),
        TunnelState::Disconnected { .. } | TunnelState::Unknown => None,
    }
}

fn timing_line(state: &AppState, projection: &Projection) -> Line<'static> {
    match timing(state, projection) {
        Some((name, value, style)) => {
            Line::from(vec![label(state, name), Span::styled(value, style)])
        }
        None => Line::default(),
    }
}

fn primary_button(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = &state.theme;
    let action = state
        .daemon
        .as_ref()
        .map(|p| PrimaryAction::for_tunnel(&p.tunnel));
    let enabled = state.live().is_some() && action != Some(PrimaryAction::Wait);
    let action = action.unwrap_or(PrimaryAction::QuickConnect);
    let style = if enabled { theme.accent } else { theme.dim };

    let label = action_label(state, action, 16);
    let mut spans = vec![Span::styled(format!("[ {label} ]"), style)];
    if enabled && !action.key().is_empty() {
        spans.push(Span::styled(format!("  {}", action.key()), theme.key));
    }
    if let Some(pending) = widgets::pending_label(state, Slot::Tunnel) {
        spans.push(pending);
    }
    let block = widgets::block(theme, "");
    frame.render_widget(
        Paragraph::new(Line::from(spans)).centered().block(block),
        area,
    );
}

/// The primary action's label, naming the quick-connect target when it is known.
pub(super) fn action_label(state: &AppState, action: PrimaryAction, name_cols: usize) -> String {
    let target = state.daemon.as_ref().and_then(|p| p.quick_connect_target());
    match (action, target) {
        (PrimaryAction::QuickConnect, Some(server)) => format!(
            "{} ({})",
            action.label(),
            format::truncate(&server.name, name_cols, state.theme.sym.ellipsis)
        ),
        (_, _) => action.label().to_owned(),
    }
}

fn kill_switch_row(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = &state.theme;
    let mut spans = vec![Span::styled("Kill switch  ", theme.text)];
    match state.daemon.as_ref() {
        Some(p) => spans.push(widgets::kill_switch_span(state, &p.kill_switch)),
        None => spans.push(Span::styled("unknown", theme.dim)),
    }
    if let Some(pending) = widgets::pending_label(state, Slot::KillSwitch) {
        spans.push(pending);
    }
    spans.push(Span::styled("  s", theme.key));
    let block = widgets::block(theme, "");
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

pub(super) fn recents(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = &state.theme;
    let block = widgets::block(theme, widgets::title(theme, "Recent"));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(projection) = state.daemon.as_ref() else {
        frame.render_widget(Paragraph::new(Span::styled("No data", theme.dim)), inner);
        return;
    };
    let active = projection.tunnel.server_id();
    let mut lines = Vec::new();
    for (index, id) in projection.recent_servers().enumerate() {
        let selected = state.ui.view == View::Home && index == state.ui.recents_cursor;
        let pointer = if selected { theme.sym.pointer } else { " " };
        let marker = if active == Some(id) {
            theme.sym.live
        } else {
            " "
        };
        let (name, cc, load) = match projection.server(id) {
            Some(s) => (s.name.as_str(), s.country_code.as_str(), s.load_pct),
            None => (id.as_str(), "", None),
        };
        let load_text = load.map_or_else(
            || format::pad_left(theme.sym.missing, 4),
            |l| format!("{l:>3}%"),
        );
        let name_width = usize::from(inner.width).saturating_sub(4 + 3 + 5);
        let row_style = if selected {
            theme.selected
        } else {
            Style::new()
        };
        lines.push(
            Line::from(vec![
                Span::raw(format!("{pointer}{marker} ")),
                Span::styled(
                    format::fit(name, name_width, theme.sym.ellipsis),
                    data_style(state, theme.text),
                ),
                Span::styled(format!(" {cc:<2}"), data_style(state, theme.dim)),
                Span::styled(
                    format!(" {load_text}"),
                    data_style(state, load.map_or(theme.dim, |l| theme.load(l))),
                ),
            ])
            .style(row_style),
        );
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled("No recent servers yet", theme.dim)));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Narrow layout: posture, server, and kill switch in three rows.
pub fn status_bar(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = &state.theme;
    let posture = posture(state);
    let [top, middle, bottom] = area.layout(&Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ]));

    let banner = theme.posture_banner(posture);
    let mut summary = format!(" {} {} ", theme.posture_symbol(posture), posture.word());
    if let Some(projection) = state.daemon.as_ref() {
        let sep = theme.sym.separator;
        if let Some(id) = projection.tunnel.server_id() {
            let name = projection.server(id).map_or_else(
                || id.to_string(),
                |s| format!("{} {}", s.name, s.country_code),
            );
            summary.push_str(&format!("{sep} {name} "));
        }
        if let Some((_, value, _)) = timing(state, projection) {
            let value = if projection.tunnel.is_connected() {
                format!("up {value}")
            } else {
                value
            };
            summary.push_str(&format!("{sep} {value} "));
        }
    }
    frame.render_widget(Block::new().style(banner), top);
    frame.render_widget(Paragraph::new(summary).style(banner), top);

    let notice = notice_line(state, middle.width.saturating_sub(1));
    let middle_line = if notice.spans.is_empty() {
        Line::from(Span::styled(
            format!(" {}", explain(state, posture)),
            theme.text,
        ))
    } else {
        Line::from([vec![Span::raw(" ")], notice.spans].concat())
    };
    frame.render_widget(Paragraph::new(middle_line), middle);

    let mut spans = vec![Span::styled(" Kill switch ", theme.dim)];
    match state.daemon.as_ref() {
        Some(p) => {
            spans.push(widgets::kill_switch_span(state, &p.kill_switch));
            if let Some(pending) = widgets::pending_label(state, Slot::KillSwitch) {
                spans.push(pending);
            }
            let action = PrimaryAction::for_tunnel(&p.tunnel);
            if state.live().is_some() && !action.key().is_empty() {
                spans.push(Span::styled(
                    format!("  {} ", theme.sym.separator),
                    theme.dim,
                ));
                spans.push(Span::styled(action.key().to_owned(), theme.key));
                spans.push(Span::styled(
                    format!(" {}", action_label(state, action, 14)),
                    theme.dim,
                ));
                if let Some(pending) = widgets::pending_label(state, Slot::Tunnel) {
                    spans.push(pending);
                }
            }
            let sep = theme.sym.separator;
            match &p.public_ip {
                Some(ip) => spans.push(Span::styled(
                    format!("  {sep} IP {} {}", ip.ip, ip.city)
                        .trim_end()
                        .to_owned(),
                    data_style(state, theme.dim),
                )),
                None => {
                    spans.push(Span::styled(
                        format!("  {sep} IP not checked {sep} Entry "),
                        data_style(state, theme.dim),
                    ));
                    spans.push(entry_span(state, p));
                }
            }
        }
        None => spans.push(Span::styled("unknown", theme.dim)),
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), bottom);
}
