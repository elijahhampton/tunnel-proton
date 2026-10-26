use std::collections::VecDeque;
use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Sparkline};
use vpnui_proto::{TunnelState, UnixMillis};

use super::widgets::{self, data_style};
use crate::app::AppState;
use crate::format;
use crate::layout;

/// WireGuard starts a new handshake REKEY_AFTER_TIME (120s) after the last one, but only when it
/// has data to send, and stops using a session REJECT_AFTER_TIME (180s) after its handshake.
/// An idle tunnel with no persistent keepalive sends nothing, so its last handshake can
/// legitimately be far older than 180s; the next outgoing packet triggers a fresh handshake.
/// Past this threshold the age is highlighted as worth a look, not reported as a failure.
pub const HANDSHAKE_STALE_AFTER: Duration = Duration::from_secs(150);

/// REJECT_AFTER_TIME: the current session can no longer carry data without a new handshake.
const HANDSHAKE_REJECT_AFTER: Duration = Duration::from_secs(180);

pub fn render(frame: &mut Frame, state: &AppState, rx: Rect, tx: Rect, session: Rect, log: Rect) {
    let theme = &state.theme;
    let connected = state
        .daemon
        .as_ref()
        .is_some_and(|p| p.tunnel.is_connected());
    let current = state.traffic.current();
    let download = Series {
        label: format!("{} Download", theme.sym.rx),
        samples: &state.traffic.rx,
        current: current.map(|(rx, _)| rx),
        style: theme.rx,
    };
    let upload = Series {
        label: format!("{} Upload", theme.sym.tx),
        samples: &state.traffic.tx,
        current: current.map(|(_, tx)| tx),
        style: theme.tx,
    };
    throughput(frame, state, rx, &download, connected);
    throughput(frame, state, tx, &upload, connected);
    session_info(frame, state, session);
    event_log(frame, state, log);
}

struct Series<'a> {
    label: String,
    samples: &'a VecDeque<u64>,
    current: Option<u64>,
    style: Style,
}

fn throughput(
    frame: &mut Frame,
    state: &AppState,
    area: Rect,
    series: &Series<'_>,
    connected: bool,
) {
    let theme = &state.theme;
    let rate = match (connected, series.current) {
        (true, Some(rate)) => format::rate(rate),
        (true, None) => "measuring".to_owned(),
        (false, _) => "no tunnel".to_owned(),
    };
    let title = Line::from(vec![
        widgets::title(theme, series.label.as_str()),
        Span::styled(format!("{rate} "), data_style(state, theme.text)),
    ]);
    let block = widgets::block(theme, title);
    let inner = layout::inner(area);
    let width = usize::from(inner.width);
    let samples = series.samples;
    let skip = samples.len().saturating_sub(width);
    let padding = width.saturating_sub(samples.len());
    let data: Vec<u64> = std::iter::repeat_n(0, padding)
        .chain(samples.iter().skip(skip).copied())
        .collect();
    let max = data.iter().copied().max().unwrap_or(0).max(1);
    frame.render_widget(
        Sparkline::default()
            .block(block)
            .data(data)
            .max(max)
            .bar_set(theme.sym.sparkline.clone())
            .style(data_style(state, series.style)),
        area,
    );
}

fn session_info(frame: &mut Frame, state: &AppState, area: Rect) {
    let theme = &state.theme;
    let block = widgets::block(theme, widgets::title(theme, "Session"));
    let inner = layout::inner(area);
    frame.render_widget(block, area);
    let [left, right] = inner.layout(&Layout::horizontal([
        Constraint::Percentage(48),
        Constraint::Fill(1),
    ]));

    let dash = || widgets::missing(theme, state.is_stale());
    let text = data_style(state, theme.text);
    let kv = |key: &str, value: Span<'static>| {
        Line::from(vec![
            Span::styled(format::fit(key, 11, ""), data_style(state, theme.dim)),
            value,
        ])
    };

    let projection = state.daemon.as_ref();
    let (endpoint, uptime, handshake) = match projection.map(|p| &p.tunnel) {
        Some(TunnelState::Connected {
            endpoint,
            since_ms,
            last_handshake_ms,
            ..
        }) => {
            let last = projection
                .and_then(|p| p.stats)
                .and_then(|s| s.last_handshake_ms)
                .or(*last_handshake_ms);
            (
                Span::styled(endpoint.clone(), text),
                Span::styled(
                    format::duration(widgets::data_now(state).since(*since_ms)),
                    text,
                ),
                handshake_span(state, last),
            )
        }
        Some(_) | None => (dash(), dash(), dash()),
    };
    let totals = match projection.and_then(|p| p.stats) {
        Some(stats) if projection.is_some_and(|p| p.tunnel.is_connected()) => Span::styled(
            format!(
                "{} {}  {} {}",
                theme.sym.rx,
                format::bytes(stats.rx_bytes),
                theme.sym.tx,
                format::bytes(stats.tx_bytes)
            ),
            text,
        ),
        Some(_) | None => dash(),
    };

    frame.render_widget(
        Paragraph::new(vec![kv("Endpoint", endpoint), kv("Handshake", handshake)]),
        left,
    );
    frame.render_widget(
        Paragraph::new(vec![kv("Uptime", uptime), kv("Total", totals)]),
        right,
    );
}

fn handshake_span(state: &AppState, last: Option<UnixMillis>) -> Span<'static> {
    let theme = &state.theme;
    let Some(last) = last else {
        return Span::styled("none yet", data_style(state, theme.dim));
    };
    let age = widgets::data_now(state).since(last);
    let style = if age > HANDSHAKE_REJECT_AFTER {
        theme.error
    } else if age > HANDSHAKE_STALE_AFTER {
        theme.warn
    } else {
        theme.text
    };
    Span::styled(format::ago(age), data_style(state, style))
}

fn event_log(frame: &mut Frame, state: &AppState, area: Rect) {
    let theme = &state.theme;
    let title = Line::from(vec![
        widgets::title(theme, "Event log"),
        Span::styled(format!("{} newest first ", state.log.len()), theme.dim),
    ]);
    let block = widgets::block(theme, title);
    let inner = layout::inner(area);
    frame.render_widget(block, area);

    if state.log.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled("No events yet", theme.dim)),
            inner,
        );
        return;
    }
    let text_width = usize::from(inner.width).saturating_sub(12);
    let lines: Vec<Line<'_>> = state
        .log
        .iter()
        .skip(state.ui.log_offset)
        .take(usize::from(inner.height))
        .map(|entry| {
            let style = widgets::severity_style(theme, entry.severity);
            Line::from(vec![
                Span::styled(
                    format::pad_left(&format::ago(state.now.since(entry.at)), 8),
                    theme.dim,
                ),
                Span::styled(
                    format!(" {} ", widgets::severity_glyph(theme, entry.severity)),
                    style,
                ),
                Span::styled(
                    format::truncate(&entry.text, text_width, theme.sym.ellipsis).into_owned(),
                    style,
                ),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}
