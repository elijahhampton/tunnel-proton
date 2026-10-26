use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use vpnui_proto::{Feature, Server, TunnelState};

use super::widgets::{self, data_style};
use crate::app::AppState;
use crate::browser::{NodeKey, Row, RowKind};
use crate::format;
use crate::layout::{self, AppLayout};

const INDENT: usize = 2;

pub fn render(frame: &mut Frame, state: &AppState, layout: &AppLayout, tree: Rect, detail: Rect) {
    let rows = state.ui.browser.rows(state.servers());
    tree_pane(frame, state, layout, tree, &rows);
    detail_pane(frame, state, detail, &rows);
}

fn tree_pane(
    frame: &mut Frame,
    state: &AppState,
    layout: &AppLayout,
    area: Rect,
    rows: &[Row<'_>],
) {
    let theme = &state.theme;
    let browser = &state.ui.browser;
    let total = state.servers().len();
    let mut title = vec![
        widgets::title(theme, "Servers"),
        Span::styled(
            format!(
                "{total} {} sort: {} ",
                theme.sym.separator,
                browser.sort.label()
            ),
            theme.dim,
        ),
    ];
    if let Some(stale) = widgets::stale_label(state) {
        title.push(Span::styled(format!("{stale} "), theme.warn));
    }
    frame.render_widget(widgets::block(theme, Line::from(title)), area);

    if let Some(search) = layout.search_line() {
        frame.render_widget(Paragraph::new(search_line(state, rows)), search);
    }
    let Some(list) = layout.servers_list() else {
        return;
    };
    if state.daemon.is_none() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Waiting for the daemon's server list",
                theme.dim,
            )),
            list,
        );
        return;
    }
    if widgets::no_profiles(state) {
        frame.render_widget(
            Paragraph::new(widgets::no_profiles_text(theme)).wrap(Wrap { trim: false }),
            list,
        );
        return;
    }
    if rows.is_empty() {
        let text = format!("No servers match \"{}\"", browser.query.trim());
        frame.render_widget(Paragraph::new(Span::styled(text, theme.dim)), list);
        return;
    }

    let selected = browser.selected_index(rows);
    let active = state.daemon.as_ref().and_then(|p| p.tunnel.server_id());
    let width = usize::from(list.width);
    let name_width = name_column(rows, width);
    let lines: Vec<Line<'_>> = rows
        .iter()
        .enumerate()
        .skip(browser.offset)
        .take(usize::from(list.height))
        .map(|(index, row)| {
            let line = match &row.kind {
                RowKind::Server(server) => {
                    server_row(state, server, width, name_width, active == Some(&server.id))
                }
                RowKind::Country {
                    code,
                    name,
                    servers,
                    avg_load,
                } => group_row(
                    state,
                    row,
                    format!("{name} {code}"),
                    *servers,
                    *avg_load,
                    width,
                ),
                RowKind::City {
                    name,
                    servers,
                    avg_load,
                } => group_row(
                    state,
                    row,
                    city_label(state, name),
                    *servers,
                    *avg_load,
                    width,
                ),
            };
            if Some(index) == selected {
                line.style(theme.selected)
            } else {
                line
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), list);
}

fn search_line(state: &AppState, rows: &[Row<'_>]) -> Line<'static> {
    let theme = &state.theme;
    let browser = &state.ui.browser;
    let matches = rows
        .iter()
        .filter(|r| matches!(r.kind, RowKind::Server(_)))
        .count();
    if browser.typing {
        let cursor = if theme.ascii { "_" } else { "▏" };
        return Line::from(vec![
            Span::styled("/ ", theme.key),
            Span::styled(browser.query.clone(), theme.text),
            Span::styled(cursor, theme.accent),
            Span::styled(format!("  {matches} matching"), theme.dim),
        ]);
    }
    if browser.searching() {
        return Line::from(vec![
            Span::styled("/ ", theme.key),
            Span::styled(browser.query.clone(), theme.accent),
            Span::styled(
                format!("  {matches} matching {} Esc clears", theme.sym.separator),
                theme.dim,
            ),
        ]);
    }
    Line::from(vec![
        Span::styled("/", theme.key),
        Span::styled(" search  ", theme.dim),
        Span::styled("o", theme.key),
        Span::styled(" sort  ", theme.dim),
        Span::styled("h/l", theme.key),
        Span::styled(" fold", theme.dim),
    ])
}

/// `▸ Switzerland CH  12 servers  avg load 41%`, indented by depth.
fn group_row(
    state: &AppState,
    row: &Row<'_>,
    name: String,
    servers: usize,
    avg_load: Option<u8>,
    width: usize,
) -> Line<'static> {
    let theme = &state.theme;
    let glyph = if row.expanded {
        theme.sym.expanded
    } else {
        theme.sym.collapsed
    };
    let indent = " ".repeat(usize::from(row.depth) * INDENT);
    let noun = if servers == 1 { "server" } else { "servers" };
    let summary = format!("  {servers} {noun}  avg load ");
    let (pct, pct_style) = match avg_load {
        Some(load) => (format!("{load}%"), theme.load(load)),
        None => (theme.sym.missing.to_owned(), theme.dim),
    };
    let fixed = format::width(&indent) + 2 + format::width(&summary) + format::width(&pct);
    let name =
        format::truncate(&name, width.saturating_sub(fixed), theme.sym.ellipsis).into_owned();
    Line::from(vec![
        Span::styled(format!("{indent}{glyph} "), data_style(state, theme.dim)),
        Span::styled(name, data_style(state, theme.title)),
        Span::styled(summary, data_style(state, theme.dim)),
        Span::styled(pct, data_style(state, pct_style)),
    ])
}

/// Profiles without a city still form a city level in the tree, labelled with the missing glyph.
fn city_label(state: &AppState, city: &str) -> String {
    if city.is_empty() {
        state.theme.sym.missing.to_owned()
    } else {
        city.to_owned()
    }
}

fn latency_text(theme: &crate::theme::Theme, latency: Option<u32>) -> String {
    match latency {
        Some(ms) => format!("{ms} ms"),
        None => theme.sym.missing.to_owned(),
    }
}

/// Short tags shown as aligned columns in the tree; the detail pane spells them out.
const TAG_COLUMNS: [(Feature, &str); 3] = [
    (Feature::P2p, "p2p"),
    (Feature::Streaming, "str"),
    (Feature::Multihop, "mh"),
];
const TAGS_WIDTH: usize = 3 + 1 + 3 + 1 + 2;
const LATENCY_WIDTH: usize = 7;
const PCT_WIDTH: usize = 3;

/// Name column width: the longest visible name, within limits that leave room for the rest.
fn name_column(rows: &[Row<'_>], width: usize) -> usize {
    let longest = rows
        .iter()
        .filter_map(|r| match r.kind {
            RowKind::Server(s) => Some(format::width(&s.name)),
            RowKind::Country { .. } | RowKind::City { .. } => None,
        })
        .max()
        .unwrap_or(0);
    let budget = server_budget(width);
    let room = budget.saturating_sub(1 + PCT_WIDTH + LATENCY_WIDTH);
    longest.clamp(8, 18).min(room)
}

fn server_budget(width: usize) -> usize {
    width.saturating_sub(2 * INDENT + 2)
}

fn server_row(
    state: &AppState,
    server: &Server,
    width: usize,
    name_width: usize,
    active: bool,
) -> Line<'static> {
    let theme = &state.theme;
    let marker = if active { theme.sym.live } else { " " };
    let rest = server_budget(width).saturating_sub(name_width + 1 + PCT_WIDTH + LATENCY_WIDTH);
    let tags = TAGS_WIDTH + 1;
    let (bar_cells, show_tags) = match rest {
        r if r >= 7 + tags => (6, true),
        r if r >= 5 + tags => (4, true),
        r if r >= 7 => (6, false),
        r if r >= 5 => (4, false),
        _ => (0, false),
    };

    let mut spans = vec![
        Span::raw(" ".repeat(2 * INDENT)),
        Span::styled(format!("{marker} "), theme.accent),
        Span::styled(
            format::fit(&server.name, name_width, theme.sym.ellipsis),
            data_style(state, theme.text),
        ),
        Span::raw(" "),
    ];
    spans.extend(widgets::load_column(
        theme,
        server.load_pct,
        bar_cells,
        state.is_stale(),
    ));
    let latency = match server.latency_ms {
        Some(ms) => format!(" {ms:>4}ms"),
        None => format!(
            " {}",
            format::pad_left(theme.sym.missing, LATENCY_WIDTH - 1)
        ),
    };
    spans.push(Span::styled(latency, data_style(state, theme.dim)));
    if show_tags {
        for (feature, tag) in TAG_COLUMNS {
            let text = if server.features.contains(&feature) {
                tag.to_owned()
            } else {
                " ".repeat(tag.len())
            };
            spans.push(Span::styled(
                format!(" {text}"),
                data_style(state, theme.accent),
            ));
        }
    }
    Line::from(spans)
}

fn feature_tags(features: &[Feature]) -> String {
    features
        .iter()
        .filter(|f| **f != Feature::Unknown)
        .map(|f| f.label())
        .collect::<Vec<_>>()
        .join(" ")
}

fn detail_pane(frame: &mut Frame, state: &AppState, area: Rect, rows: &[Row<'_>]) {
    let theme = &state.theme;
    let block = widgets::block(theme, widgets::title(theme, "Details"));
    let inner = layout::inner(area);
    frame.render_widget(block, area);

    let selected = state
        .ui
        .browser
        .selected_index(rows)
        .and_then(|i| rows.get(i));
    let lines = match selected.map(|r| &r.kind) {
        Some(RowKind::Server(server)) => server_detail(state, server, inner.width),
        Some(RowKind::Country {
            code,
            name,
            servers,
            avg_load,
        }) => group_detail(
            state,
            &format!("{name} ({code})"),
            *servers,
            *avg_load,
            selected,
        ),
        Some(RowKind::City {
            name,
            servers,
            avg_load,
        }) => group_detail(
            state,
            &city_label(state, name),
            *servers,
            *avg_load,
            selected,
        ),
        None => vec![Line::from(Span::styled("Nothing selected", theme.dim))],
    };
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn kv(state: &AppState, key: &str, value: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![Span::styled(
        format::fit(key, 11, ""),
        data_style(state, state.theme.dim),
    )];
    spans.extend(value);
    Line::from(spans)
}

fn server_detail(state: &AppState, server: &Server, width: u16) -> Vec<Line<'static>> {
    let theme = &state.theme;
    let text = data_style(state, theme.text);
    let bar_cells = usize::from(width).saturating_sub(11 + 5).min(20);
    let features = feature_tags(&server.features);
    let (enter, enter_style) = enter_action(state, server);
    let location = if server.city.is_empty() {
        format!("{} ({})", server.country, server.country_code)
    } else {
        format!(
            "{}, {} ({})",
            server.city, server.country, server.country_code
        )
    };
    let value = |text_value: String| vec![Span::styled(text_value, text)];
    let mut lines = vec![
        Line::from(Span::styled(
            server.name.clone(),
            data_style(state, theme.title),
        )),
        Line::from(Span::styled(location, text)),
        Line::default(),
        kv(
            state,
            "Load",
            widgets::load_bar(theme, server.load_pct, bar_cells, state.is_stale()),
        ),
        kv(
            state,
            "Latency",
            value(latency_text(theme, server.latency_ms)),
        ),
        kv(
            state,
            "Features",
            value(if features.is_empty() {
                theme.sym.missing.to_owned()
            } else {
                features
            }),
        ),
    ];
    if let Some(entry) = server.entry_ip {
        lines.push(kv(state, "Entry", value(entry.to_string())));
    }
    if let Some(at) = server.imported_at_ms {
        lines.push(kv(
            state,
            "Imported",
            value(format::ago(state.now.since(at))),
        ));
    }
    lines.push(kv(
        state,
        "ID",
        vec![Span::styled(
            server.id.to_string(),
            data_style(state, theme.dim),
        )],
    ));
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled("Enter ", theme.key),
        Span::styled(enter, enter_style),
    ]));
    lines
}

fn enter_action(state: &AppState, server: &Server) -> (String, Style) {
    let theme = &state.theme;
    let Some(projection) = state.live() else {
        return ("unavailable: daemon unreachable".to_owned(), theme.dim);
    };
    let here = projection.tunnel.server_id() == Some(&server.id);
    match &projection.tunnel {
        TunnelState::Connected { .. } if here => (
            "already connected here; d disconnects".to_owned(),
            theme.dim,
        ),
        TunnelState::Connecting { .. } if here => {
            ("connecting here; Esc cancels".to_owned(), theme.dim)
        }
        TunnelState::Connected { server_id, .. } => (
            format!(
                "switch from {} to {}",
                projection.server_name(server_id),
                server.name
            ),
            theme.text,
        ),
        TunnelState::Disconnecting => ("wait for the disconnect to finish".to_owned(), theme.dim),
        TunnelState::Disconnected { .. }
        | TunnelState::Connecting { .. }
        | TunnelState::Reconnecting { .. }
        | TunnelState::Unknown => (format!("connect to {}", server.name), theme.text),
    }
}

fn group_detail(
    state: &AppState,
    title: &str,
    servers: usize,
    avg_load: Option<u8>,
    selected: Option<&Row<'_>>,
) -> Vec<Line<'static>> {
    let theme = &state.theme;
    let text = data_style(state, theme.text);
    let expanded = selected.is_some_and(|r| r.expanded);
    let best = selected
        .and_then(|row| best_in_group(state, row))
        .and_then(|s| s.load_pct.map(|load| format!("{} ({load}%)", s.name)))
        .unwrap_or_else(|| theme.sym.missing.to_owned());
    let (avg, avg_style) = match avg_load {
        Some(load) => (format!("{load}%"), theme.load(load)),
        None => (theme.sym.missing.to_owned(), theme.dim),
    };
    vec![
        Line::from(Span::styled(
            title.to_owned(),
            data_style(state, theme.title),
        )),
        Line::default(),
        kv(
            state,
            "Servers",
            vec![Span::styled(servers.to_string(), text)],
        ),
        kv(
            state,
            "Avg load",
            vec![Span::styled(avg, data_style(state, avg_style))],
        ),
        kv(state, "Least busy", vec![Span::styled(best, text)]),
        Line::default(),
        Line::from(vec![
            Span::styled("Enter ", theme.key),
            Span::styled(if expanded { "collapse" } else { "expand" }, theme.text),
        ]),
    ]
}

fn best_in_group<'a>(state: &'a AppState, row: &Row<'_>) -> Option<&'a Server> {
    state
        .servers()
        .iter()
        .filter(|s| match &row.key {
            NodeKey::Country(code) => s.country_code == *code,
            NodeKey::City { country, city } => s.country_code == *country && s.city == *city,
            NodeKey::Server(id) => s.id == *id,
        })
        .filter(|s| s.load_pct.is_some())
        .min_by_key(|s| (s.load_pct, s.latency_ms.unwrap_or(u32::MAX)))
}
