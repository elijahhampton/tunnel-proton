use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Line as CanvasLine, Map, MapResolution};
use ratatui::widgets::{Paragraph, Wrap};
use vpnui_proto::TunnelState;

use super::{rail, widgets};
use crate::app::{AppState, posture};
use crate::browser::NodeKey;

/// Map latitude range, excluding Antarctica.
const MAP_Y_BOUNDS: [f64; 2] = [-60.0, 85.0];
const MAP_X_BOUNDS: [f64; 2] = [-180.0, 180.0];

const HELP: &[(&str, &str)] = &[
    ("c", "quick connect"),
    ("d", "disconnect"),
    ("Enter", "connect highlighted"),
    ("s", "arm/disarm kill switch"),
    ("/", "search servers"),
    ("1-4", "switch views"),
    ("r", "reconnect now"),
    ("?", "every key"),
    ("q", "quit (tunnel unchanged)"),
    ("Esc", "cancel a connect"),
];

struct Place {
    label: String,
    lat: f64,
    lon: f64,
}

pub fn render(frame: &mut Frame, state: &AppState, map: Rect, recents: Option<Rect>, help: Rect) {
    world_map(frame, state, map);
    if let Some(recents) = recents {
        rail::recents(frame, recents, state);
    }
    help_card(frame, state, help);
}

fn world_map(frame: &mut Frame, state: &AppState, area: Rect) {
    let theme = &state.theme;
    if widgets::no_profiles(state) {
        let block = widgets::block(theme, widgets::title(theme, "Map"));
        frame.render_widget(
            Paragraph::new(widgets::no_profiles_text(theme))
                .wrap(Wrap { trim: false })
                .block(block),
            area,
        );
        return;
    }
    let posture = posture(state);
    let accent = widgets::data_style(state, theme.posture(posture));
    let you = you(state);
    let server = target_server(state);
    let route = state.daemon.as_ref().is_some_and(|p| match p.tunnel {
        TunnelState::Connecting { .. } | TunnelState::Connected { .. } => true,
        TunnelState::Disconnected { .. }
        | TunnelState::Reconnecting { .. }
        | TunnelState::Disconnecting
        | TunnelState::Unknown => false,
    });

    let mut legend = Vec::new();
    if let Some(you) = &you {
        legend.push(Span::styled(format!(" {} ", theme.sym.you), theme.accent));
        legend.push(Span::styled(format!("{} ", you.label), theme.dim));
    }
    if let Some(server) = &server {
        legend.push(Span::styled(format!(" {} ", theme.sym.server), accent));
        legend.push(Span::styled(format!("{} ", server.label), theme.dim));
    }
    let mut block = widgets::block(theme, widgets::title(theme, "Map"));
    if !legend.is_empty() {
        block = block.title_bottom(Line::from(legend));
    }

    let map_color = theme.map_color(widgets::data_style(state, theme.map));
    let route_color = theme.map_color(accent);
    let you_style = theme.accent;
    let canvas = Canvas::default()
        .block(block)
        .marker(theme.sym.map_marker)
        .x_bounds(MAP_X_BOUNDS)
        .y_bounds(MAP_Y_BOUNDS)
        .paint(|ctx| {
            ctx.draw(&Map {
                resolution: MapResolution::High,
                color: map_color,
            });
            ctx.layer();
            if route && let (Some(from), Some(to)) = (&you, &server) {
                ctx.draw(&CanvasLine::new(
                    from.lon,
                    from.lat,
                    to.lon,
                    to.lat,
                    route_color,
                ));
            }
            if let Some(to) = &server {
                ctx.print(to.lon, to.lat, Span::styled(theme.sym.server, accent));
            }
            if let Some(from) = &you {
                ctx.print(from.lon, from.lat, Span::styled(theme.sym.you, you_style));
            }
        });
    frame.render_widget(canvas, area);
}

/// The user's real location: the address seen while the tunnel was down. Unknown when the
/// client has only ever seen the tunnel's exit address.
fn you(state: &AppState) -> Option<Place> {
    let ip = state.origin.as_ref().or_else(|| {
        let projection = state.daemon.as_ref()?;
        if projection.tunnel.is_connected() {
            None
        } else {
            projection.public_ip.as_ref()
        }
    })?;
    let label = if ip.city.is_empty() {
        "you".to_owned()
    } else {
        format!("you ({})", ip.city)
    };
    Some(Place {
        label,
        lat: ip.lat?,
        lon: ip.lon?,
    })
}

/// The tunnel's server if there is one, else the server highlighted in the browser. `None` when
/// that server has no known location.
fn target_server(state: &AppState) -> Option<Place> {
    let projection = state.daemon.as_ref()?;
    let id = projection.tunnel.server_id().cloned().or_else(|| {
        match state.ui.browser.selected.as_ref()? {
            NodeKey::Server(id) => Some(id.clone()),
            NodeKey::Country(_) | NodeKey::City { .. } => None,
        }
    })?;
    let server = projection.server(&id)?;
    Some(Place {
        label: server.name.clone(),
        lat: server.lat?,
        lon: server.lon?,
    })
}

fn help_card(frame: &mut Frame, state: &AppState, area: Rect) {
    let theme = &state.theme;
    let block = widgets::block(theme, widgets::title(theme, "Keys"));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    const KEY_WIDTH: usize = 6;
    const COLUMN_WIDTH: usize = 32;
    let columns = (usize::from(inner.width) / COLUMN_WIDTH).max(1);
    let rows = usize::from(inner.height);
    let lines: Vec<Line<'_>> = (0..rows)
        .map(|row| {
            let spans: Vec<Span<'_>> = (0..columns)
                .filter_map(|col| HELP.get(row * columns + col))
                .flat_map(|(key, desc)| {
                    [
                        Span::styled(format!("{key:<KEY_WIDTH$}"), theme.key),
                        Span::styled(
                            format!("{desc:<width$}", width = COLUMN_WIDTH - KEY_WIDTH),
                            theme.dim,
                        ),
                    ]
                })
                .collect();
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}
