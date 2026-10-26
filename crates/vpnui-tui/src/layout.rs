//! Screen geometry as a pure function of terminal size and active view. Rendering and mouse
//! hit-testing both read from here.

use ratatui::layout::{Constraint, Layout, Margin, Rect};

use crate::app::{ConfirmKind, SettingRow, View};
use crate::format;

pub const MIN_WIDTH: u16 = 60;
pub const MIN_HEIGHT: u16 = 18;
pub const WIDE_MIN_WIDTH: u16 = 100;
pub const WIDE_MIN_HEIGHT: u16 = 30;
pub const RAIL_WIDTH: u16 = 38;

const POSTURE_CARD_HEIGHT: u16 = 13;
const BUTTON_HEIGHT: u16 = 3;
const KILL_SWITCH_HEIGHT: u16 = 3;
const HELP_CARD_HEIGHT: u16 = 7;
const STATUS_BAR_HEIGHT: u16 = 3;
const SPARKLINE_HEIGHT: u16 = 5;
const SESSION_HEIGHT: u16 = 4;
const SETTINGS_LIST_HEIGHT: u16 = SettingRow::ALL.len() as u16 + 2;
const MODAL_MAX_WIDTH: u16 = 58;
const HELP_MAX_WIDTH: u16 = 74;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Wide,
    Narrow,
    TooSmall,
}

pub fn mode(width: u16, height: u16) -> Mode {
    if width < MIN_WIDTH || height < MIN_HEIGHT {
        Mode::TooSmall
    } else if width >= WIDE_MIN_WIDTH && height >= WIDE_MIN_HEIGHT {
        Mode::Wide
    } else {
        Mode::Narrow
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rail {
    pub posture: Rect,
    pub action: Rect,
    pub kill_switch: Rect,
    pub recents: Rect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewAreas {
    Home {
        map: Rect,
        /// Only in the narrow layout; the wide layout shows recents in the rail.
        recents: Option<Rect>,
        help: Rect,
    },
    Servers {
        tree: Rect,
        detail: Rect,
    },
    Stats {
        rx: Rect,
        tx: Rect,
        session: Rect,
        log: Rect,
    },
    Settings {
        list: Rect,
        detail: Rect,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppLayout {
    pub mode: Mode,
    pub area: Rect,
    pub header: Rect,
    pub footer: Rect,
    pub rail: Option<Rail>,
    pub status_bar: Option<Rect>,
    pub tabs: Rect,
    pub main: Rect,
    pub view: Option<ViewAreas>,
}

pub fn compute(area: Rect, view: View) -> AppLayout {
    let mode = mode(area.width, area.height);
    let [header, body, footer] = area.layout(&Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ]));
    let (rail, status_bar, right) = match mode {
        Mode::TooSmall => {
            return AppLayout {
                mode,
                area,
                header: Rect::default(),
                footer: Rect::default(),
                rail: None,
                status_bar: None,
                tabs: Rect::default(),
                main: area,
                view: None,
            };
        }
        Mode::Wide => {
            let [rail, right] = body.layout(&Layout::horizontal([
                Constraint::Length(RAIL_WIDTH),
                Constraint::Fill(1),
            ]));
            (Some(rail_areas(rail)), None, right)
        }
        Mode::Narrow => {
            let [bar, right] = body.layout(&Layout::vertical([
                Constraint::Length(STATUS_BAR_HEIGHT),
                Constraint::Fill(1),
            ]));
            (None, Some(bar), right)
        }
    };
    let [tabs, main] = right.layout(&Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
    ]));
    AppLayout {
        mode,
        area,
        header,
        footer,
        rail,
        status_bar,
        tabs,
        main,
        view: Some(view_areas(view, main, mode)),
    }
}

fn rail_areas(rail: Rect) -> Rail {
    let [posture, action, kill_switch, recents] = rail.layout(&Layout::vertical([
        Constraint::Length(POSTURE_CARD_HEIGHT),
        Constraint::Length(BUTTON_HEIGHT),
        Constraint::Length(KILL_SWITCH_HEIGHT),
        Constraint::Fill(1),
    ]));
    Rail {
        posture,
        action,
        kill_switch,
        recents,
    }
}

fn view_areas(view: View, main: Rect, mode: Mode) -> ViewAreas {
    match view {
        View::Home => {
            let [map, bottom] = main.layout(&Layout::vertical([
                Constraint::Fill(1),
                Constraint::Length(HELP_CARD_HEIGHT),
            ]));
            match mode {
                Mode::Narrow | Mode::TooSmall => {
                    let [recents, help] = bottom.layout(&Layout::horizontal([
                        Constraint::Percentage(50),
                        Constraint::Fill(1),
                    ]));
                    ViewAreas::Home {
                        map,
                        recents: Some(recents),
                        help,
                    }
                }
                Mode::Wide => ViewAreas::Home {
                    map,
                    recents: None,
                    help: bottom,
                },
            }
        }
        View::Servers => {
            let [tree, detail] = main.layout(&Layout::horizontal([
                Constraint::Percentage(60),
                Constraint::Fill(1),
            ]));
            ViewAreas::Servers { tree, detail }
        }
        View::Stats => {
            let [sparks, session, log] = main.layout(&Layout::vertical([
                Constraint::Length(SPARKLINE_HEIGHT),
                Constraint::Length(SESSION_HEIGHT),
                Constraint::Fill(1),
            ]));
            let [rx, tx] = sparks.layout(&Layout::horizontal([
                Constraint::Percentage(50),
                Constraint::Fill(1),
            ]));
            ViewAreas::Stats {
                rx,
                tx,
                session,
                log,
            }
        }
        View::Settings => {
            let [list, detail] = main.layout(&Layout::vertical([
                Constraint::Length(SETTINGS_LIST_HEIGHT),
                Constraint::Fill(1),
            ]));
            ViewAreas::Settings { list, detail }
        }
    }
}

/// Content area of a bordered block.
pub fn inner(r: Rect) -> Rect {
    r.inner(Margin::new(1, 1))
}

pub fn tab_label(view: View) -> String {
    format!("[{} {}]", view.number(), view.title())
}

impl AppLayout {
    pub fn tab_hits(&self) -> Vec<(View, Rect)> {
        let mut x = self.tabs.x.saturating_add(1);
        View::ALL
            .iter()
            .map(|&view| {
                let width = format::width(&tab_label(view)) as u16;
                let hit = Rect::new(x, self.tabs.y, width, 1).intersection(self.tabs);
                x = x.saturating_add(width + 1);
                (view, hit)
            })
            .collect()
    }

    pub fn recents_list(&self) -> Option<Rect> {
        match (self.rail, self.view) {
            (Some(rail), _) => Some(inner(rail.recents)),
            (
                None,
                Some(ViewAreas::Home {
                    recents: Some(r), ..
                }),
            ) => Some(inner(r)),
            (None, _) => None,
        }
    }

    pub fn search_line(&self) -> Option<Rect> {
        match self.view? {
            ViewAreas::Servers { tree, .. } => {
                let inner = inner(tree);
                Some(Rect { height: 1, ..inner }.intersection(inner))
            }
            ViewAreas::Home { .. } | ViewAreas::Stats { .. } | ViewAreas::Settings { .. } => None,
        }
    }

    pub fn servers_list(&self) -> Option<Rect> {
        match self.view? {
            ViewAreas::Servers { tree, .. } => {
                let inner = inner(tree);
                Some(Rect {
                    y: inner.y.saturating_add(1),
                    height: inner.height.saturating_sub(1),
                    ..inner
                })
            }
            ViewAreas::Home { .. } | ViewAreas::Stats { .. } | ViewAreas::Settings { .. } => None,
        }
    }

    pub fn settings_rows(&self) -> Option<Rect> {
        match self.view? {
            ViewAreas::Settings { list, .. } => Some(inner(list)),
            ViewAreas::Home { .. } | ViewAreas::Servers { .. } | ViewAreas::Stats { .. } => None,
        }
    }

    pub fn log_list(&self) -> Option<Rect> {
        match self.view? {
            ViewAreas::Stats { log, .. } => Some(inner(log)),
            ViewAreas::Home { .. } | ViewAreas::Servers { .. } | ViewAreas::Settings { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmLayout {
    pub popup: Rect,
    pub message: Vec<String>,
    pub message_area: Rect,
    pub choices: Vec<Rect>,
    pub hint: Rect,
}

pub fn confirm(area: Rect, kind: &ConfirmKind) -> ConfirmLayout {
    let width = MODAL_MAX_WIDTH.min(area.width.saturating_sub(4));
    let text_width = usize::from(width.saturating_sub(4));
    let message = format::wrap(&kind.message(), text_width);
    let choices = kind.choices().len();
    let content = message.len() + 1 + choices + 1 + 1;
    let height = (content as u16 + 2).min(area.height);
    let popup = centered(area, width, height);
    let body = popup.inner(Margin::new(2, 1));

    let row = |offset: usize| {
        Rect::new(body.x, body.y.saturating_add(offset as u16), body.width, 1).intersection(body)
    };
    ConfirmLayout {
        popup,
        message_area: Rect {
            height: message.len() as u16,
            ..body
        }
        .intersection(body),
        choices: (0..choices).map(|i| row(message.len() + 1 + i)).collect(),
        hint: row(message.len() + 1 + choices + 1),
        message,
    }
}

pub fn help(area: Rect, lines: usize) -> Rect {
    let width = HELP_MAX_WIDTH.min(area.width.saturating_sub(4));
    let height = (lines as u16 + 2).min(area.height.saturating_sub(2));
    centered(area, width, height)
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_thresholds() {
        assert_eq!(mode(59, 40), Mode::TooSmall);
        assert_eq!(mode(120, 17), Mode::TooSmall);
        assert_eq!(mode(60, 18), Mode::Narrow);
        assert_eq!(mode(80, 24), Mode::Narrow);
        assert_eq!(mode(99, 40), Mode::Narrow);
        assert_eq!(mode(120, 29), Mode::Narrow);
        assert_eq!(mode(100, 30), Mode::Wide);
    }

    #[test]
    fn wide_rail_is_fixed_width_and_regions_tile_the_screen() {
        for (w, h) in [(100, 30), (120, 40), (200, 60)] {
            let layout = compute(Rect::new(0, 0, w, h), View::Home);
            let rail = layout.rail.map(|r| r.posture.width);
            assert_eq!(rail, Some(RAIL_WIDTH));
            assert_eq!(layout.header.height, 1);
            assert_eq!(layout.footer.y, h - 1);
            assert_eq!(layout.tabs.x, RAIL_WIDTH);
            assert_eq!(layout.main.width, w - RAIL_WIDTH);
        }
    }

    #[test]
    fn narrow_has_status_bar_and_full_width_view() {
        let layout = compute(Rect::new(0, 0, 80, 24), View::Servers);
        assert!(layout.rail.is_none());
        assert_eq!(layout.status_bar.map(|r| r.height), Some(3));
        assert_eq!(layout.main.width, 80);
        assert_eq!(layout.main.height, 24 - 1 - 3 - 1 - 1);
    }

    #[test]
    fn tab_hits_do_not_overlap() {
        let layout = compute(Rect::new(0, 0, 80, 24), View::Home);
        let hits = layout.tab_hits();
        for pair in hits.windows(2) {
            assert!(pair[0].1.right() < pair[1].1.x);
        }
    }

    #[test]
    fn confirm_fits_at_minimum_size() {
        let area = Rect::new(0, 0, MIN_WIDTH, MIN_HEIGHT);
        let layout = confirm(area, &ConfirmKind::DisconnectWhileArmed);
        assert!(area.contains(layout.popup.as_position()));
        assert!(layout.popup.bottom() <= area.bottom());
        assert_eq!(layout.choices.len(), 3);
        assert!(layout.choices.iter().all(|c| c.height == 1));
    }
}
