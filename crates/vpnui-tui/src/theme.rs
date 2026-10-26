//! Semantic styles and glyphs for truecolor, 16-color, `NO_COLOR`, and `--ascii`. Views ask for
//! roles ("exposed", "dim"), never raw colors.

use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::symbols::border;

use crate::app::Posture;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    TrueColor,
    Ansi16,
    None,
}

impl ColorMode {
    /// `NO_COLOR` (any non-empty value) wins; otherwise truecolor if `COLORTERM` advertises it.
    pub fn detect(no_color: Option<&str>, colorterm: Option<&str>) -> Self {
        if no_color.is_some_and(|v| !v.is_empty()) {
            return Self::None;
        }
        match colorterm {
            Some(v) if v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit") => {
                Self::TrueColor
            }
            Some(_) | None => Self::Ansi16,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Symbols {
    pub protected: &'static str,
    pub exposed: &'static str,
    pub blocked: &'static str,
    pub unknown: &'static str,
    pub bar_full: &'static str,
    pub bar_empty: &'static str,
    pub expanded: &'static str,
    pub collapsed: &'static str,
    pub pointer: &'static str,
    pub separator: &'static str,
    pub ellipsis: &'static str,
    pub you: &'static str,
    pub server: &'static str,
    pub live: &'static str,
    pub rx: &'static str,
    pub tx: &'static str,
    pub warning: &'static str,
    /// Stands in for a value the daemon does not know.
    pub missing: &'static str,
    pub spinner: &'static [&'static str],
    pub border: border::Set<'static>,
    pub map_marker: Marker,
    pub sparkline: ratatui::symbols::bar::Set<'static>,
}

const ASCII_BORDER: border::Set<'static> = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

const ASCII_SPARKLINE: ratatui::symbols::bar::Set<'static> = ratatui::symbols::bar::Set {
    full: "#",
    seven_eighths: "#",
    three_quarters: "=",
    five_eighths: "=",
    half: "-",
    three_eighths: "-",
    one_quarter: "_",
    one_eighth: "_",
    empty: " ",
};

impl Symbols {
    pub fn unicode() -> Self {
        Self {
            protected: "✔",
            exposed: "✖",
            blocked: "■",
            unknown: "?",
            bar_full: "█",
            bar_empty: "░",
            expanded: "▾",
            collapsed: "▸",
            pointer: "›",
            separator: "·",
            ellipsis: "…",
            you: "●",
            server: "◆",
            live: "●",
            rx: "↓",
            tx: "↑",
            warning: "!",
            missing: "—",
            spinner: &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            border: border::ROUNDED,
            map_marker: Marker::Braille,
            sparkline: ratatui::symbols::bar::NINE_LEVELS,
        }
    }

    pub fn ascii() -> Self {
        Self {
            protected: "+",
            exposed: "x",
            blocked: "#",
            unknown: "?",
            bar_full: "#",
            bar_empty: ".",
            expanded: "v",
            collapsed: ">",
            pointer: ">",
            separator: "|",
            ellipsis: "~",
            you: "@",
            server: "*",
            live: "*",
            rx: "v",
            tx: "^",
            warning: "!",
            missing: "-",
            spinner: &["|", "/", "-", "\\"],
            border: ASCII_BORDER,
            map_marker: Marker::Custom('.'),
            sparkline: ASCII_SPARKLINE,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub mode: ColorMode,
    pub ascii: bool,
    pub sym: Symbols,
    pub text: Style,
    pub dim: Style,
    pub stale: Style,
    pub title: Style,
    pub accent: Style,
    pub border: Style,
    pub selected: Style,
    pub tab_active: Style,
    pub tab_inactive: Style,
    pub key: Style,
    pub ok: Style,
    pub warn: Style,
    pub error: Style,
    pub map: Style,
    pub rx: Style,
    pub tx: Style,
    protected: Style,
    exposed: Style,
    blocked: Style,
    unknown: Style,
    load_low: Style,
    load_mid: Style,
    load_high: Style,
}

struct Palette {
    green: Color,
    red: Color,
    amber: Color,
    gray: Color,
    blue: Color,
    fg: Color,
    muted: Color,
    on_badge: Color,
    selection_bg: Color,
}

const TRUECOLOR: Palette = Palette {
    green: Color::Rgb(63, 185, 80),
    red: Color::Rgb(248, 81, 73),
    amber: Color::Rgb(227, 160, 8),
    gray: Color::Rgb(139, 148, 158),
    blue: Color::Rgb(88, 166, 255),
    fg: Color::Rgb(230, 237, 243),
    muted: Color::Rgb(110, 118, 129),
    on_badge: Color::Rgb(13, 17, 23),
    selection_bg: Color::Rgb(38, 52, 74),
};

const ANSI16: Palette = Palette {
    green: Color::Green,
    red: Color::Red,
    amber: Color::Yellow,
    gray: Color::Gray,
    blue: Color::Cyan,
    fg: Color::Reset,
    muted: Color::DarkGray,
    on_badge: Color::Black,
    selection_bg: Color::DarkGray,
};

impl Theme {
    pub fn new(mode: ColorMode, ascii: bool) -> Self {
        let sym = if ascii {
            Symbols::ascii()
        } else {
            Symbols::unicode()
        };
        match mode {
            ColorMode::TrueColor => Self::colored(mode, ascii, sym, &TRUECOLOR),
            ColorMode::Ansi16 => Self::colored(mode, ascii, sym, &ANSI16),
            ColorMode::None => Self::monochrome(ascii, sym),
        }
    }

    fn colored(mode: ColorMode, ascii: bool, sym: Symbols, p: &Palette) -> Self {
        let bold = Modifier::BOLD;
        Self {
            mode,
            ascii,
            sym,
            text: Style::new().fg(p.fg),
            dim: Style::new().fg(p.muted),
            stale: Style::new().fg(p.muted).add_modifier(Modifier::DIM),
            title: Style::new().fg(p.fg).add_modifier(bold),
            accent: Style::new().fg(p.blue),
            border: Style::new().fg(p.muted),
            selected: Style::new().bg(p.selection_bg).add_modifier(bold),
            tab_active: Style::new().fg(p.on_badge).bg(p.blue).add_modifier(bold),
            tab_inactive: Style::new().fg(p.gray),
            key: Style::new().fg(p.blue).add_modifier(bold),
            ok: Style::new().fg(p.green),
            warn: Style::new().fg(p.amber),
            error: Style::new().fg(p.red).add_modifier(bold),
            map: Style::new().fg(p.muted),
            rx: Style::new().fg(p.green),
            tx: Style::new().fg(p.blue),
            protected: Style::new().fg(p.green),
            exposed: Style::new().fg(p.red),
            blocked: Style::new().fg(p.amber),
            unknown: Style::new().fg(p.gray),
            load_low: Style::new().fg(p.green),
            load_mid: Style::new().fg(p.amber),
            load_high: Style::new().fg(p.red),
        }
    }

    fn monochrome(ascii: bool, sym: Symbols) -> Self {
        let plain = Style::new();
        let bold = Style::new().add_modifier(Modifier::BOLD);
        let dim = Style::new().add_modifier(Modifier::DIM);
        Self {
            mode: ColorMode::None,
            ascii,
            sym,
            text: plain,
            dim,
            stale: dim,
            title: bold,
            accent: Style::new().add_modifier(Modifier::UNDERLINED),
            border: plain,
            selected: Style::new().add_modifier(Modifier::REVERSED),
            tab_active: Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD),
            tab_inactive: plain,
            key: bold,
            ok: plain,
            warn: bold,
            error: bold,
            map: dim,
            rx: plain,
            tx: plain,
            protected: bold,
            exposed: bold,
            blocked: bold,
            unknown: dim,
            load_low: plain,
            load_mid: plain,
            load_high: bold,
        }
    }

    pub fn posture(&self, posture: Posture) -> Style {
        match posture {
            Posture::Protected => self.protected,
            Posture::Exposed => self.exposed,
            Posture::Blocked => self.blocked,
            Posture::Unknown => self.unknown,
        }
    }

    /// Solid banner: the posture color as background in color modes, reverse video otherwise.
    pub fn posture_banner(&self, posture: Posture) -> Style {
        let fg = self.posture(posture);
        match (self.mode, fg.fg) {
            (ColorMode::TrueColor, Some(color)) => Style::new()
                .bg(color)
                .fg(TRUECOLOR.on_badge)
                .add_modifier(Modifier::BOLD),
            (ColorMode::Ansi16, Some(color)) => Style::new()
                .bg(color)
                .fg(ANSI16.on_badge)
                .add_modifier(Modifier::BOLD),
            (ColorMode::TrueColor | ColorMode::Ansi16 | ColorMode::None, _) => {
                Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
            }
        }
    }

    pub fn posture_symbol(&self, posture: Posture) -> &'static str {
        match posture {
            Posture::Protected => self.sym.protected,
            Posture::Exposed => self.sym.exposed,
            Posture::Blocked => self.sym.blocked,
            Posture::Unknown => self.sym.unknown,
        }
    }

    /// Load thresholds: below 50% green, below 80% amber, otherwise red.
    pub fn load(&self, pct: u8) -> Style {
        match pct {
            0..50 => self.load_low,
            50..80 => self.load_mid,
            _ => self.load_high,
        }
    }

    pub fn map_color(&self, style: Style) -> Color {
        style.fg.unwrap_or(Color::Reset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_color_mode() {
        assert_eq!(
            ColorMode::detect(Some("1"), Some("truecolor")),
            ColorMode::None
        );
        assert_eq!(
            ColorMode::detect(Some(""), Some("truecolor")),
            ColorMode::TrueColor
        );
        assert_eq!(ColorMode::detect(None, Some("24bit")), ColorMode::TrueColor);
        assert_eq!(ColorMode::detect(None, None), ColorMode::Ansi16);
    }

    #[test]
    fn ascii_symbols_are_ascii() {
        let s = Symbols::ascii();
        let all = [
            s.protected,
            s.exposed,
            s.blocked,
            s.unknown,
            s.bar_full,
            s.bar_empty,
            s.expanded,
            s.collapsed,
            s.pointer,
            s.separator,
            s.ellipsis,
            s.you,
            s.server,
            s.live,
            s.rx,
            s.tx,
            s.warning,
            s.missing,
        ];
        assert!(all.iter().chain(s.spinner).all(|g| g.is_ascii()));
    }

    #[test]
    fn posture_symbols_are_distinct() {
        for ascii in [false, true] {
            let theme = Theme::new(ColorMode::None, ascii);
            let mut symbols: Vec<_> = Posture::ALL
                .iter()
                .map(|&p| theme.posture_symbol(p))
                .collect();
            symbols.sort_unstable();
            symbols.dedup();
            assert_eq!(symbols.len(), Posture::ALL.len());
        }
    }
}
