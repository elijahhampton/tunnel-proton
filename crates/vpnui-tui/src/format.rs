//! Human-readable formatting and width-aware text fitting. All column math goes through here so
//! that nothing slices strings by byte offset.

use std::borrow::Cow;
use std::time::Duration;

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value < 100.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.0} {}", UNITS[unit])
    }
}

pub fn rate(bytes_per_sec: u64) -> String {
    format!("{}/s", bytes(bytes_per_sec))
}

/// Elapsed time with the two most significant units: `45s`, `2m 03s`, `1h 02m`, `3d 04h`.
pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s}s"),
        60..3_600 => format!("{}m {:02}s", s / 60, s % 60),
        3_600..86_400 => format!("{}h {:02}m", s / 3_600, (s % 3_600) / 60),
        _ => format!("{}d {:02}h", s / 86_400, (s % 86_400) / 3_600),
    }
}

/// Coarse age: `just now`, `12s ago`, `3m ago`, `2h ago`, `4d ago`.
pub fn ago(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0 => "just now".to_owned(),
        1..60 => format!("{s}s ago"),
        60..3_600 => format!("{}m ago", s / 60),
        3_600..86_400 => format!("{}h ago", s / 3_600),
        _ => format!("{}d ago", s / 86_400),
    }
}

/// Seconds remaining, rounded up so a countdown never shows `0s` before it fires.
pub fn countdown(d: Duration) -> String {
    let secs = d.as_millis().div_ceil(1000);
    format!("{secs}s")
}

pub fn width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Truncates `s` to at most `max` display columns, ending in `ellipsis` when cut.
pub fn truncate<'a>(s: &'a str, max: usize, ellipsis: &str) -> Cow<'a, str> {
    if width(s) <= max {
        return Cow::Borrowed(s);
    }
    let ellipsis_width = width(ellipsis);
    if max < ellipsis_width {
        return Cow::Owned(take_columns(ellipsis, max).to_owned());
    }
    let mut out = take_columns(s, max - ellipsis_width).to_owned();
    out.push_str(ellipsis);
    Cow::Owned(out)
}

/// Truncates or right-pads `s` to exactly `cols` display columns.
pub fn fit(s: &str, cols: usize, ellipsis: &str) -> String {
    let mut out = truncate(s, cols, ellipsis).into_owned();
    let w = width(&out);
    out.extend(std::iter::repeat_n(' ', cols.saturating_sub(w)));
    out
}

/// Left-pads `s` to `cols` display columns (no truncation).
pub fn pad_left(s: &str, cols: usize) -> String {
    let w = width(s);
    let mut out = String::with_capacity(s.len() + cols.saturating_sub(w));
    out.extend(std::iter::repeat_n(' ', cols.saturating_sub(w)));
    out.push_str(s);
    out
}

/// Greedy word wrap to `cols` display columns. Words wider than a line are split.
pub fn wrap(text: &str, cols: usize) -> Vec<String> {
    let mut lines = Vec::new();
    if cols == 0 {
        return lines;
    }
    let mut line = String::new();
    for mut word in text.split_whitespace() {
        loop {
            let needed = if line.is_empty() {
                width(word)
            } else {
                width(&line) + 1 + width(word)
            };
            if needed <= cols {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
                break;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
                continue;
            }
            let head = take_columns(word, cols);
            if head.is_empty() {
                break;
            }
            lines.push(head.to_owned());
            word = &word[head.len()..];
            if word.is_empty() {
                break;
            }
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Longest prefix of `s` that fits in `cols` columns. A wide character that would straddle the
/// boundary is dropped rather than split.
fn take_columns(s: &str, cols: usize) -> &str {
    let mut used = 0;
    for (idx, ch) in s.char_indices() {
        let w = ch.width().unwrap_or(0);
        if used + w > cols {
            return &s[..idx];
        }
        used += w;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(bytes(150 * 1024 * 1024), "150 MiB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024 + 1), "3.0 GiB");
        assert_eq!(bytes(u64::MAX), "16384 PiB");
        assert_eq!(rate(2048), "2.0 KiB/s");
    }

    #[test]
    fn formats_durations() {
        assert_eq!(duration(Duration::ZERO), "0s");
        assert_eq!(duration(Duration::from_millis(59_999)), "59s");
        assert_eq!(duration(Duration::from_secs(60)), "1m 00s");
        assert_eq!(duration(Duration::from_secs(123)), "2m 03s");
        assert_eq!(duration(Duration::from_secs(3_600 + 120)), "1h 02m");
        assert_eq!(
            duration(Duration::from_secs(3 * 86_400 + 4 * 3_600)),
            "3d 04h"
        );
    }

    #[test]
    fn formats_ages() {
        assert_eq!(ago(Duration::from_millis(400)), "just now");
        assert_eq!(ago(Duration::from_secs(12)), "12s ago");
        assert_eq!(ago(Duration::from_secs(150)), "2m ago");
        assert_eq!(ago(Duration::from_secs(7_200)), "2h ago");
        assert_eq!(ago(Duration::from_secs(4 * 86_400)), "4d ago");
    }

    #[test]
    fn countdown_rounds_up() {
        assert_eq!(countdown(Duration::from_millis(1)), "1s");
        assert_eq!(countdown(Duration::from_millis(4_000)), "4s");
        assert_eq!(countdown(Duration::from_millis(4_001)), "5s");
        assert_eq!(countdown(Duration::ZERO), "0s");
    }

    #[test]
    fn truncates_by_display_width() {
        assert_eq!(truncate("Zürich #12", 20, "…"), "Zürich #12");
        assert_eq!(truncate("Zürich #12", 6, "…"), "Züric…");
        assert_eq!(truncate("Zürich #12", 6, "..."), "Zür...");
        assert_eq!(truncate("abc", 0, "…"), "");
        assert_eq!(truncate("abcdef", 2, "..."), "..");
        // CJK characters are two columns wide and must not be split.
        assert_eq!(truncate("東京サーバー", 5, "…"), "東京…");
        assert_eq!(width(&truncate("東京サーバー", 4, "…")), 3);
    }

    #[test]
    fn wraps_on_words_and_splits_long_ones() {
        assert_eq!(
            wrap(
                "Kill switch is armed. Disconnecting will block all traffic.",
                20
            ),
            [
                "Kill switch is",
                "armed. Disconnecting",
                "will block all",
                "traffic."
            ]
        );
        assert_eq!(wrap("abcdefghij", 4), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap("  spaced   out  ", 40), ["spaced out"]);
        assert!(wrap("anything", 0).is_empty());
        assert!(wrap("東京", 1).is_empty());
    }

    #[test]
    fn fit_pads_and_truncates_to_exact_width() {
        assert_eq!(fit("São Paulo", 12, "…"), "São Paulo   ");
        assert_eq!(width(&fit("São Paulo", 12, "…")), 12);
        assert_eq!(fit("Buenos Aires", 8, "…"), "Buenos …");
        assert_eq!(width(&fit("東京", 3, "…")), 3);
        assert_eq!(pad_left("41%", 5), "  41%");
        assert_eq!(pad_left("toolong", 3), "toolong");
    }
}
