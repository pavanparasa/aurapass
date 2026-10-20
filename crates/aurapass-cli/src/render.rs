//! Terminal output helpers: tables, rules and JSON serialisation.
//!
//! Kept deliberately small and dependency-free. Column widths are computed
//! from the widest cell, and CJK/emoji widths are approximated by counting
//! [`unicode_width`]-ish classes manually — good enough for a terminal table
//! and much cheaper than pulling in a layout crate.

use aurapass_core::error::Result;
use aurapass_core::model::Item;
use serde_json::json;

/// Knobs for [`table`].
#[derive(Debug, Clone, Copy)]
pub struct TableOptions {
    /// Draw a rule under the header row.
    pub header_rule: bool,
    /// Separator inserted between columns.
    pub delimiter: &'static str,
}

impl Default for TableOptions {
    fn default() -> Self {
        Self {
            header_rule: true,
            delimiter: "  ",
        }
    }
}

/// Approximate display width of a string.
///
/// Emoji and CJK glyphs are counted as two columns, combining marks as zero.
fn display_width(s: &str) -> usize {
    s.chars()
        .map(|c| {
            let code = c as u32;
            let wide = matches!(code,
                0x1100..=0x115F     // Hangul Jamo
                | 0x2E80..=0x303E   // CJK radicals, Kangxi
                | 0x3041..=0x33FF   // Hiragana … CJK compatibility
                | 0x3400..=0x4DBF   // CJK ext A
                | 0x4E00..=0x9FFF   // CJK unified
                | 0xA000..=0xA4CF   // Yi
                | 0xAC00..=0xD7A3   // Hangul syllables
                | 0xF900..=0xFAFF   // CJK compatibility ideographs
                | 0xFE30..=0xFE6F   // CJK compatibility forms
                | 0xFF00..=0xFF60   // Fullwidth forms
                | 0x1F300..=0x1FAFF // emoji
                | 0x2600..=0x27BF   // symbols / dingbats
            );
            if wide {
                2
            } else if (0x0300..=0x036F).contains(&code) {
                0
            } else {
                1
            }
        })
        .sum()
}

fn pad(s: &str, width: usize) -> String {
    let actual = display_width(s);
    if actual >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - actual))
    }
}

/// Render a simple left-aligned table.
pub fn table(headers: &[&str], rows: &[Vec<String>], options: TableOptions) -> String {
    let columns = headers.len().max(rows.iter().map(|r| r.len()).max().unwrap_or(0));
    let mut widths = vec![0usize; columns];
    for (index, header) in headers.iter().enumerate() {
        widths[index] = widths[index].max(display_width(header));
    }
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index < columns {
                widths[index] = widths[index].max(display_width(cell));
            }
        }
    }

    let mut out = String::new();
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| pad(h, widths[i]))
        .collect();
    out.push_str(header_line.join(options.delimiter).trim_end());
    out.push('\n');
    if options.header_rule {
        out.push_str(&rule_for(&widths, options.delimiter));
        out.push('\n');
    }
    for row in rows {
        let cells: Vec<String> = (0..columns)
            .map(|i| pad(row.get(i).map(String::as_str).unwrap_or(""), widths[i]))
            .collect();
        out.push_str(cells.join(options.delimiter).trim_end());
        out.push('\n');
    }
    out.trim_end().to_string()
}

fn rule_for(widths: &[usize], delimiter: &str) -> String {
    widths
        .iter()
        .map(|w| "─".repeat((*w).max(2)))
        .collect::<Vec<_>>()
        .join(delimiter)
}

/// A horizontal rule sized for a normal terminal.
pub fn rule() -> String {
    let width = std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(64)
        .clamp(20, 100);
    "─".repeat(width)
}

/// Indent every line of `text`.
pub fn indent(text: &str, prefix: &str) -> String {
    text.lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A text progress bar, e.g. `████░░░░`.
pub fn bar(fraction: f32, width: usize) -> String {
    let clamped = fraction.clamp(0.0, 1.0);
    let filled = ((clamped * width as f32).round() as usize).min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

/// Serialise an item as JSON, masking secrets unless `reveal` is set.
pub fn item_json(item: &Item, reveal: bool) -> Result<String> {
    let secret = |value: &Option<String>| -> Option<String> {
        match value {
            None => None,
            Some(v) if reveal => Some(v.clone()),
            Some(_) => Some("••••••••".to_string()),
        }
    };
    let payload = json!({
        "id": item.id,
        "kind": item.kind,
        "title": item.title,
        "subtitle": item.subtitle,
        "username": item.username,
        "password": secret(&item.password),
        "totp": secret(&item.totp),
        "urls": item.urls,
        "notes": item.notes,
        "tags": item.tags,
        "favorite": item.favorite,
        "trashed": item.trashed,
        "category": item.category,
        "fields": item.fields.iter().map(|f| json!({
            "label": f.label,
            "value": if f.sensitive && !reveal { "••••••••".to_string() } else { f.value.clone() },
            "sensitive": f.sensitive,
        })).collect::<Vec<_>>(),
        "attachments": item.attachments.iter().map(|a| json!({
            "name": a.name, "size": a.size, "mime": a.mime,
        })).collect::<Vec<_>>(),
        "password_history_count": item.password_history.len(),
        "created_at": item.created_at,
        "updated_at": item.updated_at,
        "last_used_at": item.last_used_at,
        "password_changed_at": item.password_changed_at,
        "strength": item.strength().map(|s| json!({
            "score": s.score, "label": s.label, "crack_time": s.crack_time, "bits": s.bits(),
        })),
    });
    Ok(serde_json::to_string_pretty(&payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurapass_core::model::ItemKind;

    #[test]
    fn tables_align_and_drop_trailing_space() {
        let out = table(
            &["A", "BBBB"],
            &[
                vec!["1".into(), "x".into()],
                vec!["longer".into(), "y".into()],
            ],
            TableOptions::default(),
        );
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4, "header + rule + 2 rows");
        assert!(lines[0].starts_with("A "));
        assert!(lines[2].starts_with("1"));
        assert!(lines[3].starts_with("longer  y"));
        assert!(!lines.iter().any(|l| l.ends_with(' ')));
    }

    #[test]
    fn widths_account_for_wide_glyphs() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("🔑"), 2);
        assert_eq!(display_width("日本"), 4);
    }

    #[test]
    fn bar_is_bounded() {
        assert_eq!(bar(0.0, 10), "░".repeat(10));
        assert_eq!(bar(1.0, 10), "█".repeat(10));
        assert_eq!(bar(1.5, 10), "█".repeat(10));
        assert_eq!(bar(-1.0, 10), "░".repeat(10));
        assert_eq!(bar(0.5, 10).chars().count(), 10);
    }

    #[test]
    fn json_masks_secrets_unless_revealed() {
        let mut item = Item::new(ItemKind::Login, "Test");
        item.password = Some("hunter2".into());
        item.totp = Some("JBSWY3DPEHPK3PXP".into());
        item.fields.push(aurapass_core::model::Field::secret("PIN", "1234"));

        let masked: serde_json::Value =
            serde_json::from_str(&item_json(&item, false).unwrap()).unwrap();
        assert_eq!(masked["password"], "••••••••");
        assert_eq!(masked["totp"], "••••••••");
        assert_eq!(masked["fields"][0]["value"], "••••••••");

        let shown: serde_json::Value =
            serde_json::from_str(&item_json(&item, true).unwrap()).unwrap();
        assert_eq!(shown["password"], "hunter2");
        assert_eq!(shown["fields"][0]["value"], "1234");
    }

    #[test]
    fn indent_prefixes_every_line() {
        assert_eq!(indent("a\nb", "> "), "> a\n> b");
    }
}
