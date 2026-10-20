//! Small, dependency-free helpers: base64, hex, CSV, atomic file writes.

use crate::error::{Error, Result};
use base64::Engine as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Standard (padded) base64 alphabet, used for everything stored in a vault.
pub fn b64_encode(data: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode padded standard base64.
pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| Error::Crypto(format!("invalid base64: {e}")))
}

/// URL-safe, unpadded base64 — used for bridge tokens and query strings.
pub fn b64url_encode(data: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decode URL-safe, unpadded base64.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| Error::Crypto(format!("invalid base64url: {e}")))
}

/// Lowercase hex encoding.
pub fn hex_encode(data: impl AsRef<[u8]>) -> String {
    let mut out = String::with_capacity(data.as_ref().len() * 2);
    for b in data.as_ref() {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// Decode a hex string (case-insensitive). Odd lengths are rejected.
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(Error::Crypto("odd-length hex string".into()));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let nib = |c: u8| -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(Error::Crypto(format!("invalid hex digit {:?}", c as char))),
        }
    };
    for pair in bytes.chunks(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Ok(out)
}

/// Write `bytes` to `path` atomically with `0600` permissions.
///
/// The data is written to a sibling temporary file, fsynced, and then renamed
/// over the target. A crash therefore leaves either the old or the new file,
/// never a half-written vault.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut tmp: PathBuf = parent.join(format!(
        ".{}.tmp{}",
        path.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "aurapass".into()),
        std::process::id()
    ));
    // Extremely unlikely, but never clobber an existing temp file.
    let mut n = 0;
    while tmp.exists() {
        n += 1;
        tmp = parent.join(format!(".aurapass.tmp{}-{n}", std::process::id()));
    }

    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            f.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    fs::rename(&tmp, path)?;
    // Best-effort durability for the rename itself.
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Restrict a file to the owner (`0600`). No-op when the mode is already right.
pub fn harden_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let meta = fs::metadata(path)?;
        if meta.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// One parsed CSV record.
pub type CsvRecord = Vec<String>;

/// Parse RFC 4180-ish CSV. Handles quoted fields, escaped quotes (`""`), CRLF
/// and embedded newlines. Deliberately forgiving: a stray quote in the middle
/// of an unquoted field is treated literally instead of aborting the import.
pub fn csv_parse(input: &str, delimiter: char) -> Vec<CsvRecord> {
    let mut records: Vec<CsvRecord> = Vec::new();
    let mut record: CsvRecord = Vec::new();
    let mut field = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;
    let mut field_started = false;

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }

        if c == '"' && !field_started {
            in_quotes = true;
            field_started = true;
        } else if c == delimiter {
            record.push(std::mem::take(&mut field));
            field_started = false;
        } else if c == '\n' {
            record.push(std::mem::take(&mut field));
            field_started = false;
            records.push(std::mem::take(&mut record));
        } else if c == '\r' {
            // swallow; the \n handles the record break
        } else {
            field.push(c);
            field_started = true;
        }
    }

    if !field.is_empty() || !record.is_empty() || field_started {
        record.push(field);
        records.push(record);
    }
    // Drop trailing empty lines.
    records.retain(|r| !(r.len() == 1 && r[0].trim().is_empty()));
    records
}

/// Escape one CSV field, quoting it only when necessary.
pub fn csv_escape(field: &str, delimiter: char) -> String {
    let needs_quotes = field.contains(delimiter)
        || field.contains('"')
        || field.contains('\n')
        || field.contains('\r')
        || field.trim() != field;
    if needs_quotes {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Serialise records to CSV text with CRLF line endings.
pub fn csv_write(records: &[CsvRecord], delimiter: char) -> String {
    let mut out = String::new();
    for rec in records {
        let line: Vec<String> = rec.iter().map(|f| csv_escape(f, delimiter)).collect();
        out.push_str(&line.join(&delimiter.to_string()));
        out.push_str("\r\n");
    }
    out
}

/// Lowercased host of a URL-ish string, without `www.` or a trailing slash.
/// Returns `None` when there is nothing host-like to extract.
pub fn url_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let after_scheme = match trimmed.find("://") {
        Some(i) => &trimmed[i + 3..],
        None => trimmed,
    };
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host.strip_prefix("www.").unwrap_or(&host).to_string())
    }
}

/// Truncate a string to `max` characters, appending an ellipsis when cut.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Render a byte count the way a file manager would.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Expand a leading `~` to the user's home directory.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = directories::UserDirs::new()
    {
        return home.home_dir().join(rest);
    }
    if path == "~"
        && let Some(home) = directories::UserDirs::new()
    {
        return home.home_dir().to_path_buf();
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_roundtrip_with_quotes() {
        let recs = vec![
            vec!["a".into(), "b,c".into(), "d\"e".into()],
            vec!["1".into(), "multi\nline".into(), "".into()],
        ];
        let text = csv_write(&recs, ',');
        let back = csv_parse(&text, ',');
        assert_eq!(back, recs);
    }

    #[test]
    fn url_host_extraction() {
        assert_eq!(url_host("https://www.example.com/login"), Some("example.com".into()));
        assert_eq!(url_host("example.com:8443/x"), Some("example.com".into()));
        assert_eq!(url_host("ftp://sub.example.co.uk/a/b"), Some("sub.example.co.uk".into()));
        assert_eq!(url_host("   "), None);
    }

    #[test]
    fn hex_roundtrip() {
        let v = vec![0x00, 0x0f, 0xf0, 0xff];
        assert_eq!(hex_encode(&v), "000ff0ff");
        assert_eq!(hex_decode("000FF0ff").unwrap(), v);
    }
}
