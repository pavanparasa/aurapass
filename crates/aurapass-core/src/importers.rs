//! Importers and exporters.
//!
//! AuraPass deliberately speaks the formats that other password managers
//! produce, so switching costs nothing:
//!
//! | Format | Direction |
//! |---|---|
//! | Enpass (JSON + CSV) | in / out |
//! | Bitwarden (JSON + CSV) | in / out |
//! | LastPass CSV | in |
//! | 1Password CSV | in / out |
//! | Chrome / Edge / Brave CSV | in |
//! | KeePass(XC) CSV | in / out |
//! | Generic CSV | in |
//!
//! Parsing works on `serde_json::Value` and raw CSV rather than typed structs,
//! because every one of these formats changes shape between versions and a
//! strict struct would break on the next release.

use crate::error::{Error, Result};
use crate::model::{Field, FieldKind, Item, ItemKind};
use crate::util::{csv_parse, csv_write, url_host, CsvRecord};
use chrono::Utc;
use serde_json::Value;

/// A format AuraPass can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportFormat {
    /// Sniff from the file contents.
    #[default]
    Auto,
    /// Enpass `.json` export.
    EnpassJson,
    /// Enpass `.csv` export.
    EnpassCsv,
    /// Bitwarden (unencrypted) `.json` export.
    BitwardenJson,
    /// Bitwarden `.csv` export.
    BitwardenCsv,
    /// LastPass `.csv` export.
    LastPassCsv,
    /// Chrome / Edge / Brave password `.csv` export.
    ChromeCsv,
    /// 1Password `.csv` export.
    OnePasswordCsv,
    /// KeePass `.csv` export.
    KeePassCsv,
    /// Any other CSV with recognisable columns.
    GenericCsv,
}

impl ImportFormat {
    /// Every concrete (non-auto) format.
    pub const ALL: [ImportFormat; 9] = [
        ImportFormat::EnpassJson,
        ImportFormat::EnpassCsv,
        ImportFormat::BitwardenJson,
        ImportFormat::BitwardenCsv,
        ImportFormat::LastPassCsv,
        ImportFormat::ChromeCsv,
        ImportFormat::OnePasswordCsv,
        ImportFormat::KeePassCsv,
        ImportFormat::GenericCsv,
    ];

    /// Display name.
    pub fn label(self) -> &'static str {
        match self {
            ImportFormat::Auto => "Detect automatically",
            ImportFormat::EnpassJson => "Enpass (JSON)",
            ImportFormat::EnpassCsv => "Enpass (CSV)",
            ImportFormat::BitwardenJson => "Bitwarden (JSON)",
            ImportFormat::BitwardenCsv => "Bitwarden (CSV)",
            ImportFormat::LastPassCsv => "LastPass (CSV)",
            ImportFormat::ChromeCsv => "Chrome / Edge / Brave (CSV)",
            ImportFormat::OnePasswordCsv => "1Password (CSV)",
            ImportFormat::KeePassCsv => "KeePass (CSV)",
            ImportFormat::GenericCsv => "Other CSV",
        }
    }

    /// File-name hint used by the file picker.
    pub fn extension(self) -> &'static str {
        match self {
            ImportFormat::Auto | ImportFormat::EnpassJson | ImportFormat::BitwardenJson => "json",
            ImportFormat::EnpassCsv
            | ImportFormat::BitwardenCsv
            | ImportFormat::LastPassCsv
            | ImportFormat::ChromeCsv
            | ImportFormat::OnePasswordCsv
            | ImportFormat::KeePassCsv
            | ImportFormat::GenericCsv => "csv",
        }
    }
}

/// A parsed import, ready to be merged into a vault.
#[derive(Debug, Clone)]
pub struct ImportPreview {
    /// Which parser actually ran.
    pub format: ImportFormat,
    /// The items that were understood.
    pub items: Vec<Item>,
    /// Non-fatal problems worth showing the user.
    pub warnings: Vec<String>,
    /// Rows that were dropped because they carried no usable data.
    pub skipped: usize,
}

impl ImportPreview {
    /// Total number of records examined.
    pub fn total(&self) -> usize {
        self.items.len() + self.skipped
    }

    /// One-line summary for the UI.
    pub fn summary(&self) -> String {
        format!(
            "{}: {} entries{}",
            self.format.label(),
            self.items.len(),
            if self.skipped > 0 {
                format!(", {} skipped", self.skipped)
            } else {
                String::new()
            }
        )
    }
}

/// Guess the format from the content and (optionally) the file name.
pub fn detect(content: &str, filename: Option<&str>) -> ImportFormat {
    let trimmed = content.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        // Both Enpass and Bitwarden have top-level "items" and "folders", and
        // both may contain a "fields" key.  Enpass fields are label/value
        // pairs; Bitwarden wraps logins in a "login" object and its custom
        // fields use "name"/"value".  Inspect the shape rather than the text,
        // otherwise an Enpass export is misread as Bitwarden and most entries
        // are silently lost.
        if let Ok(root) = serde_json::from_str::<Value>(trimmed) {
            let items = items_array(&root);
            let enpass = items.iter().any(|item| {
                let labelled = item
                    .get("fields")
                    .and_then(|v| v.as_array())
                    .is_some_and(|fields| fields.iter().any(|f| f.get("label").is_some()));
                labelled
                    || (item.get("uuid").is_some()
                        && item.get("category").is_some_and(|c| c.is_string()))
            });
            if enpass {
                return ImportFormat::EnpassJson;
            }
            if items.iter().any(|item| item.get("login").is_some())
                || root.get("encrypted").is_some()
            {
                return ImportFormat::BitwardenJson;
            }
            if root.get("folders").is_some() {
                return ImportFormat::BitwardenJson;
            }
            return ImportFormat::EnpassJson;
        }
        // Not valid JSON: fall back to the old textual hints so the parser can
        // report the real syntax error.
        return ImportFormat::EnpassJson;
    }

    // Enpass writes a headerless CSV: the title, then label/value pairs such
    // as "Username", "", "E-mail", "…", "*Password", "…", "Website", "…".
    // Treating its first record as a header loses that entry and shifts every
    // column, so recognise the layout before looking for headers.
    let header = first_header_line(content);
    if header.len() >= 9 {
        let label_at = |wanted: &str| {
            (1..header.len())
                .step_by(2)
                .any(|i| normalise(&header[i]) == wanted)
        };
        if label_at("username")
            && label_at("password")
            && (label_at("website") || label_at("additionaldetails"))
        {
            return ImportFormat::EnpassCsv;
        }
    }

    let columns: Vec<String> = header.iter().map(|c| normalise(c)).collect();
    let has = |name: &str| columns.iter().any(|c| c == name);

    if has("otpauth") || has("onepasswordtype") {
        return ImportFormat::OnePasswordCsv;
    }
    // LastPass exports carry `grouping` and `fav`; some versions use the
    // `loginuri`/`loginusername` column names instead.
    if has("grouping") || has("fav") || has("loginuri") || has("loginusername") {
        return ImportFormat::LastPassCsv;
    }
    if has("name") && has("url") && has("username") && has("password") && !has("category") && !has("folder") {
        return ImportFormat::ChromeCsv;
    }
    if has("notes") && has("title") && has("category") {
        return ImportFormat::EnpassCsv;
    }
    if has("folder") || has("favorite") || has("type") {
        return ImportFormat::BitwardenCsv;
    }
    if let Some(name) = filename {
        let lower = name.to_ascii_lowercase();
        if lower.contains("lastpass") {
            return ImportFormat::LastPassCsv;
        }
        if lower.contains("bitwarden") {
            return ImportFormat::BitwardenCsv;
        }
        if lower.contains("enpass") {
            return ImportFormat::EnpassCsv;
        }
        if lower.contains("chrome") || lower.contains("edge") || lower.contains("brave") {
            return ImportFormat::ChromeCsv;
        }
    }
    ImportFormat::GenericCsv
}

fn first_header_line(content: &str) -> Vec<String> {
    content
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| {
            let delimiter = if l.matches('\t').count() > l.matches(',').count() {
                '\t'
            } else if l.matches(';').count() > l.matches(',').count() {
                ';'
            } else {
                ','
            };
            csv_parse(l, delimiter)
                .into_iter()
                .next()
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

/// Lowercase and strip everything that is not a letter or digit.
fn normalise(s: &str) -> String {
    s.trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// Parse `content` in the given format.
pub fn parse(content: &str, format: ImportFormat) -> Result<ImportPreview> {
    let filename = None;
    let format = match format {
        ImportFormat::Auto => detect(content, filename),
        other => other,
    };
    match format {
        ImportFormat::EnpassJson => parse_enpass_json(content),
        ImportFormat::BitwardenJson => parse_bitwarden_json(content),
        ImportFormat::EnpassCsv => parse_enpass_csv(content),
        ImportFormat::BitwardenCsv
        | ImportFormat::LastPassCsv
        | ImportFormat::ChromeCsv
        | ImportFormat::OnePasswordCsv
        | ImportFormat::KeePassCsv
        | ImportFormat::GenericCsv => parse_csv(content, format),
        ImportFormat::Auto => unreachable!("auto is resolved above"),
    }
}

// ------------------------------------------------------------------ JSON

fn value_str(obj: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(v) = obj.get(*key) {
            match v {
                Value::String(s) if !s.trim().is_empty() => return Some(s.clone()),
                Value::Number(n) => return Some(n.to_string()),
                Value::Bool(b) => return Some(b.to_string()),
                _ => {}
            }
        }
    }
    None
}

fn items_array(root: &Value) -> Vec<&Value> {
    if let Some(arr) = root.as_array() {
        return arr.iter().collect();
    }
    root.get("items")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

fn parse_enpass_json(content: &str) -> Result<ImportPreview> {
    let root: Value = serde_json::from_str(content)
        .map_err(|e| Error::Import(format!("not valid JSON: {e}")))?;
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let mut skipped = 0;

    for raw in items_array(&root) {
        let title = value_str(raw, &["title", "name"]).unwrap_or_default();
        if title.trim().is_empty() {
            skipped += 1;
            continue;
        }
        let category = value_str(raw, &["category", "type"]);
        let mut item = Item::new(kind_from_category(category.as_deref()), title);
        item.external_id = value_str(raw, &["uuid", "id"]);

        if let Some(fields) = raw.get("fields").and_then(|v| v.as_array()) {
            for field in fields {
                let label = value_str(field, &["label", "name"]).unwrap_or_default();
                let value = value_str(field, &["value", "data"]).unwrap_or_default();
                if label.is_empty() && value.is_empty() {
                    continue;
                }
                let sensitive = field
                    .get("sensitive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let type_id = field.get("type").and_then(|v| v.as_i64()).unwrap_or(0);
                apply_enpass_field(&mut item, &label, value, sensitive, type_id);
            }
        }

        if let Some(note) = value_str(raw, &["note", "notes"]) {
            item.notes = note;
        }
        if let Some(sub) = value_str(raw, &["subtitle"]) {
            item.subtitle = Some(sub);
        }
        if let Some(urls) = raw.get("urls").and_then(|v| v.as_array()) {
            for u in urls {
                if let Some(s) = u.as_str().filter(|s| !s.trim().is_empty()) {
                    item.urls.push(s.to_string());
                }
            }
        }
        if let Some(fav) = raw.get("favorite").and_then(|v| v.as_bool()) {
            item.favorite = fav;
        }
        if let Some(tags) = raw.get("tags").and_then(|v| v.as_array()) {
            for tag in tags {
                if let Some(s) = tag.as_str().filter(|s| !s.trim().is_empty()) {
                    item.tags.push(s.to_string());
                }
            }
        }
        if item.urls.is_empty()
            && let Some(url) = value_str(raw, &["url", "website"])
        {
            item.urls.push(url);
        }
        if let Some(attachments) = raw.get("attachments").and_then(|v| v.as_array())
            && !attachments.is_empty()
        {
            warnings.push(format!(
                "“{}”: {} attachment(s) were not imported (export them separately)",
                item.title,
                attachments.len()
            ));
        }
        items.push(item);
    }

    Ok(ImportPreview {
        format: ImportFormat::EnpassJson,
        items,
        warnings,
        skipped,
    })
}

/// Map Enpass's numeric field types onto our model.
fn apply_enpass_field(item: &mut Item, label: &str, value: String, sensitive: bool, type_id: i64) {
    let lower = label.to_ascii_lowercase();
    let is = |names: &[&str]| names.iter().any(|n| lower == *n || lower.ends_with(*n));

    if type_id == 8 || is(&["totp", "otp", "one time password", "authenticator", "otpauth"]) {
        item.totp = Some(value);
        return;
    }
    if type_id == 1 || is(&["password", "passwd"]) {
        if item.password.is_none() {
            item.password = Some(value.clone());
            item.password_changed_at = Some(Utc::now());
            return;
        }
        item.fields.push(Field::secret(label, value));
        return;
    }
    if is(&["username", "user name", "login", "email", "e-mail", "user"]) && item.username.is_none() {
        item.username = Some(value);
        return;
    }
    if type_id == 3 || is(&["url", "website", "link"]) {
        if !value.trim().is_empty() {
            item.urls.push(value);
        }
        return;
    }
    if is(&["title", "name"]) {
        item.title = value;
        return;
    }
    if is(&["note", "notes"]) {
        item.notes = value;
        return;
    }
    if sensitive {
        item.fields.push(Field::secret(label, value));
        return;
    }

    let kind = match type_id {
        1 => FieldKind::Password,
        2 => FieldKind::Email,
        3 => FieldKind::Url,
        4 => FieldKind::Multiline,
        5 => FieldKind::Number,
        6 => FieldKind::Phone,
        7 => FieldKind::Date,
        _ => FieldKind::Text,
    };
    item.fields.push(Field {
        id: uuid::Uuid::new_v4(),
        label: if label.is_empty() { "Field".into() } else { label.to_string() },
        value,
        sensitive,
        kind,
    });
}

/// Enpass CSV is not a table with a header: each row is a title followed by
/// label/value pairs. Empty values are still present, which is what keeps the
/// pairs aligned. A naive "first row is the header" parse loses an entry and
/// shifts every field, so it gets its own reader.
fn parse_enpass_csv(content: &str) -> Result<ImportPreview> {
    let delimiter = sniff_delimiter(content);
    let records = csv_parse(content, delimiter);
    if records.is_empty() {
        return Err(Error::Import("the file contains no rows".into()));
    }

    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let mut skipped = 0;

    for record in records {
        if record.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let title = record.first().map(|s| s.trim()).unwrap_or("");
        if title.is_empty() {
            skipped += 1;
            continue;
        }
        // Some third-party converters put a header row on top. The layout
        // check keeps us from dropping a real entry whose title is "Title".
        if normalise(title) == "title"
            && record.get(1).is_some_and(|c| normalise(c) == "username")
            && record.get(3).is_some_and(|c| {
                let key = normalise(c);
                key == "password" || key == "email"
            })
        {
            continue;
        }

        let mut item = Item::new(ItemKind::Login, title);
        let mut index = 1;
        while index + 1 < record.len() {
            let label = record[index].trim();
            let value = record[index + 1].trim();
            index += 2;
            if label.is_empty() {
                continue;
            }
            apply_enpass_csv_field(&mut item, label, value);
        }
        items.push(item);
    }

    if items.is_empty() {
        return Err(Error::Import(
            "no entries were found in this Enpass CSV".into(),
        ));
    }
    if skipped > 0 {
        warnings.push(format!("{skipped} row(s) had no title and were skipped"));
    }

    Ok(ImportPreview {
        format: ImportFormat::EnpassCsv,
        items,
        warnings,
        skipped,
    })
}

fn apply_enpass_csv_field(item: &mut Item, label: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    let key = normalise(label);
    match key.as_str() {
        "additionaldetails" | "section" | "sections" => {}
        "username" => {
            if item.username.is_none() {
                item.username = Some(value.to_string());
            } else if item.username.as_deref() != Some(value) {
                item.fields.push(Field::new("Username", value));
            }
        }
        "email" | "emailaddress" => {
            if item.username.is_none() {
                item.username = Some(value.to_string());
            } else if item.username.as_deref() != Some(value)
                && !item.fields.iter().any(|f| f.label == "E-mail" && f.value == value)
            {
                item.fields.push(Field::new("E-mail", value));
            }
        }
        "password" | "passwd" => {
            if item.password.is_none() {
                item.password = Some(value.to_string());
                item.password_changed_at = Some(Utc::now());
            } else if item.password.as_deref() != Some(value) {
                item.fields.push(Field::secret("Password", value));
            }
        }
        "website" | "url" | "websiteurl" | "link" => {
            if !item.urls.iter().any(|u| u.eq_ignore_ascii_case(value)) {
                item.urls.push(value.to_string());
            }
        }
        "totp" | "otp" | "onetimecode" | "onetimepassword" | "authenticator" => {
            item.totp = Some(value.to_string());
        }
        "notes" | "note" => {
            if item.notes.is_empty() {
                item.notes = value.to_string();
            } else {
                item.notes.push('\n');
                item.notes.push_str(value);
            }
        }
        "securityanswer" => item.fields.push(Field::secret(
            label.trim_start_matches('*').trim(),
            value,
        )),
        _ => {
            let name = label.trim_start_matches('*').trim();
            let name = if name.is_empty() { "Field" } else { name };
            if label.trim_start().starts_with('*') {
                item.fields.push(Field::secret(name, value));
            } else {
                item.fields.push(Field::new(name, value));
            }
        }
    }
}

fn parse_bitwarden_json(content: &str) -> Result<ImportPreview> {
    let root: Value = serde_json::from_str(content)
        .map_err(|e| Error::Import(format!("not valid JSON: {e}")))?;
    if root.get("encrypted").and_then(|v| v.as_bool()) == Some(true) {
        return Err(Error::Import(
            "this is an encrypted Bitwarden export; re-export it without a password".into(),
        ));
    }

    let folder_names: std::collections::HashMap<String, String> = root
        .get("folders")
        .and_then(|v| v.as_array())
        .map(|folders| {
            folders
                .iter()
                .filter_map(|f| {
                    Some((
                        value_str(f, &["id"])?,
                        value_str(f, &["name"]).unwrap_or_else(|| "Folder".into()),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let mut skipped = 0;

    for raw in items_array(&root) {
        let title = value_str(raw, &["name", "title"]).unwrap_or_default();
        if title.trim().is_empty() {
            skipped += 1;
            continue;
        }
        let type_id = raw.get("type").and_then(|v| v.as_i64()).unwrap_or(1);
        let kind = match type_id {
            2 => ItemKind::SecureNote,
            3 => ItemKind::CreditCard,
            4 => ItemKind::Identity,
            _ => ItemKind::Login,
        };
        let mut item = Item::new(kind, title);
        item.external_id = value_str(raw, &["id"]);

        if let Some(notes) = value_str(raw, &["notes"]) {
            item.notes = notes;
        }
        if raw.get("favorite").and_then(|v| v.as_bool()) == Some(true) {
            item.favorite = true;
        }
        if let Some(folder) = raw
            .get("folderId")
            .and_then(|v| v.as_str())
            .and_then(|id| folder_names.get(id))
        {
            item.subtitle = Some(folder.clone());
        }

        if let Some(login) = raw.get("login") {
            if let Some(u) = value_str(login, &["username"]) {
                item.username = Some(u);
            }
            if let Some(p) = value_str(login, &["password"]) {
                item.password = Some(p);
                item.password_changed_at = Some(Utc::now());
            }
            if let Some(t) = value_str(login, &["totp"]) {
                item.totp = Some(t);
            }
            if let Some(uris) = login.get("uris").and_then(|v| v.as_array()) {
                for u in uris {
                    if let Some(s) = value_str(u, &["uri"]).filter(|s| !s.trim().is_empty()) {
                        item.urls.push(s);
                    }
                }
            }
        }

        if let Some(card) = raw.get("card") {
            for (label, keys) in [
                ("Cardholder", &["cardholderName"][..]),
                ("Brand", &["brand"][..]),
                ("Number", &["number"][..]),
                ("Expiry", &["expMonth", "expYear"][..]),
                ("CVV", &["code"][..]),
            ] {
                if let Some(v) = value_str(card, keys) {
                    let sensitive = matches!(label, "Number" | "CVV");
                    item.fields.push(if sensitive {
                        Field::secret(label, v)
                    } else {
                        Field::new(label, v)
                    });
                }
            }
        }

        if let Some(identity) = raw.get("identity") {
            for (label, key) in [
                ("Full name", "firstName"),
                ("Last name", "lastName"),
                ("Address", "address1"),
                ("City", "city"),
                ("Postcode", "postalCode"),
                ("Country", "country"),
                ("Phone", "phone"),
                ("Email", "email"),
            ] {
                if let Some(v) = value_str(identity, &[key]) {
                    item.fields.push(Field::new(label, v));
                }
            }
        }

        if let Some(fields) = raw.get("fields").and_then(|v| v.as_array()) {
            for field in fields {
                let label = value_str(field, &["name"]).unwrap_or_default();
                let value = value_str(field, &["value"]).unwrap_or_default();
                if label.is_empty() && value.is_empty() {
                    continue;
                }
                // Bitwarden field types: 0 text, 1 hidden, 2 boolean, 3 linked.
                let sensitive = field.get("type").and_then(|v| v.as_i64()) == Some(1);
                if sensitive {
                    item.fields.push(Field::secret(label, value));
                } else {
                    item.fields.push(Field::new(label, value));
                }
            }
        }

        if let Some(attachments) = raw.get("attachments").and_then(|v| v.as_array())
            && !attachments.is_empty()
        {
            warnings.push(format!(
                "“{}”: attachments are not included in JSON exports",
                item.title
            ));
        }

        items.push(item);
    }

    Ok(ImportPreview {
        format: ImportFormat::BitwardenJson,
        items,
        warnings,
        skipped,
    })
}

// ------------------------------------------------------------------- CSV

/// Canonical columns the CSV importer understands, and the aliases each maps to.
const COLUMN_ALIASES: &[(&str, &[&str])] = &[
    ("title", &["title", "name", "account", "item", "entryname", "accountname"]),
    ("username", &["username", "user", "login", "loginusername", "email", "userid"]),
    ("password", &["password", "pass", "loginpassword", "secret"]),
    ("url", &["url", "urls", "website", "loginuri", "link", "webaddress", "site"]),
    ("totp", &["totp", "otp", "otpauth", "otpsecret", "totpsecret", "onetimepassword", "authenticatorkey"]),
    ("notes", &["notes", "note", "comments", "extra", "description"]),
    ("category", &["category", "group", "grouping", "folder", "type", "onepasswordtype"]),
    ("tags", &["tags", "tag", "labels"]),
    ("favorite", &["favorite", "favourite", "fav", "starred", "pinned"]),
    ("expiry", &["expiry", "expires", "expirydate", "expiration"]),
];

fn parse_csv(content: &str, format: ImportFormat) -> Result<ImportPreview> {
    let delimiter = sniff_delimiter(content);
    let mut records = csv_parse(content, delimiter);
    if records.is_empty() {
        return Err(Error::Import("the file contains no rows".into()));
    }
    let header = records.remove(0);

    // Map each column index onto a canonical role.
    let mut roles: Vec<Option<&'static str>> = Vec::with_capacity(header.len());
    let mut extras: Vec<(usize, String)> = Vec::new();
    for (index, column) in header.iter().enumerate() {
        let key = normalise(column);
        let role = COLUMN_ALIASES.iter().find_map(|(role, aliases)| {
            aliases.iter().find(|a| **a == key).map(|_| *role)
        });
        match role {
            Some(role) => roles.push(Some(role)),
            None => {
                roles.push(None);
                if !key.is_empty() {
                    extras.push((index, column.trim().to_string()));
                }
            }
        }
    }

    if !roles.iter().any(|r| *r == Some("title")) {
        // Without a title column we cannot build meaningful entries; treat the
        // first column as the title, which is right for the common case.
        if let Some(first) = roles.first_mut() {
            *first = Some("title");
        }
    }

    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let mut skipped = 0;
    let duplicate_headers = header.len() != roles.len();

    for record in records {
        if record.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let mut item: Option<Item> = None;
        let mut extra_values: Vec<(String, String)> = Vec::new();

        for (index, role) in roles.iter().enumerate() {
            let value = record.get(index).cloned().unwrap_or_default();
            let value_trimmed = value.trim().to_string();
            match role {
                Some("title") => {
                    let title = if value_trimmed.is_empty() {
                        "Untitled".to_string()
                    } else {
                        value_trimmed.clone()
                    };
                    // A value may arrive before the title column; in that case
                    // the item already exists as a placeholder and must not be
                    // thrown away.
                    match item.as_mut() {
                        Some(existing) => existing.title = title,
                        None => item = Some(Item::new(ItemKind::Login, title)),
                    }
                }
                Some("username") if !value_trimmed.is_empty() => {
                    let it = ensure(&mut item, &record, roles_iter(&roles));
                    if it.username.is_none() {
                        it.username = Some(value_trimmed);
                    }
                }
                Some("password") if !value_trimmed.is_empty() => {
                    let it = ensure(&mut item, &record, roles_iter(&roles));
                    if it.password.is_none() {
                        it.password = Some(value);
                        it.password_changed_at = Some(Utc::now());
                    }
                }
                Some("url") if !value_trimmed.is_empty() => {
                    let it = ensure(&mut item, &record, roles_iter(&roles));
                    for part in value_trimmed.split(['|', ',', '\n']) {
                        let part = part.trim();
                        if !part.is_empty() && !it.urls.contains(&part.to_string()) {
                            it.urls.push(part.to_string());
                        }
                    }
                }
                Some("totp") if !value_trimmed.is_empty() => {
                    let it = ensure(&mut item, &record, roles_iter(&roles));
                    it.totp = Some(value_trimmed);
                }
                Some("notes") if !value_trimmed.is_empty() => {
                    let it = ensure(&mut item, &record, roles_iter(&roles));
                    if it.notes.is_empty() {
                        it.notes = value;
                    } else {
                        it.notes.push('\n');
                        it.notes.push_str(&value);
                    }
                }
                Some("category") if !value_trimmed.is_empty() => {
                    let it = ensure(&mut item, &record, roles_iter(&roles));
                    it.subtitle = Some(value_trimmed.clone());
                    it.kind = kind_from_category(Some(&value_trimmed));
                }
                Some("tags") if !value_trimmed.is_empty() => {
                    let it = ensure(&mut item, &record, roles_iter(&roles));
                    for tag in value_trimmed.split(['|', ',', ';']) {
                        let tag = tag.trim();
                        if !tag.is_empty() {
                            it.tags.push(tag.to_string());
                        }
                    }
                }
                Some("favorite") => {
                    let truthy = matches!(
                        value_trimmed.to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "y"
                    );
                    let it = ensure(&mut item, &record, roles_iter(&roles));
                    it.favorite = truthy;
                }
                Some("expiry") if !value_trimmed.is_empty() => {
                    let it = ensure(&mut item, &record, roles_iter(&roles));
                    it.subtitle.get_or_insert_with(|| value_trimmed.clone());
                }
                _ => {}
            }
        }

        for (index, label) in &extras {
            if let Some(value) = record.get(*index).filter(|v| !v.trim().is_empty()) {
                extra_values.push((label.clone(), value.trim().to_string()));
            }
        }

        match item {
            Some(mut it) => {
                for (label, value) in extra_values {
                    it.fields.push(Field::new(label, value));
                }
                if it.title.trim().is_empty() {
                    skipped += 1;
                    continue;
                }
                items.push(it);
            }
            None => skipped += 1,
        }
    }

    if duplicate_headers {
        warnings.push("the header row had duplicate column names".into());
    }
    if extras.len() > 8 {
        warnings.push(format!(
            "{} unrecognised columns were imported as custom fields",
            extras.len()
        ));
    }

    Ok(ImportPreview {
        format: if format == ImportFormat::Auto {
            ImportFormat::GenericCsv
        } else {
            format
        },
        items,
        warnings,
        skipped,
    })
}

fn roles_iter(roles: &[Option<&'static str>]) -> Vec<Option<&'static str>> {
    roles.to_vec()
}

/// Build a placeholder item when a value arrives before the title column.
fn ensure<'a>(slot: &'a mut Option<Item>, record: &CsvRecord, _roles: Vec<Option<&'static str>>) -> &'a mut Item {
    if slot.is_none() {
        let guess = record
            .iter()
            .find(|c| url_host(c).is_some())
            .and_then(|c| url_host(c))
            .unwrap_or_else(|| "Imported entry".to_string());
        *slot = Some(Item::new(ItemKind::Login, guess));
    }
    slot.as_mut().expect("just inserted")
}

fn sniff_delimiter(content: &str) -> char {
    let line = content.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let candidates = [',', '\t', ';', '|'];
    candidates
        .into_iter()
        .max_by_key(|c| line.matches(*c).count())
        .filter(|c| line.matches(*c).count() > 0)
        .unwrap_or(',')
}

/// Best-effort mapping from a category / folder label onto [`ItemKind`].
pub fn kind_from_category(category: Option<&str>) -> ItemKind {
    let Some(raw) = category else {
        return ItemKind::Login;
    };
    let c = raw.trim().to_ascii_lowercase();
    let c = c.as_str();
    if c.contains("credit") || c.contains("card") {
        ItemKind::CreditCard
    } else if c.contains("bank") || c.contains("financial") {
        ItemKind::BankAccount
    } else if c.contains("note") {
        ItemKind::SecureNote
    } else if c.contains("identity") || c.contains("personal") || c.contains("contact") {
        ItemKind::Identity
    } else if c.contains("ssh") {
        ItemKind::SshKey
    } else if c.contains("api") || c.contains("token") || c.contains("developer") {
        ItemKind::ApiKey
    } else if c.contains("wifi") || c.contains("wi-fi") || c.contains("network") {
        ItemKind::Wifi
    } else if c.contains("licence") || c.contains("license") || c.contains("software") {
        ItemKind::SoftwareLicense
    } else if c.contains("database") || c.contains("db") {
        ItemKind::Database
    } else if c.contains("server") || c.contains("hosting") {
        ItemKind::Server
    } else if c.contains("password") {
        ItemKind::Password
    } else if c.contains("login") || c.contains("web") || c.contains("account") {
        ItemKind::Login
    } else if c.is_empty() {
        ItemKind::Login
    } else {
        ItemKind::Custom
    }
}

// --------------------------------------------------------------- export

/// Column order used by [`export_csv`] (also understood by our own importer).
pub const CSV_HEADERS: [&str; 10] = [
    "Title", "Category", "Type", "Username", "Password", "TOTP", "URL", "Notes", "Tags",
    "Favorite",
];

/// Export items to CSV text (Enpass-compatible column names).
///
/// **The result is plaintext.** The GUI and CLI both warn before writing one.
pub fn export_csv(items: &[Item]) -> String {
    let mut records: Vec<CsvRecord> = Vec::with_capacity(items.len() + 1);
    records.push(CSV_HEADERS.iter().map(|s| s.to_string()).collect());
    for item in items {
        let category = item
            .subtitle
            .clone()
            .unwrap_or_else(|| item.kind.label().to_string());
        records.push(vec![
            item.title.clone(),
            category,
            item.kind.label().to_string(),
            item.username.clone().unwrap_or_default(),
            item.password.clone().unwrap_or_default(),
            item.totp.clone().unwrap_or_default(),
            item.urls.join("|"),
            item.notes.clone(),
            item.tags.join("|"),
            if item.favorite { "true".into() } else { String::new() },
        ]);
    }
    csv_write(&records, ',')
}

/// Export items to an Enpass-shaped JSON document.
///
/// **The result is plaintext.**
pub fn export_json(items: &[Item], vault_name: &str) -> Result<String> {
    let items: Vec<Value> = items
        .iter()
        .map(|item| {
            let mut fields: Vec<Value> = Vec::new();
            if let Some(u) = &item.username {
                fields.push(serde_json::json!({
                    "label": "Username", "value": u, "type": 0, "sensitive": false
                }));
            }
            if let Some(p) = &item.password {
                fields.push(serde_json::json!({
                    "label": "Password", "value": p, "type": 1, "sensitive": true
                }));
            }
            if let Some(t) = &item.totp {
                fields.push(serde_json::json!({
                    "label": "TOTP", "value": t, "type": 8, "sensitive": true
                }));
            }
            for url in &item.urls {
                fields.push(serde_json::json!({
                    "label": "Website", "value": url, "type": 3, "sensitive": false
                }));
            }
            for f in &item.fields {
                fields.push(serde_json::json!({
                    "label": f.label,
                    "value": f.value,
                    "type": match f.kind {
                        FieldKind::Password => 1,
                        FieldKind::Email => 2,
                        FieldKind::Url => 3,
                        FieldKind::Multiline => 4,
                        FieldKind::Number => 5,
                        FieldKind::Phone => 6,
                        FieldKind::Date => 7,
                        FieldKind::Totp => 8,
                        FieldKind::Text => 0,
                    },
                    "sensitive": f.sensitive,
                }));
            }
            serde_json::json!({
                "title": item.title,
                "subtitle": item.subtitle,
                "category": item.kind.label(),
                "note": item.notes,
                "favorite": item.favorite,
                "tags": item.tags,
                "fields": fields,
            })
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
        "format": "aurapass-export",
        "vault": vault_name,
        "exported_at": Utc::now().to_rfc3339(),
        "warning": "This file is NOT encrypted. Delete it when you are done.",
        "items": items,
    }))
    .map_err(Error::from)
}

/// Write a CSV/JSON export to disk with owner-only permissions.
pub fn write_export(path: &std::path::Path, content: &str) -> Result<()> {
    crate::util::atomic_write(path, content.as_bytes(), 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENPASS_JSON: &str = r#"{
      "items": [
        {
          "title": "GitHub",
          "category": "Login",
          "note": "work account",
          "fields": [
            {"label": "Username", "value": "alice", "type": 0},
            {"label": "Password", "value": "s3cret", "type": 1, "sensitive": true},
            {"label": "Website", "value": "https://github.com", "type": 3},
            {"label": "PIN", "value": "1234", "type": 5}
          ],
          "favorite": true
        },
        {
          "title": "Wi-Fi at home",
          "category": "Wi-Fi",
          "fields": [
            {"label": "Password", "value": "supersecretwifi", "type": 1, "sensitive": true}
          ]
        }
      ]
    }"#;

    const BITWARDEN_JSON: &str = r#"{
      "encrypted": false,
      "folders": [{"id": "f1", "name": "Work"}],
      "items": [
        {
          "type": 1,
          "name": "Example",
          "notes": "hello",
          "favorite": true,
          "folderId": "f1",
          "login": {
            "username": "bob",
            "password": "pw123",
            "totp": "JBSWY3DPEHPK3PXP",
            "uris": [{"uri": "https://example.com"}]
          },
          "fields": [{"name": "Recovery", "value": "abc-123", "type": 1}]
        },
        {"type": 3, "name": "Visa", "card": {"cardholderName": "Bob", "number": "4111111111111111", "code": "123"}}
      ]
    }"#;

    const CHROME_CSV: &str = "name,url,username,password,note\nGitHub,https://github.com,alice,pw123,\n";

    // Enpass CSV has no header row: title, then label/value pairs.
    const ENPASS_CSV: &str = concat!(
        "GitHub,Username,alice,E-mail,alice@example.com,*Password,s3cret,",
        "Website,https://github.com,ADDITIONAL DETAILS,,One-time code,",
        "JBSWY3DPEHPK3PXP,Security question,Pet,*Security answer,Fluffy\n",
        "Amazon,Username,,E-mail,,*Password,pw2,Website,https://amazon.com,",
        "ADDITIONAL DETAILS,,,,,,,,\n"
    );

    const LASTPASS_CSV: &str =
        "url,username,password,totp,extra,name,grouping,fav\nhttps://gitlab.com,alice,pw456,,notes here,GitLab,Work,1\n";

    #[test]
    fn detect_picks_sensible_formats() {
        assert_eq!(detect(ENPASS_JSON, None), ImportFormat::EnpassJson);
        assert_eq!(detect(BITWARDEN_JSON, None), ImportFormat::BitwardenJson);
        assert_eq!(detect(CHROME_CSV, None), ImportFormat::ChromeCsv);
        assert_eq!(detect(LASTPASS_CSV, None), ImportFormat::LastPassCsv);
        assert_eq!(detect(ENPASS_CSV, None), ImportFormat::EnpassCsv);
        assert_eq!(detect("Title,Category,Notes\nx,y,z\n", None), ImportFormat::EnpassCsv);
    }

    #[test]
    fn enpass_csv_is_headerless_label_value_pairs() {
        let preview = parse(ENPASS_CSV, ImportFormat::EnpassCsv).unwrap();
        assert_eq!(preview.items.len(), 2);
        let gh = &preview.items[0];
        assert_eq!(gh.title, "GitHub");
        assert_eq!(gh.username.as_deref(), Some("alice"));
        assert_eq!(gh.password(), Some("s3cret"));
        assert_eq!(gh.urls, vec!["https://github.com"]);
        assert_eq!(gh.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(
            gh.fields
                .iter()
                .any(|f| f.label == "Security answer" && f.sensitive)
        );
        assert_eq!(preview.items[1].username, None);
        assert_eq!(preview.items[1].password(), Some("pw2"));
    }

    #[test]
    fn enpass_json_with_folders_is_not_bitwarden() {
        let json = r#"{
          "folders": [{"id": "f1", "name": "Work"}],
          "items": [{
            "uuid": "e-1",
            "title": "Login",
            "category": "login",
            "fields": [
              {"label": "Username", "value": "alice", "type": 0},
              {"label": "Password", "value": "pw", "type": 1, "sensitive": true}
            ]
          }]
        }"#;
        assert_eq!(detect(json, None), ImportFormat::EnpassJson);
        let preview = parse(json, ImportFormat::Auto).unwrap();
        assert_eq!(preview.items.len(), 1);
        assert_eq!(preview.items[0].external_id.as_deref(), Some("e-1"));
    }

    #[test]
    fn enpass_json_import() {
        let preview = parse(ENPASS_JSON, ImportFormat::Auto).unwrap();
        assert_eq!(preview.items.len(), 2);
        let gh = &preview.items[0];
        assert_eq!(gh.title, "GitHub");
        assert_eq!(gh.username.as_deref(), Some("alice"));
        assert_eq!(gh.password(), Some("s3cret"));
        assert_eq!(gh.urls, vec!["https://github.com"]);
        assert_eq!(gh.notes, "work account");
        assert!(gh.favorite);
        assert!(gh.fields.iter().any(|f| f.label == "PIN" && f.value == "1234"));
        assert_eq!(preview.items[1].kind, ItemKind::Wifi);
    }

    #[test]
    fn bitwarden_json_import() {
        let preview = parse(BITWARDEN_JSON, ImportFormat::Auto).unwrap();
        assert_eq!(preview.items.len(), 2);
        let login = &preview.items[0];
        assert_eq!(login.username.as_deref(), Some("bob"));
        assert_eq!(login.password(), Some("pw123"));
        assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(login.subtitle.as_deref(), Some("Work"));
        assert!(login.fields.iter().any(|f| f.label == "Recovery" && f.sensitive));
        let card = &preview.items[1];
        assert_eq!(card.kind, ItemKind::CreditCard);
        assert!(card.fields.iter().any(|f| f.label == "Number" && f.sensitive));
    }

    #[test]
    fn encrypted_bitwarden_export_is_refused_with_a_clear_message() {
        let err = parse(r#"{"encrypted": true, "items": []}"#, ImportFormat::BitwardenJson)
            .unwrap_err();
        assert!(err.to_string().contains("encrypted"));
    }

    #[test]
    fn chrome_csv_import() {
        let preview = parse(CHROME_CSV, ImportFormat::Auto).unwrap();
        assert_eq!(preview.items.len(), 1);
        let it = &preview.items[0];
        assert_eq!(it.title, "GitHub");
        assert_eq!(it.username.as_deref(), Some("alice"));
        assert_eq!(it.password(), Some("pw123"));
        assert_eq!(it.urls, vec!["https://github.com"]);
    }

    #[test]
    fn lastpass_csv_import_handles_extra_columns() {
        let preview = parse(LASTPASS_CSV, ImportFormat::Auto).unwrap();
        assert_eq!(preview.items.len(), 1);
        let it = &preview.items[0];
        assert_eq!(it.title, "GitLab");
        assert_eq!(it.notes, "notes here");
        assert!(it.favorite);
        assert_eq!(it.subtitle.as_deref(), Some("Work"));
    }

    #[test]
    fn csv_roundtrip_through_our_own_exporter() {
        let original = parse(ENPASS_JSON, ImportFormat::Auto).unwrap().items;
        let csv = export_csv(&original);
        let back = parse(&csv, ImportFormat::GenericCsv).unwrap();
        assert_eq!(back.items.len(), original.len());
        for (a, b) in original.iter().zip(back.items.iter()) {
            assert_eq!(a.title, b.title);
            assert_eq!(a.username, b.username);
            assert_eq!(a.password, b.password);
            assert_eq!(a.notes, b.notes);
            assert_eq!(a.urls, b.urls);
            assert_eq!(a.favorite, b.favorite);
        }
    }

    #[test]
    fn json_export_is_plaintext_and_reimportable() {
        let original = parse(BITWARDEN_JSON, ImportFormat::Auto).unwrap().items;
        let json = export_json(&original, "Test").unwrap();
        assert!(json.contains("NOT encrypted"));
        let back = parse(&json, ImportFormat::EnpassJson).unwrap();
        assert_eq!(back.items.len(), original.len());
        assert_eq!(back.items[0].title, "Example");
        assert_eq!(back.items[0].password(), Some("pw123"));
    }

    #[test]
    fn csv_with_quotes_and_commas_survives() {
        let mut item = Item::new(ItemKind::Login, "Comma, Inc.");
        item.password = Some("pa,ss\"word".into());
        item.notes = "line one\nline two".into();
        let csv = export_csv(std::slice::from_ref(&item));
        let back = parse(&csv, ImportFormat::GenericCsv).unwrap();
        assert_eq!(back.items[0].title, "Comma, Inc.");
        assert_eq!(back.items[0].password(), Some("pa,ss\"word"));
        assert_eq!(back.items[0].notes, "line one\nline two");
    }

    #[test]
    fn category_mapping_covers_the_common_labels() {
        assert_eq!(kind_from_category(Some("Credit Card")), ItemKind::CreditCard);
        assert_eq!(kind_from_category(Some("Secure Note")), ItemKind::SecureNote);
        assert_eq!(kind_from_category(Some("Wi-Fi")), ItemKind::Wifi);
        assert_eq!(kind_from_category(Some("Login")), ItemKind::Login);
        assert_eq!(kind_from_category(Some("Something else")), ItemKind::Custom);
        assert_eq!(kind_from_category(None), ItemKind::Login);
    }

    #[test]
    fn empty_csv_is_an_error() {
        assert!(parse("", ImportFormat::GenericCsv).is_err());
    }

    #[test]
    fn semicolon_delimited_csv_is_handled() {
        let csv = "Title;Username;Password\nRouter;admin;hunter22\n";
        let preview = parse(csv, ImportFormat::GenericCsv).unwrap();
        assert_eq!(preview.items.len(), 1);
        assert_eq!(preview.items[0].username.as_deref(), Some("admin"));
        assert_eq!(preview.items[0].password(), Some("hunter22"));
    }
}
