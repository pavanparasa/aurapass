//! The vault data model: items, categories, attachments and settings.
//!
//! Everything in here is serialised into the encrypted payload, so fields are
//! added with `#[serde(default)]` to keep older vaults readable.

use crate::crypto::random_bytes;
use crate::generator::PasswordPolicy;
use crate::strength;
use crate::util::url_host;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current payload schema version.
pub const DATA_SCHEMA: u32 = 2;

/// The kind of secret an item holds. Drives the icon and the default template
/// shown by the desktop app.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// Website or application login.
    #[default]
    Login,
    /// A bare password with no username.
    Password,
    /// Free-form encrypted note.
    SecureNote,
    /// Payment card.
    CreditCard,
    /// Bank account details.
    BankAccount,
    /// Passport / driving licence / national id.
    Identity,
    /// SSH private key plus passphrase.
    SshKey,
    /// API token or client secret.
    ApiKey,
    /// Wireless network credentials.
    Wifi,
    /// Software licence key.
    SoftwareLicense,
    /// Database connection string.
    Database,
    /// Server / host credentials.
    Server,
    /// Anything that does not fit above.
    Custom,
}

impl ItemKind {
    /// Every kind, in the order the sidebar lists them.
    pub const ALL: [ItemKind; 13] = [
        ItemKind::Login,
        ItemKind::Password,
        ItemKind::CreditCard,
        ItemKind::BankAccount,
        ItemKind::Identity,
        ItemKind::ApiKey,
        ItemKind::SshKey,
        ItemKind::Wifi,
        ItemKind::Server,
        ItemKind::Database,
        ItemKind::SoftwareLicense,
        ItemKind::SecureNote,
        ItemKind::Custom,
    ];

    /// Human-readable name.
    pub fn label(self) -> &'static str {
        match self {
            ItemKind::Login => "Login",
            ItemKind::Password => "Password",
            ItemKind::SecureNote => "Secure Note",
            ItemKind::CreditCard => "Credit Card",
            ItemKind::BankAccount => "Bank Account",
            ItemKind::Identity => "Identity",
            ItemKind::SshKey => "SSH Key",
            ItemKind::ApiKey => "API Key",
            ItemKind::Wifi => "Wi-Fi",
            ItemKind::SoftwareLicense => "Software Licence",
            ItemKind::Database => "Database",
            ItemKind::Server => "Server",
            ItemKind::Custom => "Custom",
        }
    }

    /// A single glyph used as a lightweight icon in the UI.
    pub fn icon(self) -> &'static str {
        match self {
            ItemKind::Login => "🔑",
            ItemKind::Password => "•••",
            ItemKind::SecureNote => "📝",
            ItemKind::CreditCard => "💳",
            ItemKind::BankAccount => "🏦",
            ItemKind::Identity => "🪪",
            ItemKind::SshKey => "🔐",
            ItemKind::ApiKey => "🧩",
            ItemKind::Wifi => "📶",
            ItemKind::SoftwareLicense => "📜",
            ItemKind::Database => "🗄",
            ItemKind::Server => "🖥",
            ItemKind::Custom => "📦",
        }
    }

    /// Whether items of this kind usually carry a password to audit.
    pub fn has_auditable_password(self) -> bool {
        matches!(
            self,
            ItemKind::Login
                | ItemKind::Password
                | ItemKind::BankAccount
                | ItemKind::Server
                | ItemKind::Database
                | ItemKind::Wifi
                | ItemKind::Custom
        )
    }

    /// The label of the first field the detail pane focuses on.
    pub fn primary_secret_label(self) -> &'static str {
        match self {
            ItemKind::CreditCard => "Card number",
            ItemKind::ApiKey => "Token",
            ItemKind::SoftwareLicense => "Licence key",
            ItemKind::SshKey => "Private key",
            ItemKind::SecureNote => "Note",
            _ => "Password",
        }
    }
}

/// Semantic type of a custom field, so the UI can render the right editor.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// One-line text.
    #[default]
    Text,
    /// Masked text with a reveal toggle.
    Password,
    /// Clickable link.
    Url,
    /// Email address.
    Email,
    /// Phone number.
    Phone,
    /// ISO date.
    Date,
    /// Multi-line text.
    Multiline,
    /// Numeric value.
    Number,
    /// TOTP shared secret.
    Totp,
}

/// A user-defined field attached to an item.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Field {
    /// Stable identity for reordering and edit tracking.
    pub id: Uuid,
    /// Display label, e.g. "PIN".
    pub label: String,
    /// The value itself (plaintext inside the encrypted payload).
    pub value: String,
    /// Whether the UI should mask the value by default.
    #[serde(default)]
    pub sensitive: bool,
    /// Rendered field type.
    #[serde(default)]
    pub kind: FieldKind,
}

impl Field {
    /// Create a plain text field.
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            label: label.into(),
            value: value.into(),
            sensitive: false,
            kind: FieldKind::Text,
        }
    }

    /// Create a masked field.
    pub fn secret(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            sensitive: true,
            kind: FieldKind::Password,
            ..Self::new(label, value)
        }
    }
}

/// A file stored inside the vault, encrypted along with everything else.
///
/// Attachments are capped by the UI; keeping them inline means a vault stays a
/// single portable file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Attachment {
    /// Stable identity.
    pub id: Uuid,
    /// Original file name.
    pub name: String,
    /// MIME type, when known.
    #[serde(default)]
    pub mime: String,
    /// Size in bytes of the decoded data.
    pub size: u64,
    /// Base64 payload.
    pub data: String,
    /// When it was added.
    pub created_at: DateTime<Utc>,
}

/// One previous password, kept so users can recover an older value.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PasswordHistoryEntry {
    /// The old password.
    pub password: String,
    /// When it was replaced.
    pub changed_at: DateTime<Utc>,
}

/// A user-defined category (Enpass calls these "categories").
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Category {
    /// Stable identity.
    pub id: Uuid,
    /// Display name.
    pub name: String,
    /// Glyph shown next to the name.
    #[serde(default)]
    pub icon: String,
    /// Optional `#rrggbb` colour.
    #[serde(default)]
    pub color: Option<String>,
}

impl Category {
    /// Create a category with an auto-assigned id.
    pub fn new(name: impl Into<String>, icon: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            icon: icon.into(),
            color: None,
        }
    }
}

/// One auditable event in the vault's history.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ActivityEntry {
    /// When it happened.
    pub at: DateTime<Utc>,
    /// What happened.
    pub kind: ActivityKind,
    /// Which vault / item / app it concerned.
    pub subject: String,
    /// Optional extra detail. Never contains secrets.
    #[serde(default)]
    pub detail: Option<String>,
}

/// The kinds of events recorded in the activity log.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    /// The vault was unlocked.
    Unlocked,
    /// The vault was locked.
    Locked,
    /// An item was created.
    Created,
    /// An item was modified.
    Updated,
    /// An item was moved to the bin.
    Trashed,
    /// An item was restored from the bin.
    Restored,
    /// An item was permanently deleted.
    Deleted,
    /// The master password was changed.
    PasswordChanged,
    /// A plaintext export was written.
    Exported,
    /// Data was imported.
    Imported,
    /// A breach check was run.
    BreachChecked,
    /// A browser extension paired with the vault.
    ExtensionPaired,
    /// A browser extension consumed a credential.
    Autofilled,
}

impl ActivityKind {
    /// Short label for the activity list.
    pub fn label(self) -> &'static str {
        match self {
            ActivityKind::Unlocked => "Unlocked",
            ActivityKind::Locked => "Locked",
            ActivityKind::Created => "Created",
            ActivityKind::Updated => "Updated",
            ActivityKind::Trashed => "Moved to bin",
            ActivityKind::Restored => "Restored",
            ActivityKind::Deleted => "Deleted",
            ActivityKind::PasswordChanged => "Master password changed",
            ActivityKind::Exported => "Exported",
            ActivityKind::Imported => "Imported",
            ActivityKind::BreachChecked => "Breach check",
            ActivityKind::ExtensionPaired => "Extension paired",
            ActivityKind::Autofilled => "Filled in browser",
        }
    }
}

/// Preferences that travel with the encrypted payload.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VaultSettings {
    /// Lock the vault after this many seconds without interaction. `0` disables.
    #[serde(default = "default_auto_lock")]
    pub auto_lock_secs: u64,
    /// Clear the clipboard this many seconds after copying a secret. `0` disables.
    #[serde(default = "default_clipboard_clear")]
    pub clipboard_clear_secs: u64,
    /// Whether the health screen may query Have I Been Pwned.
    #[serde(default = "yes")]
    pub breach_check_enabled: bool,
    /// Start with secrets masked.
    #[serde(default = "yes")]
    pub hide_secrets_default: bool,
    /// Policy used by the built-in generator.
    #[serde(default)]
    pub password_policy: PasswordPolicy,
    /// `"system"`, `"dark"` or `"light"`.
    #[serde(default = "system_theme")]
    pub theme: String,
    /// Default sort order for the item list: `"title"`, `"updated"`, `"created"`.
    #[serde(default = "title_sort")]
    pub sort_order: String,
    /// Show the item list as a compact table instead of cards.
    #[serde(default)]
    pub compact_list: bool,
}

fn default_auto_lock() -> u64 {
    300
}
fn default_clipboard_clear() -> u64 {
    30
}
fn yes() -> bool {
    true
}
fn system_theme() -> String {
    "system".to_string()
}
fn title_sort() -> String {
    "title".to_string()
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            auto_lock_secs: default_auto_lock(),
            clipboard_clear_secs: default_clipboard_clear(),
            breach_check_enabled: true,
            hide_secrets_default: true,
            password_policy: PasswordPolicy::default(),
            theme: system_theme(),
            sort_order: title_sort(),
            compact_list: false,
        }
    }
}

/// A single vault entry.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Item {
    /// Stable identity; never reused.
    pub id: Uuid,
    /// What sort of secret this is.
    #[serde(default)]
    pub kind: ItemKind,
    /// Display name.
    pub title: String,
    /// Secondary line shown under the title.
    #[serde(default)]
    pub subtitle: Option<String>,
    /// Account name / e-mail.
    #[serde(default)]
    pub username: Option<String>,
    /// The secret itself.
    #[serde(default)]
    pub password: Option<String>,
    /// TOTP secret or `otpauth://` URI.
    #[serde(default)]
    pub totp: Option<String>,
    /// Websites this item belongs to.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Free-form notes.
    #[serde(default)]
    pub notes: String,
    /// Category id, when the item is filed.
    #[serde(default)]
    pub category: Option<Uuid>,
    /// Free-form tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Pinned to the top of the list.
    #[serde(default)]
    pub favorite: bool,
    /// Extra user-defined fields.
    #[serde(default)]
    pub fields: Vec<Field>,
    /// Encrypted file attachments.
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    /// Previous passwords, newest first, capped by the app.
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    /// Set when the item is in the bin.
    #[serde(default)]
    pub trashed: bool,
    /// Set when the item expires (e.g. a temporary credential).
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// When the item was created.
    pub created_at: DateTime<Utc>,
    /// When the item was last modified.
    pub updated_at: DateTime<Utc>,
    /// When a credential from this item was last used or copied.
    #[serde(default)]
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the password was last changed.
    #[serde(default)]
    pub password_changed_at: Option<DateTime<Utc>>,
    /// Reserved for future per-item icon overrides.
    #[serde(default)]
    pub icon: Option<String>,
    /// Stable id from the export this item came from, when the format has one.
    ///
    /// It is only used to recognise the same record on a later re-import; two
    /// entries that happen to share a title are still distinct entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

impl Item {
    /// A blank item of the given kind with a fresh id.
    pub fn new(kind: ItemKind, title: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            kind,
            title: title.into(),
            subtitle: None,
            username: None,
            password: None,
            totp: None,
            urls: Vec::new(),
            notes: String::new(),
            category: None,
            tags: Vec::new(),
            favorite: false,
            fields: Vec::new(),
            attachments: Vec::new(),
            password_history: Vec::new(),
            trashed: false,
            expires_at: None,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            password_changed_at: None,
            icon: None,
            external_id: None,
        }
    }

    /// Mark the item as modified now.
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// The password, if any, without allocating.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref().filter(|p| !p.is_empty())
    }

    /// Set a new password, archiving the previous one.
    ///
    /// `history_limit` caps the archive (Enpass keeps five).
    pub fn set_password(&mut self, new: impl Into<String>, history_limit: usize) {
        let new = new.into();
        if self.password.as_deref() == Some(new.as_str()) {
            return;
        }
        if let Some(old) = self.password.take().filter(|p| !p.is_empty()) {
            self.password_history.insert(
                0,
                PasswordHistoryEntry {
                    password: old,
                    changed_at: Utc::now(),
                },
            );
            self.password_history.truncate(history_limit.max(1));
        }
        self.password = if new.is_empty() { None } else { Some(new) };
        self.password_changed_at = Some(Utc::now());
        self.touch();
    }

    /// First URL that looks usable.
    pub fn primary_url(&self) -> Option<&str> {
        self.urls
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
    }

    /// Every distinct host this item is associated with.
    pub fn hosts(&self) -> Vec<String> {
        let mut out: Vec<String> = self.urls.iter().filter_map(|u| url_host(u)).collect();
        out.sort();
        out.dedup();
        out
    }

    /// Strength of the stored password.
    pub fn strength(&self) -> Option<strength::Strength> {
        self.password()
            .map(|p| strength::evaluate(p, &[self.title.as_str()]))
    }

    /// Record that the credential was used, for the "last used" sort.
    pub fn mark_used(&mut self) {
        self.last_used_at = Some(Utc::now());
    }

    /// Whether the item has expired.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|t| t <= now)
    }

    /// Case-insensitive, multi-word search across the fields a user would
    /// search. Every whitespace-separated term must match somewhere: the
    /// fields are joined into one lower-cased haystack, so
    /// `"cloudflare markus"` finds a Cloudflare login whose username is
    /// Markus regardless of which field each word came from.
    pub fn matches(&self, needle: &str) -> bool {
        let terms: Vec<String> = needle
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();
        if terms.is_empty() {
            return true;
        }

        let mut hay = String::new();
        let mut push = |value: &str| {
            if value.is_empty() {
                return;
            }
            if !hay.is_empty() {
                hay.push('\n');
            }
            hay.push_str(&value.to_lowercase());
        };

        push(&self.title);
        if let Some(subtitle) = self.subtitle.as_deref() {
            push(subtitle);
        }
        if let Some(username) = self.username.as_deref() {
            push(username);
        }
        push(&self.notes);
        if let Some(url) = self.primary_url() {
            push(url);
        }
        for url in &self.urls {
            push(url);
        }
        for tag in &self.tags {
            push(tag);
        }
        // Custom field labels and non-sensitive values are searchable too.
        for field in &self.fields {
            push(&field.label);
            if !field.sensitive {
                push(&field.value);
            }
        }

        terms.iter().all(|term| hay.contains(term.as_str()))
    }

    /// A one-line description used in list views.
    pub fn summary(&self) -> String {
        if let Some(u) = self.username.as_deref().filter(|u| !u.is_empty()) {
            return u.to_string();
        }
        if let Some(u) = self.primary_url() {
            return url_host(u).unwrap_or_else(|| u.to_string());
        }
        crate::util::truncate(self.notes.trim(), 60)
    }
}

/// Everything that is encrypted inside a vault file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VaultData {
    /// Payload schema version.
    #[serde(default = "data_schema")]
    pub schema: u32,
    /// All items, including those in the bin.
    #[serde(default)]
    pub items: Vec<Item>,
    /// User categories.
    #[serde(default)]
    pub categories: Vec<Category>,
    /// Recent activity, newest first.
    #[serde(default)]
    pub activity: Vec<ActivityEntry>,
    /// Vault preferences.
    #[serde(default)]
    pub settings: VaultSettings,
}

fn data_schema() -> u32 {
    DATA_SCHEMA
}

impl Default for VaultData {
    fn default() -> Self {
        Self {
            schema: DATA_SCHEMA,
            items: Vec::new(),
            categories: Vec::new(),
            activity: Vec::new(),
            settings: VaultSettings::default(),
        }
    }
}

impl VaultData {
    /// Number of entries kept in the activity log.
    pub const ACTIVITY_LIMIT: usize = 400;

    /// Append an activity entry, trimming the log to its limit.
    pub fn push_activity(&mut self, kind: ActivityKind, subject: impl Into<String>, detail: Option<String>) {
        self.activity.insert(
            0,
            ActivityEntry {
                at: Utc::now(),
                kind,
                subject: subject.into(),
                detail,
            },
        );
        self.activity.truncate(Self::ACTIVITY_LIMIT);
    }

    /// Find an item by id.
    pub fn get(&self, id: Uuid) -> Option<&Item> {
        self.items.iter().find(|i| i.id == id)
    }

    /// Find an item by id, mutably.
    pub fn get_mut(&mut self, id: Uuid) -> Option<&mut Item> {
        self.items.iter_mut().find(|i| i.id == id)
    }

    /// Insert or replace an item by id.
    pub fn upsert(&mut self, item: Item) {
        match self.items.iter_mut().find(|i| i.id == item.id) {
            Some(slot) => *slot = item,
            None => self.items.push(item),
        }
    }

    /// Items currently in the bin.
    pub fn trashed(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| i.trashed)
    }

    /// Items not in the bin.
    pub fn active(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| !i.trashed)
    }

    /// Every distinct tag, sorted.
    pub fn all_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self
            .items
            .iter()
            .flat_map(|i| i.tags.iter().cloned())
            .filter(|t| !t.trim().is_empty())
            .collect();
        tags.sort_by_key(|t| t.to_lowercase());
        tags.dedup();
        tags
    }

    /// Resolve a category id to its name.
    pub fn category_name(&self, id: Uuid) -> Option<&str> {
        self.categories
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.name.as_str())
    }

    /// Resolve a category by (case-insensitive) name, creating it when needed.
    pub fn category_by_name_or_create(&mut self, name: &str) -> Uuid {
        if let Some(existing) = self
            .categories
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
        {
            return existing.id;
        }
        let cat = Category::new(name, "📁");
        let id = cat.id;
        self.categories.push(cat);
        id
    }

    /// Count of items per kind, for the sidebar badges.
    pub fn count_by_kind(&self, kind: ItemKind) -> usize {
        self.active().filter(|i| i.kind == kind).count()
    }

    /// Passwords that appear on more than one item.
    ///
    /// Returns a map from password to the ids that share it. Passwords shorter
    /// than eight characters are ignored, since they are already flagged as weak
    /// and reporting them twice is noise.
    pub fn reused_passwords(&self) -> Vec<(String, Vec<Uuid>)> {
        use std::collections::HashMap;
        let mut map: HashMap<&str, Vec<Uuid>> = HashMap::new();
        for item in self.active() {
            if let Some(p) = item.password()
                && p.len() >= 8
            {
                map.entry(p).or_default().push(item.id);
            }
        }
        let mut out: Vec<(String, Vec<Uuid>)> = map
            .into_iter()
            .filter(|(_, ids)| ids.len() > 1)
            .map(|(p, ids)| (p.to_string(), ids))
            .collect();
        out.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        out
    }

    /// Items whose title and username are identical (likely duplicates).
    pub fn duplicate_groups(&self) -> Vec<Vec<Uuid>> {
        use std::collections::HashMap;
        let mut map: HashMap<(String, String), Vec<Uuid>> = HashMap::new();
        for item in self.active() {
            let key = (
                item.title.trim().to_lowercase(),
                item.username.clone().unwrap_or_default().trim().to_lowercase(),
            );
            if key.0.is_empty() && key.1.is_empty() {
                continue;
            }
            map.entry(key).or_default().push(item.id);
        }
        map.into_values().filter(|v| v.len() > 1).collect()
    }
}

/// A random, human-pronounceable-ish default title for brand-new items.
pub fn default_title(kind: ItemKind) -> String {
    kind.label().to_string()
}

/// Generate a short random suffix, used when names must be unique.
pub fn short_suffix() -> String {
    let bytes = random_bytes::<3>();
    crate::util::hex_encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_history_is_capped_and_newest_first() {
        let mut item = Item::new(ItemKind::Login, "x");
        item.set_password("one", 2);
        item.set_password("two", 2);
        item.set_password("three", 2);
        assert_eq!(item.password(), Some("three"));
        assert_eq!(item.password_history.len(), 2);
        assert_eq!(item.password_history[0].password, "two");
        assert_eq!(item.password_history[1].password, "one");
    }

    #[test]
    fn reused_passwords_only_reports_shared_ones() {
        let mut data = VaultData::default();
        for name in ["a", "b"] {
            let mut it = Item::new(ItemKind::Login, name);
            it.set_password("shared-secret", 5);
            data.upsert(it);
        }
        let mut unique = Item::new(ItemKind::Login, "c");
        unique.set_password("unique-secret", 5);
        data.upsert(unique);

        let reused = data.reused_passwords();
        assert_eq!(reused.len(), 1);
        assert_eq!(reused[0].0, "shared-secret");
        assert_eq!(reused[0].1.len(), 2);
    }

    #[test]
    fn search_matches_hosts_and_tags() {
        let mut it = Item::new(ItemKind::Login, "GitHub");
        it.urls.push("https://github.com/login".into());
        it.tags.push("work".into());
        assert!(it.matches("github"));
        assert!(it.matches("WORK"));
        assert!(!it.matches("gitlab"));
    }

    #[test]
    fn search_requires_every_word_across_fields() {
        let mut it = Item::new(ItemKind::Login, "Cloudflare");
        it.urls.push("https://dash.cloudflare.com/login".into());
        it.username = Some("markus".into());

        assert!(it.matches("cloudflare markus"));
        assert!(it.matches("markus cloudflare"));
        assert!(it.matches("dash markus"));
        assert!(it.matches("  CLOUDFLARE   MARKUS  "));
        assert!(!it.matches("cloudflare jane"));
        assert!(!it.matches("github markus"));
    }
}
