//! The vault container: reading, writing, unlocking and locking vault files.
//!
//! See the crate-level docs for the on-disk layout. The important properties:
//!
//! * **Authenticated headers.** The canonical header JSON is used as AEAD
//!   associated data, so KDF parameters, the vault name and the wrapped key
//!   cannot be tampered with.
//! * **Chained payload.** The vault body is bound to `SHA-256(header)` and the
//!   revision counter, so a rollback to an older body is detected.
//! * **Password changes are cheap.** Only the master-key wrap is rewritten, the
//!   payload is re-sealed (it must be, since its AAD changes) but the key never
//!   has to be re-derived from scratch for every item.
//! * **Atomic writes.** Saves go through a temporary file and `rename(2)`, with
//!   `0600` permissions.

use crate::audit::{self, AuditOptions, AuditReport};
use crate::crypto::{self, KdfParams, KdfPreset, Key, Sealed};
use crate::error::{Error, Result};
use crate::model::{ActivityKind, Item, ItemKind, VaultData};
use crate::util::{atomic_write, harden_permissions};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Magic value stored in every vault file.
pub const FORMAT_MAGIC: &str = "aurapass-vault";

/// Refuse to read anything larger than this (512 MiB) so a bogus file cannot
/// exhaust memory.
pub const MAX_VAULT_BYTES: u64 = 512 * 1024 * 1024;

/// Minimum length we accept for a new master password.
pub const MIN_MASTER_PASSWORD_LEN: usize = 8;

/// How many old passwords we keep per item.
pub const PASSWORD_HISTORY_LIMIT: usize = 5;

/// Content identity for imports from formats that carry no stable record id.
///
/// Title and username alone are not an identity: password managers routinely
/// contain several entries called "Login" or "Amazon".  Matching on the whole
/// record means re-importing a CSV still skips entries that are genuinely the
/// same, while two distinct entries with the same title are both kept.
fn import_fingerprint(item: &Item) -> String {
    let mut urls: Vec<String> = item
        .urls
        .iter()
        .map(|u| u.trim().to_ascii_lowercase())
        .filter(|u| !u.is_empty())
        .collect();
    urls.sort();
    urls.dedup();

    let mut fields: Vec<String> = item
        .fields
        .iter()
        .map(|f| {
            format!(
                "{}={}={}",
                f.label.trim().to_ascii_lowercase(),
                f.value,
                f.sensitive
            )
        })
        .collect();
    fields.sort();

    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        item.title.trim().to_lowercase(),
        item.username
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_lowercase(),
        item.password.as_deref().unwrap_or(""),
        item.totp.as_deref().unwrap_or(""),
        item.notes,
        urls.join("\u{1e}"),
        fields.join("\u{1e}"),
    )
}

/// Size of the plaintext header + ciphertext envelope, in JSON.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    /// Always [`FORMAT_MAGIC`].
    pub format: String,
    /// Container format version.
    pub version: u32,
    /// Random identifier, stable for the life of the vault.
    pub vault_id: Uuid,
    /// Display name of the vault.
    #[serde(default)]
    pub name: String,
    /// Password KDF parameters.
    pub kdf: KdfParams,
    /// The master key, wrapped by the password-derived KEK.
    pub key_wrap: Sealed,
    /// The encrypted payload.
    pub data: Sealed,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp.
    pub updated_at: DateTime<Utc>,
    /// Monotonic revision counter, bumped on every save.
    #[serde(default)]
    pub revision: u64,
    /// Whether a key file participates in the KEK derivation.
    #[serde(default)]
    pub has_keyfile: bool,
    /// Free-form note shown on the unlock screen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl Envelope {
    /// The canonical header: everything except the payload, serialised with
    /// stable key ordering. This is the AEAD associated data.
    pub fn header_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("data");
        }
        Ok(serde_json::to_vec(&value)?)
    }

    /// Associated data for unwrapping the master key.
    ///
    /// This deliberately covers only the fields that describe *how the key is
    /// protected* — never the wrap itself and never the revision counter, which
    /// changes after the wrap has been made. Binding these fields stops an
    /// attacker from downgrading the Argon2 cost or swapping in their own wrap.
    fn key_wrap_aad(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct KeyWrapAad<'a> {
            format: &'a str,
            version: u32,
            vault_id: Uuid,
            name: &'a str,
            kdf: &'a KdfParams,
            has_keyfile: bool,
        }
        let aad = KeyWrapAad {
            format: &self.format,
            version: self.version,
            vault_id: self.vault_id,
            name: &self.name,
            kdf: &self.kdf,
            has_keyfile: self.has_keyfile,
        };
        Ok(serde_json::to_vec(&aad)?)
    }

    /// Associated data for the payload: binds it to the header *and* the
    /// revision, so a stale body paired with a newer header fails to verify.
    fn data_aad(&self) -> Result<Vec<u8>> {
        let mut aad = crypto::sha256(self.header_bytes()?).to_vec();
        aad.extend_from_slice(&self.revision.to_be_bytes());
        Ok(aad)
    }

    /// Derive the KEK and unwrap the master key.
    pub fn unwrap_master_key(&self, password: &str, keyfile: Option<&[u8]>) -> Result<Key> {
        if self.has_keyfile && keyfile.is_none() {
            // Still attempt the derivation: the flag is advisory, and a vault
            // moved between machines may have lost its key file.
        }
        let kek = crypto::derive_kek(password, keyfile, &self.kdf)?;
        self.key_wrap
            .open(&kek, &self.key_wrap_aad()?)
            .map_err(|_| Error::InvalidPassword)
            .and_then(|raw| Key::from_slice(&raw))
    }

    /// Wrap and store a master key under `password`.
    fn wrap_master_key(
        &mut self,
        key: &Key,
        password: &str,
        keyfile: Option<&[u8]>,
    ) -> Result<()> {
        // `has_keyfile` participates in the AAD, so it must be set before the
        // wrap is produced.
        self.has_keyfile = keyfile.is_some();
        let kek = crypto::derive_kek(password, keyfile, &self.kdf)?;
        let aad = self.key_wrap_aad()?;
        self.key_wrap = Sealed::seal(&kek, &aad, key.as_bytes())?;
        Ok(())
    }

    /// Encrypt `payload` into this envelope.
    fn seal_payload(&mut self, key: &Key, payload: &[u8]) -> Result<()> {
        let aad = self.data_aad()?;
        self.data = Sealed::seal(key, &aad, payload)?;
        Ok(())
    }

    /// Decrypt the payload.
    pub fn open_payload(&self, key: &Key) -> Result<Vec<u8>> {
        self.data
            .open(key, &self.data_aad()?)
            .map_err(|_| Error::AeadFailed)
    }
}

/// Snapshot of a vault file's public metadata, shown before unlocking.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultInfo {
    /// Where the file lives.
    pub path: PathBuf,
    /// Display name.
    pub name: String,
    /// Stable vault identifier.
    pub vault_id: Uuid,
    /// Container format version.
    pub version: u32,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last save time.
    pub updated_at: DateTime<Utc>,
    /// Save counter.
    pub revision: u64,
    /// KDF parameters.
    pub kdf: KdfParams,
    /// Whether a key file is required.
    pub has_keyfile: bool,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Optional note.
    pub comment: Option<String>,
}

/// A vault file on disk, locked.
#[derive(Debug, Clone)]
pub struct VaultFile {
    /// Parsed header and ciphertext.
    pub envelope: Envelope,
    /// Where it was loaded from, when known.
    pub path: Option<PathBuf>,
}

impl VaultFile {
    /// Read and validate a vault file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let meta = std::fs::metadata(path)?;
        if meta.len() > MAX_VAULT_BYTES {
            return Err(Error::InvalidFormat(format!(
                "file is {} which exceeds the {} limit",
                crate::util::human_bytes(meta.len()),
                crate::util::human_bytes(MAX_VAULT_BYTES)
            )));
        }
        // Warn-by-fixing: a vault readable by other users is a bug, not a
        // feature.
        harden_permissions(path)?;

        let mut file = std::fs::File::open(path)?;
        let mut buf = Vec::with_capacity(meta.len() as usize);
        file.read_to_end(&mut buf)?;
        let envelope: Envelope = serde_json::from_slice(&buf)
            .map_err(|e| Error::InvalidFormat(format!("could not parse the header: {e}")))?;

        if envelope.format != FORMAT_MAGIC {
            return Err(Error::InvalidFormat(format!(
                "expected format {FORMAT_MAGIC:?}, found {:?}",
                envelope.format
            )));
        }
        if envelope.version > crate::VAULT_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: envelope.version,
                supported: crate::VAULT_FORMAT_VERSION,
            });
        }

        Ok(Self {
            envelope,
            path: Some(path.to_path_buf()),
        })
    }

    /// Cheap check used when scanning a directory for vaults.
    pub fn looks_like_vault(path: impl AsRef<Path>) -> bool {
        let Ok(mut file) = std::fs::File::open(path.as_ref()) else {
            return false;
        };
        let mut head = [0u8; 256];
        let Ok(n) = file.read(&mut head) else {
            return false;
        };
        String::from_utf8_lossy(&head[..n]).contains(FORMAT_MAGIC)
    }

    /// Public metadata, without needing the password.
    pub fn info(&self) -> VaultInfo {
        let size_bytes = self
            .path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0);
        VaultInfo {
            path: self.path.clone().unwrap_or_default(),
            name: self.envelope.name.clone(),
            vault_id: self.envelope.vault_id,
            version: self.envelope.version,
            created_at: self.envelope.created_at,
            updated_at: self.envelope.updated_at,
            revision: self.envelope.revision,
            kdf: self.envelope.kdf.clone(),
            has_keyfile: self.envelope.has_keyfile,
            size_bytes,
            comment: self.envelope.comment.clone(),
        }
    }

    /// Check a password (and key file) without keeping the vault open.
    pub fn verify_password(&self, password: &str, keyfile: Option<&[u8]>) -> Result<bool> {
        Ok(self.unwrap_master_key(password, keyfile).is_ok())
    }

    /// Convenience wrapper around [`Envelope::unwrap_master_key`].
    pub fn unwrap_master_key(&self, password: &str, keyfile: Option<&[u8]>) -> Result<Key> {
        self.envelope.unwrap_master_key(password, keyfile)
    }

    /// Create a brand-new vault on disk and return it unlocked.
    pub fn create(
        path: impl AsRef<Path>,
        password: &str,
        name: impl Into<String>,
        preset: KdfPreset,
        keyfile: Option<&[u8]>,
    ) -> Result<UnlockedVault> {
        validate_master_password(password)?;
        let now = Utc::now();
        let key = Key::generate();

        let mut envelope = Envelope {
            format: FORMAT_MAGIC.to_string(),
            version: crate::VAULT_FORMAT_VERSION,
            vault_id: Uuid::new_v4(),
            name: name.into(),
            kdf: KdfParams::with_preset(preset),
            key_wrap: Sealed::seal(&Key::generate(), b"", b"placeholder")?,
            data: Sealed::seal(&Key::generate(), b"", b"placeholder")?,
            created_at: now,
            updated_at: now,
            revision: 1,
            has_keyfile: false,
            comment: None,
        };
        envelope.wrap_master_key(&key, password, keyfile)?;

        let mut data = VaultData::default();
        data.push_activity(
            ActivityKind::Created,
            "Vault created",
            Some(format!("KDF: {}", preset.label())),
        );

        let payload = serde_json::to_vec(&data)?;
        envelope.seal_payload(&key, &payload)?;

        let file = VaultFile {
            envelope,
            path: Some(path.as_ref().to_path_buf()),
        };
        let mut unlocked = UnlockedVault {
            file,
            key,
            data,
            dirty: false,
            session_started: Instant::now(),
            last_activity: Instant::now(),
        };
        unlocked.save()?;
        Ok(unlocked)
    }

    /// Unlock this vault.
    pub fn unlock(&self, password: &str, keyfile: Option<&[u8]>) -> Result<UnlockedVault> {
        let key = self.unwrap_master_key(password, keyfile)?;
        self.unlock_with_key(key)
    }

    /// Unlock with an already-unwrapped master key.
    ///
    /// Used by the session PIN path, where the key came out of the PIN
    /// envelope instead of the password-derived KEK.
    pub fn unlock_with_key(&self, key: Key) -> Result<UnlockedVault> {
        let payload = self.envelope.open_payload(&key).map_err(|_| Error::InvalidPassword)?;
        let mut data: VaultData = serde_json::from_slice(&payload)
            .map_err(|e| Error::InvalidFormat(format!("could not parse the vault body: {e}")))?;
        if data.schema > crate::model::DATA_SCHEMA {
            return Err(Error::UnsupportedVersion {
                found: data.schema,
                supported: crate::model::DATA_SCHEMA,
            });
        }
        data.push_activity(ActivityKind::Unlocked, "Vault unlocked", None);

        Ok(UnlockedVault {
            file: self.clone(),
            key,
            data,
            dirty: true,
            session_started: Instant::now(),
            last_activity: Instant::now(),
        })
    }
}

/// Reject master passwords that should never be allowed.
pub fn validate_master_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_MASTER_PASSWORD_LEN {
        return Err(Error::WeakPassword(format!(
            "the master password must be at least {MIN_MASTER_PASSWORD_LEN} characters long"
        )));
    }
    const BANNED: [&str; 12] = [
        "password",
        "12345678",
        "qwertyui",
        "letmein1",
        "iloveyou",
        "admin123",
        "aurapass",
        "password1",
        "123456789",
        "1234567890",
        "trustno1",
        "changeme",
    ];
    let lower = password.to_lowercase();
    if BANNED.contains(&lower.as_str()) {
        return Err(Error::WeakPassword(
            "that master password appears on every cracking word list".into(),
        ));
    }
    Ok(())
}

/// How to sort the item list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    /// Alphabetical by title.
    #[default]
    Title,
    /// Most recently modified first.
    Updated,
    /// Most recently created first.
    Created,
    /// Most recently used first.
    LastUsed,
    /// Grouped by kind, then title.
    Kind,
}

impl SortOrder {
    /// Every order, for the UI's dropdown.
    pub const ALL: [SortOrder; 5] = [
        SortOrder::Title,
        SortOrder::Updated,
        SortOrder::Created,
        SortOrder::LastUsed,
        SortOrder::Kind,
    ];

    /// Display label.
    pub fn label(self) -> &'static str {
        match self {
            SortOrder::Title => "Title",
            SortOrder::Updated => "Last modified",
            SortOrder::Created => "Date created",
            SortOrder::LastUsed => "Last used",
            SortOrder::Kind => "Type",
        }
    }

    /// Parse the value stored in [`crate::model::VaultSettings::sort_order`].
    pub fn from_setting(s: &str) -> Self {
        match s {
            "updated" => SortOrder::Updated,
            "created" => SortOrder::Created,
            "last_used" => SortOrder::LastUsed,
            "kind" => SortOrder::Kind,
            _ => SortOrder::Title,
        }
    }

    /// Value to store back into the settings.
    pub fn as_setting(self) -> &'static str {
        match self {
            SortOrder::Title => "title",
            SortOrder::Updated => "updated",
            SortOrder::Created => "created",
            SortOrder::LastUsed => "last_used",
            SortOrder::Kind => "kind",
        }
    }
}

/// A saved search / filter over the item list.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VaultQuery {
    /// Free-text query matched against titles, usernames, URLs, tags, notes.
    pub text: String,
    /// Restrict to these kinds (empty means all).
    pub kinds: Vec<ItemKind>,
    /// Restrict to one category.
    pub category: Option<Uuid>,
    /// Restrict to items carrying all of these tags.
    pub tags: Vec<String>,
    /// Only favourites.
    pub favorites_only: bool,
    /// Include items in the bin.
    pub include_trashed: bool,
    /// Sort order.
    pub sort: SortOrder,
}

impl VaultQuery {
    /// Apply this query to a [`VaultData`], returning ids in display order.
    pub fn apply(&self, data: &VaultData) -> Vec<Uuid> {
        let mut items: Vec<&Item> = data
            .items
            .iter()
            .filter(|i| self.include_trashed || !i.trashed)
            .filter(|i| self.kinds.is_empty() || self.kinds.contains(&i.kind))
            .filter(|i| self.category.is_none_or(|c| i.category == Some(c)))
            .filter(|i| !self.favorites_only || i.favorite)
            .filter(|i| {
                self.tags.iter().all(|t| {
                    i.tags
                        .iter()
                        .any(|it| it.eq_ignore_ascii_case(t))
                })
            })
            .filter(|i| i.matches(&self.text))
            .collect();

        match self.sort {
            // Cache the lower-cased key once per item. The old comparator
            // allocated two strings per comparison, which made scrolling a
            // large vault needlessly expensive.
            SortOrder::Title => items.sort_by_cached_key(|i| i.title.to_lowercase()),
            SortOrder::Updated => items.sort_by(|a, b| b.updated_at.cmp(&a.updated_at)),
            SortOrder::Created => items.sort_by(|a, b| b.created_at.cmp(&a.created_at)),
            SortOrder::LastUsed => items.sort_by(|a, b| b.last_used_at.cmp(&a.last_used_at)),
            SortOrder::Kind => items.sort_by_cached_key(|i| {
                (i.kind.label(), i.title.to_lowercase())
            }),
        }
        // Favourites float to the top regardless of the chosen order.
        if !self.favorites_only && self.sort != SortOrder::LastUsed {
            items.sort_by_key(|i| !i.favorite);
        }
        items.into_iter().map(|i| i.id).collect()
    }
}

/// An unlocked vault: decrypted contents plus the key needed to re-seal them.
#[derive(Debug, Clone)]
pub struct UnlockedVault {
    file: VaultFile,
    key: Key,
    /// Decrypted contents.
    pub data: VaultData,
    dirty: bool,
    session_started: Instant,
    last_activity: Instant,
}

impl UnlockedVault {
    /// Path of the backing file.
    pub fn path(&self) -> Option<&Path> {
        self.file.path.as_deref()
    }

    /// Vault display name.
    pub fn name(&self) -> &str {
        &self.file.envelope.name
    }

    /// Rename the vault (does not touch the file name).
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.file.envelope.name = name.into();
        self.dirty = true;
    }

    /// Stable vault identifier.
    pub fn id(&self) -> Uuid {
        self.file.envelope.vault_id
    }

    /// Current revision number.
    pub fn revision(&self) -> u64 {
        self.file.envelope.revision
    }

    /// Wrap this vault's master key under a session PIN.
    ///
    /// The returned envelope belongs in the config file; the master password is
    /// never stored, only the key that the PIN unlocks.
    pub fn pin_envelope(&self, pin: &str, session: &str) -> Result<crate::pin::PinUnlock> {
        let path = self
            .path()
            .ok_or_else(|| Error::other("the vault has no file path"))?;
        crate::pin::PinUnlock::new(path, self.id().to_string(), &self.key, pin, session)
    }

    /// KDF parameters currently in force.
    pub fn kdf(&self) -> &KdfParams {
        &self.file.envelope.kdf
    }

    /// How long this session has been open.
    pub fn session_age(&self) -> Duration {
        self.session_started.elapsed()
    }

    /// Seconds since the last user interaction with the vault.
    pub fn idle_secs(&self) -> u64 {
        self.last_activity.elapsed().as_secs()
    }

    /// Whether the auto-lock timer has expired.
    pub fn should_auto_lock(&self) -> bool {
        let limit = self.data.settings.auto_lock_secs;
        limit > 0 && self.idle_secs() >= limit
    }

    /// Reset the idle timer. Call this whenever the user does something.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Whether there are unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the vault as modified without changing anything else.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// A read-only view of the locked file.
    pub fn file(&self) -> &VaultFile {
        &self.file
    }

    /// Read-only access to the decrypted vault body (items, categories, …).
    pub fn data(&self) -> &VaultData {
        &self.data
    }

    /// Mutable access to the vault body. Marks the vault dirty so the change
    /// is always written back on the next save.
    pub fn data_mut(&mut self) -> &mut VaultData {
        self.dirty = true;
        &mut self.data
    }

    /// The vault's settings.
    pub fn settings(&self) -> &crate::model::VaultSettings {
        &self.data.settings
    }

    /// Mutable settings; marks the vault dirty.
    pub fn settings_mut(&mut self) -> &mut crate::model::VaultSettings {
        self.dirty = true;
        &mut self.data.settings
    }

    /// Encrypt and write the vault back to disk.
    pub fn save(&mut self) -> Result<()> {
        let path = self
            .file
            .path
            .clone()
            .ok_or_else(|| Error::other("this vault has no file path yet"))?;
        self.save_to(&path)
    }

    /// Encrypt and write the vault to a specific path, adopting it.
    pub fn save_to(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref().to_path_buf();
        self.file.envelope.revision += 1;
        self.file.envelope.updated_at = Utc::now();
        self.data.schema = crate::model::DATA_SCHEMA;

        let payload = serde_json::to_vec(&self.data)?;
        self.file.envelope.seal_payload(&self.key, &payload)?;

        let body = serde_json::to_vec_pretty(&self.file.envelope)?;
        atomic_write(&path, &body, 0o600)?;

        self.file.path = Some(path);
        self.dirty = false;
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Write an encrypted backup to another location (the file is portable).
    pub fn export_backup(&mut self, path: impl AsRef<Path>) -> Result<()> {
        if self.dirty {
            self.save()?;
        }
        let src = self
            .file
            .path
            .clone()
            .ok_or_else(|| Error::other("this vault has no file path yet"))?;
        let bytes = std::fs::read(&src)?;
        atomic_write(path.as_ref(), &bytes, 0o600)?;
        self.data.push_activity(
            ActivityKind::Exported,
            "Encrypted backup written",
            Some(path.as_ref().display().to_string()),
        );
        self.dirty = true;
        Ok(())
    }

    /// Change the master password, optionally rotating the KDF parameters and
    /// key file.
    pub fn change_password(
        &mut self,
        current_password: &str,
        new_password: &str,
        new_keyfile: Option<&[u8]>,
        preset: Option<KdfPreset>,
    ) -> Result<()> {
        validate_master_password(new_password)?;
        if new_keyfile.is_none() && self.file.envelope.has_keyfile {
            return Err(Error::other(
                "this vault uses a key file; supply it to keep it enabled",
            ));
        }
        // Prove we know the current password before rewriting the wrap.
        let _ = self
            .file
            .unwrap_master_key(current_password, None)
            .or_else(|e| {
                // Allow the caller to pass the key file through the same
                // argument for the common "same key file" case.
                match new_keyfile {
                    Some(kf) => self.file.unwrap_master_key(current_password, Some(kf)),
                    None => Err(e),
                }
            })?;

        if let Some(p) = preset {
            self.file.envelope.kdf = KdfParams::with_preset(p);
        }
        // Re-wrap the same master key: no item has to be touched.
        self.file
            .envelope
            .wrap_master_key(&self.key, new_password, new_keyfile)?;
        self.file.envelope.revision += 1;
        self.file.envelope.updated_at = Utc::now();
        self.data.push_activity(
            ActivityKind::PasswordChanged,
            "Master password changed",
            Some(format!(
                "Argon2id {} MiB × {}",
                self.file.envelope.kdf.memory_kib / 1024,
                self.file.envelope.kdf.iterations
            )),
        );
        self.dirty = true;
        self.save()
    }

    /// Re-derive the KEK with a different cost preset, without changing the
    /// password (the password is needed to re-wrap the key).
    pub fn change_kdf(&mut self, password: &str, preset: KdfPreset) -> Result<()> {
        if self.file.envelope.has_keyfile {
            return Err(Error::other(
                "rotating KDF parameters of a key-file vault needs the key file",
            ));
        }
        // Prove the password before rewriting the wrap.
        let _ = self.file.unwrap_master_key(password, None)?;
        self.file.envelope.kdf = KdfParams::with_preset(preset);
        self.file
            .envelope
            .wrap_master_key(&self.key, password, None)?;
        self.file.envelope.revision += 1;
        self.file.envelope.updated_at = Utc::now();
        self.dirty = true;
        self.save()
    }

    /// Lock the vault, returning the (still encrypted) file handle. The key is
    /// zeroized when this value is dropped.
    pub fn lock(mut self) -> Result<VaultFile> {
        if self.dirty {
            self.save()?;
        }
        self.data.push_activity(ActivityKind::Locked, "Vault locked", None);
        Ok(self.file)
    }

    // ---------------------------------------------------------------- items

    /// Create a new item and return its id.
    pub fn create_item(&mut self, kind: ItemKind, title: impl Into<String>) -> Uuid {
        let item = Item::new(kind, title);
        let id = item.id;
        self.data.upsert(item);
        self.data
            .push_activity(ActivityKind::Created, format!("Created “{}”", self.title_of(id)), None);
        self.dirty = true;
        self.touch();
        id
    }

    /// Duplicate an item, giving the copy a new id and a " (copy)" suffix.
    pub fn duplicate_item(&mut self, id: Uuid) -> Result<Uuid> {
        let mut copy = self
            .data
            .get(id)
            .cloned()
            .ok_or_else(|| Error::ItemNotFound(id.to_string()))?;
        copy.id = Uuid::new_v4();
        copy.title = format!("{} (copy)", copy.title);
        copy.created_at = Utc::now();
        copy.updated_at = Utc::now();
        copy.password_history.clear();
        copy.attachments.iter_mut().for_each(|a| a.id = Uuid::new_v4());
        copy.fields.iter_mut().for_each(|f| f.id = Uuid::new_v4());
        let new_id = copy.id;
        self.data.upsert(copy);
        self.dirty = true;
        Ok(new_id)
    }

    /// Move an item to the bin.
    pub fn trash_item(&mut self, id: Uuid) -> Result<()> {
        let title = self.title_of(id);
        let item = self
            .data
            .get_mut(id)
            .ok_or_else(|| Error::ItemNotFound(id.to_string()))?;
        item.trashed = true;
        item.touch();
        self.data
            .push_activity(ActivityKind::Trashed, format!("Moved “{title}” to the bin"), None);
        self.dirty = true;
        Ok(())
    }

    /// Bring an item back from the bin.
    pub fn restore_item(&mut self, id: Uuid) -> Result<()> {
        let title = self.title_of(id);
        let item = self
            .data
            .get_mut(id)
            .ok_or_else(|| Error::ItemNotFound(id.to_string()))?;
        item.trashed = false;
        item.touch();
        self.data
            .push_activity(ActivityKind::Restored, format!("Restored “{title}”"), None);
        self.dirty = true;
        Ok(())
    }

    /// Delete an item for good.
    pub fn delete_item(&mut self, id: Uuid) -> Result<()> {
        let title = self.title_of(id);
        let before = self.data.items.len();
        self.data.items.retain(|i| i.id != id);
        if before == self.data.items.len() {
            return Err(Error::ItemNotFound(id.to_string()));
        }
        self.data
            .push_activity(ActivityKind::Deleted, format!("Deleted “{title}”"), None);
        self.dirty = true;
        Ok(())
    }

    /// Permanently remove everything in the bin. Returns how many were purged.
    pub fn empty_bin(&mut self) -> usize {
        let before = self.data.items.len();
        self.data.items.retain(|i| !i.trashed);
        let purged = before - self.data.items.len();
        if purged > 0 {
            self.data.push_activity(
                ActivityKind::Deleted,
                format!("Emptied the bin ({purged} entries)"),
                None,
            );
            self.dirty = true;
        }
        purged
    }

    /// Borrow an item.
    pub fn item(&self, id: Uuid) -> Option<&Item> {
        self.data.get(id)
    }

    /// Borrow an item mutably and mark the vault dirty.
    pub fn item_mut(&mut self, id: Uuid) -> Option<&mut Item> {
        self.dirty = true;
        self.touch();
        self.data.get_mut(id)
    }

    /// Title of an item, or a placeholder if it has gone.
    fn title_of(&self, id: Uuid) -> String {
        self.data
            .get(id)
            .map(|i| i.title.clone())
            .unwrap_or_else(|| id.to_string())
    }

    /// Record that an item was used (copied, autofilled…).
    pub fn note_usage(&mut self, id: Uuid) {
        if let Some(item) = self.data.get_mut(id) {
            item.mark_used();
            self.dirty = true;
        }
    }

    /// Find the best item for a URL, matching on host.
    ///
    /// Exact host wins; otherwise a registrable-domain match is used, so
    /// `login.example.com` still finds an entry for `example.com`.
    pub fn find_for_url(&self, url: &str) -> Vec<Uuid> {
        let Some(host) = crate::util::url_host(url) else {
            return Vec::new();
        };
        let base = registrable_domain(&host);
        let mut exact = Vec::new();
        let mut loose = Vec::new();
        for item in self.data.active() {
            for candidate in item.hosts() {
                if candidate == host {
                    exact.push(item.id);
                    break;
                }
                if !base.is_empty() && registrable_domain(&candidate) == base {
                    loose.push(item.id);
                    break;
                }
            }
        }
        exact.append(&mut loose);
        exact.dedup();
        exact
    }

    /// Run a filter over the vault.
    pub fn query(&self, query: &VaultQuery) -> Vec<Uuid> {
        query.apply(&self.data)
    }

    /// Import items, optionally filing them in a category.
    ///
    /// Records are matched by their export id when the format supplies one,
    /// otherwise by their full content.  A shared (title, username) is *not*
    /// treated as identity by default: Enpass exports contain hundreds of
    /// distinct entries whose visible title is just "Login".  `overwrite`
    /// additionally falls back to (title, username), which is the explicit
    /// "update my existing logins" mode.
    ///
    /// Returns `(added, updated, skipped)`.
    pub fn import_items(
        &mut self,
        items: Vec<Item>,
        category: Option<&str>,
        overwrite: bool,
    ) -> (usize, usize, usize) {
        let mut added = 0;
        let mut updated = 0;
        let mut skipped = 0;
        let category_id = category.map(|c| self.data.category_by_name_or_create(c));

        let mut by_external: HashMap<String, Uuid> = HashMap::new();
        let mut by_content: HashMap<String, Uuid> = HashMap::new();
        let mut by_name: HashMap<(String, String), Uuid> = HashMap::new();
        for item in self.data.active() {
            if let Some(external) = &item.external_id {
                by_external.entry(external.clone()).or_insert(item.id);
            }
            by_content
                .entry(import_fingerprint(item))
                .or_insert(item.id);
            by_name
                .entry((
                    item.title.trim().to_lowercase(),
                    item.username.as_deref().unwrap_or("").trim().to_lowercase(),
                ))
                .or_insert(item.id);
        }

        for mut incoming in items {
            if let Some(cat) = category_id {
                incoming.category = Some(cat);
            }
            let external = incoming
                .external_id
                .as_ref()
                .and_then(|id| by_external.get(id))
                .copied();
            let content = by_content
                .get(&import_fingerprint(&incoming))
                .copied();
            let existing = if overwrite {
                external
                    .or_else(|| {
                        by_name
                            .get(&(
                                incoming.title.trim().to_lowercase(),
                                incoming
                                    .username
                                    .as_deref()
                                    .unwrap_or("")
                                    .trim()
                                    .to_lowercase(),
                            ))
                            .copied()
                    })
                    .or(content)
            } else {
                external.or(content)
            };

            match existing {
                Some(id) if overwrite => {
                    if let Some(target) = self.data.get_mut(id) {
                        if let Some(pw) = incoming.password.clone() {
                            target.set_password(pw, PASSWORD_HISTORY_LIMIT);
                        }
                        for url in incoming.urls {
                            if !target.urls.contains(&url) {
                                target.urls.push(url);
                            }
                        }
                        if !incoming.notes.is_empty() && target.notes.is_empty() {
                            target.notes = incoming.notes;
                        }
                        if target.external_id.is_none() {
                            target.external_id = incoming.external_id.clone();
                        }
                        target.touch();
                    }
                    updated += 1;
                }
                Some(_) => skipped += 1,
                None => {
                    if let Some(external) = &incoming.external_id {
                        by_external.entry(external.clone()).or_insert(incoming.id);
                    }
                    self.data.upsert(incoming);
                    added += 1;
                }
            }
        }

        if added + updated > 0 {
            self.data.push_activity(
                ActivityKind::Imported,
                format!("Imported {added} entries"),
                Some(format!("{updated} updated, {skipped} skipped")),
            );
            self.dirty = true;
        }
        (added, updated, skipped)
    }

    // -------------------------------------------------------------- health

    /// Run the health audit.
    pub fn audit(
        &self,
        breaches: &HashMap<Uuid, u32>,
        options: &AuditOptions,
    ) -> AuditReport {
        audit::audit(&self.data, breaches, options, Utc::now())
    }

    /// Passwords to check against the breach corpus, deduplicated.
    pub fn passwords_for_breach_check(&self) -> Vec<(Uuid, String)> {
        let mut seen = std::collections::HashSet::new();
        self.data
            .active()
            .filter_map(|i| {
                let p = i.password()?;
                if seen.insert(p.to_string()) {
                    Some((i.id, p.to_string()))
                } else {
                    // Still report the item id so the audit can flag it, but
                    // without adding a second lookup for the same password.
                    None
                }
            })
            .collect()
    }

    /// Items sharing a password, used to propagate breach results to all of
    /// them after a deduplicated check.
    pub fn items_sharing_passwords(&self) -> HashMap<String, Vec<Uuid>> {
        let mut map: HashMap<String, Vec<Uuid>> = HashMap::new();
        for item in self.data.active() {
            if let Some(p) = item.password() {
                map.entry(p.to_string()).or_default().push(item.id);
            }
        }
        map
    }

    /// Simple counters for the sidebar/status bar.
    pub fn stats(&self) -> VaultStats {
        let active: Vec<&Item> = self.data.active().collect();
        VaultStats {
            items: active.len(),
            favorites: active.iter().filter(|i| i.favorite).count(),
            trashed: self.data.trashed().count(),
            with_totp: active.iter().filter(|i| i.totp.is_some()).count(),
            categories: self.data.categories.len(),
            tags: self.data.all_tags().len(),
        }
    }
}

/// Aggregate numbers shown in the status bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VaultStats {
    /// Active items.
    pub items: usize,
    /// Favourited items.
    pub favorites: usize,
    /// Items in the bin.
    pub trashed: usize,
    /// Items with a TOTP secret.
    pub with_totp: usize,
    /// Number of categories.
    pub categories: usize,
    /// Number of distinct tags.
    pub tags: usize,
}

/// Best-effort registrable domain (eTLD+1) without a public-suffix list.
///
/// Handles the common shape `sub.example.co.uk` → `example.co.uk` by treating a
/// two-letter final label as a country code and keeping one more label. It is
/// deliberately conservative: a wrong answer only means a URL match is slightly
/// looser or tighter, never a security decision.
pub fn registrable_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    match labels.len() {
        0 => String::new(),
        1 | 2 => labels.join("."),
        n => {
            let tld = labels[n - 1];
            let second = labels[n - 2];
            // "co.uk", "com.au", "org.nz" …
            let is_cc_two_level = tld.len() == 2
                && matches!(
                    second,
                    "co" | "com" | "org" | "net" | "gov" | "edu" | "ac" | "or" | "ne" | "go"
                );
            if is_cc_two_level && n >= 3 {
                labels[n - 3..].join(".")
            } else {
                labels[n - 2..].join(".")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfPreset;

    /// Vaults used in tests use the cheapest preset so the suite stays fast.
    fn fast_preset() -> KdfPreset {
        KdfPreset::Interactive
    }

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn create_vault(dir: &tempfile::TempDir) -> UnlockedVault {
        let path = dir.path().join("v.aurapass");
        VaultFile::create(&path, "correct horse battery", "Test Vault", fast_preset(), None).unwrap()
    }

    #[test]
    fn create_unlock_roundtrip() {
        let dir = tmpdir();
        let path = dir.path().join("v.aurapass");
        {
            let mut vault = VaultFile::create(
                &path,
                "correct horse battery",
                "Personal",
                fast_preset(),
                None,
            )
            .unwrap();
            let id = vault.create_item(ItemKind::Login, "GitHub");
            vault.item_mut(id).unwrap().password = Some("hunter2hunter2".into());
            vault.save().unwrap();
        }

        let file = VaultFile::load(&path).unwrap();
        assert_eq!(file.info().name, "Personal");
        assert!(file.verify_password("correct horse battery", None).unwrap());
        assert!(!file.verify_password("wrong password", None).unwrap());

        let vault = file.unlock("correct horse battery", None).unwrap();
        assert_eq!(vault.stats().items, 1);
        assert_eq!(
            vault
                .data
                .items
                .iter()
                .find(|i| i.title == "GitHub")
                .unwrap()
                .password(),
            Some("hunter2hunter2")
        );
    }

    #[test]
    fn wrong_password_is_rejected_with_a_clean_error() {
        let dir = tmpdir();
        let vault = create_vault(&dir);
        let file = vault.lock().unwrap();
        assert!(matches!(
            file.unlock("nope-nope-nope", None),
            Err(Error::InvalidPassword)
        ));
    }

    #[test]
    fn short_master_passwords_are_refused() {
        assert!(matches!(
            validate_master_password("short"),
            Err(Error::WeakPassword(_))
        ));
        assert!(validate_master_password("long enough password").is_ok());
        assert!(validate_master_password("password").is_err());
    }

    #[test]
    fn tampering_with_the_header_is_detected() {
        let dir = tmpdir();
        let path = dir.path().join("v.aurapass");
        let vault = create_vault(&dir);
        vault.lock().unwrap();

        // Downgrade the KDF cost in the header.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["kdf"]["memory_kib"] = serde_json::json!(8);
        std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        let file = VaultFile::load(&path).unwrap();
        assert!(matches!(
            file.unlock("correct horse battery", None),
            Err(Error::InvalidPassword)
        ));
    }

    #[test]
    fn tampering_with_the_body_is_detected() {
        let dir = tmpdir();
        let path = dir.path().join("v.aurapass");
        let vault = create_vault(&dir);
        vault.lock().unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let ct = json["data"]["ct"].as_str().unwrap().to_string();
        let mut bytes = crate::util::b64_decode(&ct).unwrap();
        bytes[10] ^= 0xff;
        json["data"]["ct"] = serde_json::json!(crate::util::b64_encode(&bytes));
        std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        let file = VaultFile::load(&path).unwrap();
        assert!(matches!(
            file.unlock("correct horse battery", None),
            Err(Error::InvalidPassword)
        ));
    }

    #[test]
    fn keyfile_vaults_need_the_keyfile() {
        let dir = tmpdir();
        let path = dir.path().join("v.aurapass");
        VaultFile::create(
            &path,
            "correct horse battery",
            "With key file",
            fast_preset(),
            Some(b"this is my key file"),
        )
        .unwrap()
        .lock()
        .unwrap();

        let file = VaultFile::load(&path).unwrap();
        assert!(file.info().has_keyfile);
        assert!(file.unlock("correct horse battery", Some(b"this is my key file")).is_ok());
        assert!(file.unlock("correct horse battery", None).is_err());
        assert!(file.unlock("correct horse battery", Some(b"wrong")).is_err());
    }

    #[test]
    fn changing_the_password_keeps_the_items() {
        let dir = tmpdir();
        let mut vault = create_vault(&dir);
        let id = vault.create_item(ItemKind::Login, "Bank");
        vault.item_mut(id).unwrap().password = Some("s3cret-value-here".into());
        vault.save().unwrap();

        vault
            .change_password("correct horse battery", "a brand new password", None, Some(KdfPreset::Moderate))
            .unwrap();

        let path = vault.path().unwrap().to_path_buf();
        let file = VaultFile::load(&path).unwrap();
        assert!(file.unlock("correct horse battery", None).is_err());
        let reopened = file.unlock("a brand new password", None).unwrap();
        assert_eq!(
            reopened.item(id).unwrap().password(),
            Some("s3cret-value-here")
        );
        assert_eq!(reopened.kdf().preset(), Some(KdfPreset::Moderate));
    }

    #[test]
    fn rollback_to_an_older_body_is_detected() {
        let dir = tmpdir();
        let path = dir.path().join("v.aurapass");
        let mut vault = create_vault(&dir);
        vault.save().unwrap();

        // Capture an old body, then change the vault so the revision moves on.
        let old: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let old_data = old["data"].clone();
        let id = vault.create_item(ItemKind::Login, "Second item");
        vault.save().unwrap();

        // Splice the old body back in: same header, older payload.
        let mut now: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        now["data"] = old_data;
        std::fs::write(&path, serde_json::to_string_pretty(&now).unwrap()).unwrap();

        let file = VaultFile::load(&path).unwrap();
        assert!(
            file.unlock("correct horse battery", None).is_err(),
            "a rolled-back body must not verify"
        );
        let _ = id;
    }

    #[test]
    fn save_is_atomic_and_keeps_a_single_file() {
        let dir = tmpdir();
        let mut vault = create_vault(&dir);
        let path = vault.path().unwrap().to_path_buf();
        for i in 0..5 {
            vault.create_item(ItemKind::Login, format!("item {i}"));
            vault.save().unwrap();
        }
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec!["v.aurapass".to_string()], "no temp files left behind");
        assert!(VaultFile::load(&path).unwrap().info().revision >= 5);
    }

    #[test]
    fn query_filters_and_sorts() {
        let dir = tmpdir();
        let mut vault = create_vault(&dir);
        let a = vault.create_item(ItemKind::Login, "Zeta");
        let b = vault.create_item(ItemKind::SecureNote, "Alpha");
        vault.item_mut(a).unwrap().urls.push("https://zeta.example".into());
        vault.item_mut(a).unwrap().favorite = true;
        vault.item_mut(b).unwrap().tags.push("work".into());

        let by_title = vault.query(&VaultQuery {
            sort: SortOrder::Title,
            ..Default::default()
        });
        // Favourites first, then alphabetical.
        assert_eq!(by_title, vec![a, b]);

        let notes = vault.query(&VaultQuery {
            kinds: vec![ItemKind::SecureNote],
            ..Default::default()
        });
        assert_eq!(notes, vec![b]);

        let tagged = vault.query(&VaultQuery {
            tags: vec!["WORK".into()],
            ..Default::default()
        });
        assert_eq!(tagged, vec![b]);

        let found = vault.query(&VaultQuery {
            text: "zeta".into(),
            ..Default::default()
        });
        assert_eq!(found, vec![a]);
    }

    #[test]
    fn url_matching_prefers_exact_hosts() {
        let dir = tmpdir();
        let mut vault = create_vault(&dir);
        let exact = vault.create_item(ItemKind::Login, "Login");
        vault.item_mut(exact).unwrap().urls = vec!["https://login.example.com".into()];
        let base = vault.create_item(ItemKind::Login, "Example");
        vault.item_mut(base).unwrap().urls = vec!["https://example.com".into()];
        let other = vault.create_item(ItemKind::Login, "Other");
        vault.item_mut(other).unwrap().urls = vec!["https://unrelated.test".into()];

        let hits = vault.find_for_url("https://login.example.com/auth");
        assert_eq!(hits.first(), Some(&exact));
        assert!(hits.contains(&base));
        assert!(!hits.contains(&other));

        assert!(vault.find_for_url("not a url").is_empty());
    }

    #[test]
    fn bin_lifecycle() {
        let dir = tmpdir();
        let mut vault = create_vault(&dir);
        let id = vault.create_item(ItemKind::Login, "Temp");
        vault.trash_item(id).unwrap();
        assert_eq!(vault.stats().trashed, 1);
        assert_eq!(vault.stats().items, 0);
        vault.restore_item(id).unwrap();
        assert_eq!(vault.stats().items, 1);
        vault.trash_item(id).unwrap();
        assert_eq!(vault.empty_bin(), 1);
        assert!(vault.item(id).is_none());
    }

    #[test]
    fn import_merges_and_skips() {
        let dir = tmpdir();
        let mut vault = create_vault(&dir);
        let mut existing = Item::new(ItemKind::Login, "GitHub");
        existing.username = Some("alice".into());
        existing.password = Some("old-password-value".into());
        vault.data.upsert(existing);

        let mut incoming = Item::new(ItemKind::Login, "GitHub");
        incoming.username = Some("ALICE".into());
        incoming.password = Some("new-password-value".into());
        let mut fresh = Item::new(ItemKind::Login, "GitLab");
        fresh.password = Some("another-password".into());

        // A different password makes this a distinct record, even though the
        // title and username match: importers must not collapse entries.
        let (added, updated, skipped) =
            vault.import_items(vec![incoming, fresh], Some("Imported"), false);
        assert_eq!((added, updated, skipped), (2, 0, 0));

        let (added2, updated2, _) = vault.import_items(
            vec![{
                let mut i = Item::new(ItemKind::Login, "GitHub");
                i.username = Some("alice".into());
                i.password = Some("replaced-password".into());
                i
            }],
            None,
            true,
        );
        assert_eq!((added2, updated2), (0, 1));
        let gh = vault
            .data
            .items
            .iter()
            .find(|i| i.title == "GitHub" && i.password() == Some("replaced-password"))
            .unwrap();
        assert_eq!(gh.password_history[0].password, "old-password-value");
    }

    #[test]
    fn reimport_matches_record_ids_and_content() {
        let dir = tmpdir();
        let mut vault = create_vault(&dir);

        let mut first = Item::new(ItemKind::Login, "Login");
        first.username = Some("alice".into());
        first.password = Some("one".into());
        first.external_id = Some("enpass-1".into());
        let mut second = Item::new(ItemKind::Login, "Login");
        second.username = Some("alice".into());
        second.password = Some("two".into());
        second.external_id = Some("enpass-2".into());

        assert_eq!(vault.import_items(vec![first, second], None, false).0, 2);

        let mut again = Item::new(ItemKind::Login, "Login");
        again.username = Some("alice".into());
        again.password = Some("one".into());
        again.external_id = Some("enpass-1".into());
        let mut changed = Item::new(ItemKind::Login, "Login");
        changed.username = Some("alice".into());
        changed.password = Some("two-changed".into());
        changed.external_id = Some("enpass-2".into());
        // The same content without an id is recognised too.
        let mut plain = Item::new(ItemKind::Login, "Plain");
        plain.password = Some("three".into());
        assert_eq!(vault.import_items(vec![plain.clone()], None, false).0, 1);
        assert_eq!(vault.import_items(vec![plain], None, false).0, 0);

        let (added, _, skipped) = vault.import_items(vec![again, changed], None, false);
        assert_eq!((added, skipped), (0, 2));
    }

    #[test]
    fn registrable_domain_handles_common_shapes() {
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("login.example.com"), "example.com");
        assert_eq!(registrable_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("localhost"), "localhost");
    }

    #[test]
    fn wrong_format_is_rejected() {
        let dir = tmpdir();
        let path = dir.path().join("not-a-vault.json");
        std::fs::write(&path, r#"{"format":"something-else","version":2}"#).unwrap();
        assert!(matches!(
            VaultFile::load(&path),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn future_versions_are_refused() {
        let dir = tmpdir();
        let path = dir.path().join("v.aurapass");
        let vault = create_vault(&dir);
        vault.lock().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["version"] = serde_json::json!(9999);
        std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
        assert!(matches!(
            VaultFile::load(&path),
            Err(Error::UnsupportedVersion { found: 9999, .. })
        ));
    }

    #[test]
    fn vault_file_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tmpdir();
        let vault = create_vault(&dir);
        let path = vault.path().unwrap().to_path_buf();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vault must not be group/world readable");
    }
}
