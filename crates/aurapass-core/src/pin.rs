//! Session PIN unlock.
//!
//! Typing a long master password every time the vault locks is the main
//! friction of a local password manager. AuraPass therefore lets the user pick
//! a numeric PIN when a vault is created: the vault's master key is wrapped a
//! second time under a PIN-derived KEK and kept in the (owner-only) config
//! file.
//!
//! The PIN is deliberately scoped to **the current desktop login session**:
//!
//! * [`session_fingerprint`] hashes the kernel boot id, the user id and the
//!   logind session id;
//! * the PIN envelope records that fingerprint and is only offered while it
//!   matches;
//! * unlocking with the master password refreshes the fingerprint, so a PIN
//!   survives locking and unlocking the app, but not a reboot or a logout.
//!
//! This is a convenience trade-off, not a replacement for the master password.
//! A PIN has far less entropy than a passphrase, so the envelope is protected
//! with a deliberately slow Argon2id derivation and permanent lock-out after
//! [`MAX_PIN_ATTEMPTS`] failures. Anyone who can read the config file can still
//! attack the PIN offline; the master password remains the real secret.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::{KdfParams, KdfPreset, Key, Sealed, derive_kek, sha256};
use crate::error::{Error, Result};
use crate::util::hex_encode;

/// Shortest accepted PIN.
pub const PIN_MIN_LEN: usize = 4;
/// Longest accepted PIN.
pub const PIN_MAX_LEN: usize = 12;
/// How many wrong PINs are tolerated before the master password is required.
pub const MAX_PIN_ATTEMPTS: u32 = 5;

/// A master key wrapped by a PIN, valid for one desktop session.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PinUnlock {
    /// The vault this envelope belongs to.
    pub vault: PathBuf,
    /// The vault's stable id, checked after unwrapping.
    pub vault_id: String,
    /// Argon2id parameters and salt for the PIN.
    pub kdf: KdfParams,
    /// The master key, sealed under the PIN-derived KEK.
    pub key: Sealed,
    /// Fingerprint of the desktop session this PIN was issued for.
    #[serde(default)]
    pub session: String,
    /// Wrong PINs entered in this session.
    #[serde(default)]
    pub failures: u32,
    /// When the PIN was set.
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
}

impl PinUnlock {
    /// Wrap `key` under `pin` for the given desktop session.
    pub fn new(
        vault: impl Into<PathBuf>,
        vault_id: impl Into<String>,
        key: &Key,
        pin: &str,
        session: &str,
    ) -> Result<Self> {
        validate_pin(pin)?;
        let vault = vault.into();
        let vault_id = vault_id.into();
        // A PIN is short, so pay for a heavier derivation than a vault unlock:
        // Moderate is roughly a quarter of a second on a laptop.
        let kdf = KdfParams::with_preset(KdfPreset::Moderate);
        let kek = derive_kek(pin, None, &kdf)?;
        let sealed = Sealed::seal(&kek, &aad(&vault, &vault_id), key.as_bytes())?;
        Ok(Self {
            vault,
            vault_id,
            kdf,
            key: sealed,
            session: session.to_string(),
            failures: 0,
            created_at: Some(Utc::now()),
        })
    }

    /// Unwrap the master key. Wrong PINs and damaged envelopes look the same.
    pub fn unwrap_key(&self, pin: &str) -> Result<Key> {
        let kek = derive_kek(pin, None, &self.kdf)?;
        let bytes = self
            .key
            .open(&kek, &aad(&self.vault, &self.vault_id))
            .map_err(|_| Error::InvalidPassword)?;
        let key = Key::from_slice(&bytes);
        // `bytes` lives until here; overwrite it before returning.
        let mut bytes = bytes;
        bytes.fill(0);
        key
    }

    /// Whether this PIN may be offered in `session`.
    pub fn is_live(&self, session: &str) -> bool {
        !session.is_empty() && self.session == session && self.failures < MAX_PIN_ATTEMPTS
    }

    /// Re-bind the PIN to the current session (after a master unlock) and
    /// forgive earlier mistypes.
    pub fn refresh_session(&mut self, session: &str) {
        self.session = session.to_string();
        self.failures = 0;
    }

    /// Note a wrong PIN. Returns true when the PIN is now exhausted.
    pub fn record_failure(&mut self) -> bool {
        self.failures = self.failures.saturating_add(1);
        self.failures >= MAX_PIN_ATTEMPTS
    }
}

/// AAD binding the envelope to one vault, so it cannot be moved between files.
fn aad(vault: &Path, vault_id: &str) -> Vec<u8> {
    format!(
        "aurapass/pin-v1|{}|{}",
        vault.to_string_lossy(),
        vault_id
    )
    .into_bytes()
}

/// Reject PINs that are not digits, too short, too long, or trivially guessable.
pub fn validate_pin(pin: &str) -> Result<()> {
    if !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::WeakPassword(
            "the unlock PIN must contain digits only".into(),
        ));
    }
    if !(PIN_MIN_LEN..=PIN_MAX_LEN).contains(&pin.len()) {
        return Err(Error::WeakPassword(format!(
            "the unlock PIN must be {PIN_MIN_LEN} to {PIN_MAX_LEN} digits long"
        )));
    }
    if pin.chars().all(|c| c == pin.chars().next().unwrap_or('0')) {
        return Err(Error::WeakPassword(
            "that PIN repeats the same digit; pick something less obvious".into(),
        ));
    }
    Ok(())
}

/// Fingerprint of the current desktop login session.
///
/// A new boot id or a new logind session changes the hash, which retires every
/// stored PIN until the master password is entered again.
pub fn session_fingerprint() -> String {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default()
        .trim()
        .to_string();
    let session = std::env::var("XDG_SESSION_ID").unwrap_or_default();
    #[cfg(unix)]
    let uid = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(0)
    };
    #[cfg(not(unix))]
    let uid = 0u32;
    let mut material = format!("{boot}|{uid}|{session}");
    // If /proc is not mounted there is no trustworthy session boundary; mixing
    // in the DISPLAY keeps the value from being a constant on such systems.
    if boot.is_empty() {
        material.push('|');
        material.push_str(&std::env::var("DISPLAY").unwrap_or_default());
    }
    hex_encode(sha256(material.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::from_slice(&[7u8; 32]).unwrap()
    }

    #[test]
    fn pin_roundtrip() {
        let pin = PinUnlock::new(
            "/tmp/example.aurapass",
            "6f1c1d1e-0000-0000-0000-000000000000",
            &key(),
            "482913",
            "session-a",
        )
        .unwrap();
        assert!(pin.is_live("session-a"));
        assert!(!pin.is_live("session-b"));
        let unwrapped = pin.unwrap_key("482913").unwrap();
        assert_eq!(unwrapped, key());
        assert!(pin.unwrap_key("000000").is_err());
    }

    #[test]
    fn pin_is_bound_to_its_vault() {
        let pin = PinUnlock::new(
            "/tmp/example.aurapass",
            "id",
            &key(),
            "482913",
            "session",
        )
        .unwrap();
        let mut other = pin.clone();
        other.vault = "/tmp/other.aurapass".into();
        assert!(other.unwrap_key("482913").is_err());
    }

    #[test]
    fn tries_are_limited() {
        let mut pin = PinUnlock::new("/tmp/a.aurapass", "id", &key(), "482913", "s").unwrap();
        for _ in 0..MAX_PIN_ATTEMPTS - 1 {
            assert!(!pin.record_failure());
        }
        assert!(pin.record_failure());
        assert!(!pin.is_live("s"));
        pin.refresh_session("s");
        assert!(pin.is_live("s"));
        assert_eq!(pin.failures, 0);
    }

    #[test]
    fn pin_opens_a_real_vault() {
        use crate::crypto::KdfPreset;
        use crate::vault::VaultFile;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.aurapass");
        let vault = VaultFile::create(
            &path,
            "correct horse battery staple",
            "Test",
            KdfPreset::Interactive,
            None,
        )
        .unwrap();
        let envelope = vault.pin_envelope("482913", "session-a").unwrap();
        let key = envelope.unwrap_key("482913").unwrap();
        drop(vault);

        let reopened = VaultFile::load(&path)
            .unwrap()
            .unlock_with_key(key)
            .unwrap();
        assert_eq!(reopened.name(), "Test");
        assert_eq!(reopened.id().to_string(), envelope.vault_id);
    }

    #[test]
    fn rejects_bad_pins() {
        assert!(validate_pin("123").is_err());
        assert!(validate_pin("1234567890123").is_err());
        assert!(validate_pin("12a456").is_err());
        assert!(validate_pin("0000").is_err());
        assert!(validate_pin("482913").is_ok());
    }
}
