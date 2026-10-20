//! AuraPass core library.
//!
//! This crate is deliberately UI-agnostic: the desktop GUI, the CLI and the
//! browser bridge are all thin shells over the types defined here.
//!
//! # Vault format
//!
//! An `aurapass` vault is a single file with a plaintext, authenticated header
//! and an encrypted body:
//!
//! ```text
//! {
//!   "format": "aurapass-vault",
//!   "version": 2,
//!   "vault_id": "…uuid…",
//!   "kdf":       { "algo": "argon2id", "salt": "…", "memory_kib": 65536, … },
//!   "key_wrap":  { "nonce": "…", "ct": "…" },   // master key, wrapped by the KEK
//!   "data":      { "nonce": "…", "ct": "…" },   // the vault itself
//!   "created_at": "…", "updated_at": "…", "revision": 3
//! }
//! ```
//!
//! * The **master key** is 32 random bytes generated at vault creation. It is
//!   what actually encrypts the vault, so changing the password only re-wraps
//!   the master key instead of re-encrypting the whole database.
//! * The **KEK** (key-encryption key) is derived from the user's password with
//!   Argon2id. Optionally a key file is mixed in with HKDF.
//! * Both wraps use XChaCha20-Poly1305 with the canonical header as associated
//!   data, which authenticates the KDF parameters and stops an attacker from
//!   silently downgrading them.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod audit;
pub mod autostart;
#[cfg(feature = "breach")]
pub mod breach;
pub mod config;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod importers;
pub mod ipc;
pub mod model;
pub mod pin;
pub mod strength;
pub mod totp;
pub mod util;
pub mod vault;
pub mod wordlist;

pub use error::{Error, Result};
pub use model::{
    Attachment, Category, Field, Item, ItemKind, PasswordHistoryEntry, VaultData, VaultSettings,
};
pub use vault::{Envelope, UnlockedVault, VaultFile};

/// Human-readable name of the product.
pub const APP_NAME: &str = "AuraPass";
/// Machine-readable identifier, used for directories, D-Bus names and packages.
pub const APP_ID: &str = "aurapass";
/// Version reported to the browser extension and in the UI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Current on-disk vault format version.
pub const VAULT_FORMAT_VERSION: u32 = 2;
/// Default TCP port of the browser bridge. The bridge picks a free port when
/// this one is taken.
pub const DEFAULT_BRIDGE_PORT: u16 = 8974;

/// Seconds since the Unix epoch, or `0` if the system clock is before 1970.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Current wall-clock time in UTC.
pub fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}
