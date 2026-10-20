//! Error type shared by every AuraPass component.

use thiserror::Error;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while handling a vault.
#[derive(Debug, Error)]
pub enum Error {
    /// An operation needed the vault contents but the vault is locked.
    #[error("the vault is locked")]
    Locked,

    /// The master key could not be unwrapped: wrong password or key file, or a
    /// damaged header.
    #[error("wrong password or key file")]
    InvalidPassword,

    /// An authenticated-decryption step failed.
    #[error("authentication failed: the data was modified, truncated or corrupted")]
    AeadFailed,

    /// The file is not an AuraPass vault, or its header is malformed.
    #[error("not a valid AuraPass vault: {0}")]
    InvalidFormat(String),

    /// The vault was written by a newer AuraPass.
    #[error("vault format version {found} is newer than the supported version {supported}")]
    UnsupportedVersion {
        /// Version found in the file.
        found: u32,
        /// Newest version this build understands.
        supported: u32,
    },

    /// No item matched the given id.
    #[error("no item with id {0}")]
    ItemNotFound(String),

    /// No category matched the given id.
    #[error("no category with id {0}")]
    CategoryNotFound(String),

    /// Bad parameters, malformed base64, wrong key length, …
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// A password policy was impossible to satisfy.
    #[error("password policy is impossible: {0}")]
    ImpossiblePolicy(String),

    /// A password or key file was rejected by policy (too short, weak, …).
    #[error("{0}")]
    WeakPassword(String),

    /// Restoring/importing produced data that cannot be represented.
    #[error("import failed: {0}")]
    Import(String),

    /// Export/backup failures.
    #[error("export failed: {0}")]
    Export(String),

    /// Data that must be valid TOTP material was not.
    #[error("invalid TOTP data: {0}")]
    Totp(String),

    /// Filesystem problem.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON problem.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Any other self-describing failure.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Build an [`Error::Other`] from anything printable.
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }

    /// Build an [`Error::Crypto`] from anything printable.
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }
}
