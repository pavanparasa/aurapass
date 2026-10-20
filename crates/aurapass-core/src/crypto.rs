//! The cryptographic heart of AuraPass.
//!
//! * Password → **KEK** via Argon2id (optionally salted with a key file).
//! * KEK wraps a random 32-byte **master key** with XChaCha20-Poly1305.
//! * The master key encrypts the vault body with XChaCha20-Poly1305.
//!
//! Every key lives in a [`Key`], which zeroizes itself on drop and never
//! implements `Display`.

use crate::error::{Error, Result};
use crate::util::{b64_decode, b64_encode};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use std::fmt;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize;

/// Length of a symmetric key, in bytes.
pub const KEY_LEN: usize = 32;
/// Length of an XChaCha20 nonce, in bytes.
pub const NONCE_LEN: usize = 24;
/// Length of a KDF salt, in bytes.
pub const SALT_LEN: usize = 16;
/// Length of a Poly1305 authentication tag, in bytes.
pub const TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// Fill a fixed-size buffer with cryptographically secure random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("the OS random number generator must be available");
    buf
}

/// Fill a fresh `Vec` with cryptographically secure random bytes.
pub fn random_vec(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    getrandom::fill(&mut v).expect("the OS random number generator must be available");
    v
}

/// SHA-256 of `data`.
pub fn sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data.as_ref());
    h.finalize().into()
}

/// SHA-1 of `data`. Only used for the Have I Been Pwned k-anonymity protocol,
/// which is defined in terms of SHA-1 prefixes.
pub fn sha1(data: impl AsRef<[u8]>) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data.as_ref());
    h.finalize().into()
}

/// HMAC-SHA-256.
pub fn hmac_sha256(key: &[u8], data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data.as_ref());
    mac.finalize().into_bytes().into()
}

/// Constant-time equality for secrets.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// A 32-byte symmetric key that zeroizes itself on drop.
#[derive(Clone)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Generate a fresh random key.
    pub fn generate() -> Self {
        Self(random_bytes())
    }

    /// Wrap existing bytes, rejecting anything that is not [`KEY_LEN`] long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_LEN {
            return Err(Error::crypto(format!(
                "expected a {KEY_LEN}-byte key, got {}",
                bytes.len()
            )));
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(bytes);
        Ok(Self(k))
    }

    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Domain-separated sub-key via HKDF-SHA256.
    ///
    /// Used so that the master key never encrypts two different things with the
    /// same key material (e.g. vault body vs. bridge session keys).
    pub fn subkey(&self, info: &[u8], salt: &[u8]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut okm = [0u8; KEY_LEN];
        hk.expand(info, &mut okm)
            .map_err(|e| Error::crypto(format!("hkdf expand failed: {e}")))?;
        let key = Self(okm);
        okm.zeroize();
        Ok(key)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for Key {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}
impl Eq for Key {}

/// Supported key-derivation functions. Only Argon2id is offered: the other
/// Argon2 variants are strictly worse for password hashing, and PBKDF2 is only
/// supported on the *import* side.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlgo {
    /// Argon2id version 0x13 (the RFC 9106 recommendation).
    #[default]
    #[serde(rename = "argon2id")]
    Argon2id,
}

/// Supported AEAD ciphers.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AeadAlgo {
    /// XChaCha20-Poly1305 (192-bit nonces — safe with random nonces).
    #[default]
    #[serde(rename = "xchacha20poly1305")]
    XChaCha20Poly1305,
}

/// User-selectable Argon2id cost presets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KdfPreset {
    /// ~0.1 s on a modern laptop. Good default for interactive unlock.
    #[default]
    Interactive,
    /// ~0.5 s. Noticeably more expensive for an attacker.
    Moderate,
    /// ~2 s. For high-value vaults and patient users.
    Paranoid,
}

impl KdfPreset {
    /// All presets, cheapest first.
    pub const ALL: [KdfPreset; 3] = [
        KdfPreset::Interactive,
        KdfPreset::Moderate,
        KdfPreset::Paranoid,
    ];

    /// Short human label.
    pub fn label(self) -> &'static str {
        match self {
            KdfPreset::Interactive => "Interactive (fast)",
            KdfPreset::Moderate => "Moderate",
            KdfPreset::Paranoid => "Paranoid (slow)",
        }
    }

    /// Longer explanation shown in the UI.
    pub fn description(self) -> &'static str {
        match self {
            KdfPreset::Interactive => "64 MiB / 3 passes — unlocks in a blink.",
            KdfPreset::Moderate => "256 MiB / 4 passes — half a second of work.",
            KdfPreset::Paranoid => "1 GiB / 8 passes — several seconds, hardest to crack.",
        }
    }
}

/// Argon2id parameters, stored in the vault header.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Which KDF to use.
    #[serde(default)]
    pub algo: KdfAlgo,
    /// Random salt, base64.
    pub salt: String,
    /// Memory cost in kibibytes.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
    /// Derived key length in bytes.
    #[serde(default = "default_key_len")]
    pub key_len: u32,
}

fn default_key_len() -> u32 {
    KEY_LEN as u32
}

impl KdfParams {
    /// Fresh parameters for the given preset, with a new random salt.
    pub fn with_preset(preset: KdfPreset) -> Self {
        let (memory_kib, iterations, parallelism) = match preset {
            KdfPreset::Interactive => (64 * 1024, 3, 1),
            KdfPreset::Moderate => (256 * 1024, 4, 2),
            KdfPreset::Paranoid => (1024 * 1024, 8, 4),
        };
        Self {
            algo: KdfAlgo::Argon2id,
            salt: b64_encode(random_bytes::<SALT_LEN>()),
            memory_kib,
            iterations,
            parallelism,
            key_len: KEY_LEN as u32,
        }
    }

    /// Approximate work factor, in MiB × passes. Used to compare vaults.
    pub fn work_factor(&self) -> u64 {
        (self.memory_kib as u64).saturating_mul(self.iterations as u64) / 1024
    }

    /// Best-effort mapping back onto a preset (for UI display).
    pub fn preset(&self) -> Option<KdfPreset> {
        KdfPreset::ALL.into_iter().find(|p| {
            let candidate = KdfParams {
                salt: String::new(),
                ..KdfParams::with_preset(*p)
            };
            candidate.memory_kib == self.memory_kib
                && candidate.iterations == self.iterations
                && candidate.parallelism == self.parallelism
        })
    }
}

/// Derive the key-encryption key from a password and optional key file.
///
/// When a key file is supplied its SHA-256 is concatenated with the Argon2id
/// output and the pair is run through HKDF-SHA256, so the file acts as a second
/// factor without weakening the password path.
pub fn derive_kek(password: &str, keyfile: Option<&[u8]>, params: &KdfParams) -> Result<Key> {
    let salt = b64_decode(&params.salt)?;
    if salt.len() < 8 {
        return Err(Error::crypto("KDF salt is too short"));
    }
    let out_len = params.key_len.max(16) as usize;
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(out_len),
        )
        .map_err(|e| Error::crypto(format!("invalid Argon2 parameters: {e}")))?,
    );

    let mut derived = vec![0u8; out_len];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut derived)
        .map_err(|e| Error::crypto(format!("Argon2 failed: {e}")))?;

    let kek = match keyfile {
        None => Key::from_slice(&derived),
        Some(file) => {
            let mut ikm = derived.clone();
            ikm.extend_from_slice(&sha256(file));
            let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
            let mut okm = [0u8; KEY_LEN];
            let res = hk
                .expand(b"aurapass/v2/keyfile-composite", &mut okm)
                .map_err(|e| Error::crypto(format!("hkdf expand failed: {e}")));
            ikm.zeroize();
            res?;
            Key::from_slice(&okm)
        }
    };
    derived.zeroize();
    kek
}

/// An XChaCha20-Poly1305 ciphertext with its nonce, both base64 for JSON.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// Base64 nonce (24 bytes).
    pub nonce: String,
    /// Base64 ciphertext, including the 16-byte authentication tag.
    pub ct: String,
    /// Cipher used, so the format stays forward-compatible.
    #[serde(default)]
    pub algo: AeadAlgo,
}

impl Sealed {
    /// Encrypt `plaintext`, authenticating `aad`.
    pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<Self> {
        let nonce = random_bytes::<NONCE_LEN>();
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| Error::crypto(format!("cipher init failed: {e}")))?;
        let xnonce = XNonce::try_from(&nonce[..])
            .map_err(|e| Error::crypto(format!("nonce rejected: {e}")))?;
        let ct = cipher
            .encrypt(
                &xnonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::AeadFailed)?;
        Ok(Self {
            nonce: b64_encode(nonce),
            ct: b64_encode(ct),
            algo: AeadAlgo::XChaCha20Poly1305,
        })
    }

    /// Decrypt and verify. Returns [`Error::AeadFailed`] when the tag does not
    /// check out, which the caller usually maps to "wrong password".
    pub fn open(&self, key: &Key, aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = b64_decode(&self.nonce)?;
        if nonce.len() != NONCE_LEN {
            return Err(Error::InvalidFormat(format!(
                "nonce must be {NONCE_LEN} bytes, found {}",
                nonce.len()
            )));
        }
        let ct = b64_decode(&self.ct)?;
        if ct.len() < TAG_LEN {
            return Err(Error::InvalidFormat("ciphertext is shorter than its tag".into()));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| Error::crypto(format!("cipher init failed: {e}")))?;
        let xnonce = XNonce::try_from(&nonce[..])
            .map_err(|e| Error::crypto(format!("nonce rejected: {e}")))?;
        cipher
            .decrypt(
                &xnonce,
                Payload {
                    msg: &ct,
                    aad,
                },
            )
            .map_err(|_| Error::AeadFailed)
    }

    /// Size of the stored ciphertext in bytes (useful for the UI).
    pub fn len(&self) -> usize {
        self.ct.len()
    }

    /// True when this wrap holds no payload at all.
    pub fn is_empty(&self) -> bool {
        self.ct.is_empty()
    }
}

/// Measure how long one unlock attempt takes with the given parameters.
/// Used by the settings screen to warn users before they pick "paranoid".
pub fn benchmark_kdf(params: &KdfParams) -> Result<std::time::Duration> {
    let start = std::time::Instant::now();
    let _ = derive_kek("aurapass-benchmark", None, params)?;
    Ok(start.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        KdfParams {
            algo: KdfAlgo::Argon2id,
            salt: b64_encode(random_bytes::<SALT_LEN>()),
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            key_len: 32,
        }
    }

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let key = Key::generate();
        let sealed = Sealed::seal(&key, b"header", b"hello world").unwrap();
        assert_eq!(sealed.open(&key, b"header").unwrap(), b"hello world");
        // Wrong AAD (i.e. a tampered header) must fail.
        assert!(matches!(sealed.open(&key, b"other"), Err(Error::AeadFailed)));
    }

    #[test]
    fn flipping_a_bit_is_detected() {
        let key = Key::generate();
        let sealed = Sealed::seal(&key, b"", b"payload").unwrap();
        let mut raw = b64_decode(&sealed.ct).unwrap();
        raw[0] ^= 0x01;
        let tampered = Sealed {
            ct: b64_encode(raw),
            ..sealed
        };
        assert!(matches!(tampered.open(&key, b""), Err(Error::AeadFailed)));
    }

    #[test]
    fn different_passwords_give_different_keks() {
        let params = fast_params();
        let a = derive_kek("hunter2", None, &params).unwrap();
        let b = derive_kek("hunter3", None, &params).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn keyfile_changes_the_kek() {
        let params = fast_params();
        let plain = derive_kek("pw", None, &params).unwrap();
        let with_file = derive_kek("pw", Some(b"file-bytes"), &params).unwrap();
        assert_ne!(plain, with_file);
        // And it is deterministic.
        let again = derive_kek("pw", Some(b"file-bytes"), &params).unwrap();
        assert_eq!(with_file, again);
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let k = Key::generate();
        assert_ne!(k.subkey(b"a", b"s").unwrap(), k.subkey(b"b", b"s").unwrap());
    }

    #[test]
    fn params_roundtrip_through_presets() {
        for preset in KdfPreset::ALL {
            let p = KdfParams::with_preset(preset);
            assert_eq!(p.preset(), Some(preset));
        }
    }
}
