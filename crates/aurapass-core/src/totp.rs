//! TOTP (RFC 6238) and HOTP (RFC 4226).
//!
//! Implemented directly on top of HMAC so that AuraPass controls base32
//! decoding, `otpauth://` parsing and clock handling without pulling in a
//! framework. Verified against the RFC 6238 test vectors below.

use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// Hash used by a TOTP configuration. Authenticator apps default to SHA-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1 (the default everywhere).
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl TotpAlgorithm {
    /// Parse the `algorithm=` parameter of an `otpauth://` URI.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "" | "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            other => Err(Error::Totp(format!("unsupported algorithm {other}"))),
        }
    }

    /// Name as used in `otpauth://` URIs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// A parsed TOTP/HOTP configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Totp {
    /// Raw shared secret.
    pub secret: Vec<u8>,
    /// Hash function.
    pub algorithm: TotpAlgorithm,
    /// Number of digits in a generated code.
    pub digits: u32,
    /// Time step in seconds (TOTP only).
    pub period: u64,
    /// Account label, when known.
    pub label: Option<String>,
    /// Issuer, when known.
    pub issuer: Option<String>,
    /// Counter for HOTP. Unused for TOTP.
    pub counter: u64,
}

impl Totp {
    /// Build a TOTP from a base32 secret and sensible defaults.
    pub fn from_base32(secret: &str) -> Result<Self> {
        let secret = decode_base32(secret)?;
        if secret.is_empty() {
            return Err(Error::Totp("the secret decodes to zero bytes".into()));
        }
        Ok(Self {
            secret,
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            label: None,
            issuer: None,
            counter: 0,
        })
    }

    /// Parse either a raw base32 secret or a full `otpauth://` URI.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::Totp("empty secret".into()));
        }
        if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
            Self::parse_uri(trimmed)
        } else {
            Self::from_base32(trimmed)
        }
    }

    /// Parse an `otpauth://totp/Issuer:account?secret=…&digits=…` URI.
    ///
    /// A hand-rolled parser is used on purpose: the extension sends these over
    /// the bridge, so malformed input must fail cleanly rather than panic.
    pub fn parse_uri(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("otpauth://")
            .ok_or_else(|| Error::Totp("URI must start with otpauth://".into()))?;

        let (kind, rest) = rest
            .split_once('/')
            .ok_or_else(|| Error::Totp("URI has no label".into()))?;
        let kind = kind.to_ascii_lowercase();
        if kind != "totp" && kind != "hotp" {
            return Err(Error::Totp(format!("unsupported otpauth type {kind}")));
        }

        let (path, query) = match rest.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (rest, None),
        };

        // Label is `Issuer:Account` or just `Account`, percent-encoded.
        let mut issuer: Option<String> = None;
        let mut label: Option<String> = None;
        let decoded_path = percent_decode(path);
        if !decoded_path.is_empty() {
            let (i, l) = match decoded_path.split_once(':') {
                Some((i, l)) => (Some(i.trim().to_string()), l.trim().to_string()),
                None => (None, decoded_path.trim().to_string()),
            };
            if let Some(i) = i.filter(|s| !s.is_empty()) {
                issuer = Some(i);
            }
            if !l.is_empty() {
                label = Some(l);
            }
        }

        let mut secret: Option<Vec<u8>> = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits: u32 = 6;
        let mut period: u64 = 30;
        let mut counter: u64 = 0;

        for pair in query.unwrap_or("").split('&').filter(|s| !s.is_empty()) {
            let (key, value) = match pair.split_once('=') {
                Some((k, v)) => (percent_decode(k).to_ascii_lowercase(), percent_decode(v)),
                None => (percent_decode(pair).to_ascii_lowercase(), String::new()),
            };
            match key.as_str() {
                "secret" => secret = Some(decode_base32(&value)?),
                "algorithm" => algorithm = TotpAlgorithm::parse(&value)?,
                "digits" => {
                    digits = value
                        .trim()
                        .parse()
                        .map_err(|_| Error::Totp(format!("invalid digits value {value:?}")))?
                }
                "period" => {
                    period = value
                        .trim()
                        .parse()
                        .map_err(|_| Error::Totp(format!("invalid period value {value:?}")))?
                }
                "counter" => {
                    counter = value
                        .trim()
                        .parse()
                        .map_err(|_| Error::Totp(format!("invalid counter value {value:?}")))?
                }
                "issuer" if !value.trim().is_empty() => issuer = Some(value.trim().to_string()),
                _ => {}
            }
        }

        let secret = secret.filter(|s| !s.is_empty()).ok_or_else(|| {
            Error::Totp("the URI has no usable `secret` parameter".into())
        })?;

        if !(4..=10).contains(&digits) {
            return Err(Error::Totp(format!("{digits} digits is out of range")));
        }
        if period == 0 || period > 3600 {
            return Err(Error::Totp(format!("period {period} is out of range")));
        }

        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
            label,
            issuer,
            counter,
        })
    }

    /// Render back to an `otpauth://` URI (used when exporting or handing a
    /// credential to the browser extension).
    pub fn to_uri(&self) -> String {
        let label = match (&self.issuer, &self.label) {
            (Some(i), Some(l)) => format!("{}:{}", percent_encode(i), percent_encode(l)),
            (Some(i), None) => percent_encode(i),
            (None, Some(l)) => percent_encode(l),
            (None, None) => String::from("AuraPass"),
        };
        let secret = encode_base32(&self.secret);
        let mut uri = format!(
            "otpauth://totp/{label}?secret={secret}&digits={}&period={}&algorithm={}",
            self.digits,
            self.period,
            self.algorithm.as_str()
        );
        if let Some(i) = &self.issuer {
            uri.push_str(&format!("&issuer={}", percent_encode(i)));
        }
        uri
    }

    /// The HOTP value for an explicit counter (RFC 4226).
    pub fn hotp(&self, counter: u64) -> Result<String> {
        let digest = match self.algorithm {
            TotpAlgorithm::Sha1 => {
                let mut mac = <Hmac<Sha1> as hmac::digest::KeyInit>::new_from_slice(&self.secret)
                    .map_err(|e| Error::Totp(format!("HMAC init failed: {e}")))?;
                mac.update(&counter.to_be_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            TotpAlgorithm::Sha256 => {
                let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&self.secret)
                    .map_err(|e| Error::Totp(format!("HMAC init failed: {e}")))?;
                mac.update(&counter.to_be_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            TotpAlgorithm::Sha512 => {
                let mut mac = <Hmac<Sha512> as hmac::digest::KeyInit>::new_from_slice(&self.secret)
                    .map_err(|e| Error::Totp(format!("HMAC init failed: {e}")))?;
                mac.update(&counter.to_be_bytes());
                mac.finalize().into_bytes().to_vec()
            }
        };

        // Dynamic truncation.
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let slice = digest
            .get(offset..offset + 4)
            .ok_or_else(|| Error::Totp("truncation offset out of range".into()))?;
        let binary = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) & 0x7fff_ffff;
        let modulus = 10u32.pow(self.digits);
        Ok(format!("{:0width$}", binary % modulus, width = self.digits as usize))
    }

    /// The TOTP code for a Unix timestamp (RFC 6238).
    pub fn code_at(&self, unix_seconds: u64) -> Result<String> {
        let counter = unix_seconds / self.period.max(1);
        self.hotp(counter)
    }

    /// The code for "now".
    pub fn now(&self) -> Result<String> {
        self.code_at(crate::now_unix())
    }

    /// Seconds until the current code expires.
    pub fn seconds_remaining(&self, unix_seconds: u64) -> u64 {
        let period = self.period.max(1);
        period - (unix_seconds % period)
    }

    /// How far through the current period we are, in `0.0..=1.0`.
    pub fn progress(&self, unix_seconds: u64) -> f32 {
        let period = self.period.max(1) as f32;
        let elapsed = (unix_seconds % period as u64) as f32;
        (elapsed / period).clamp(0.0, 1.0)
    }

    /// A short label such as `GitHub: alice@example.com`.
    pub fn display_name(&self) -> String {
        match (&self.issuer, &self.label) {
            (Some(i), Some(l)) if i != l => format!("{i}: {l}"),
            (Some(i), _) => i.clone(),
            (None, Some(l)) => l.clone(),
            (None, None) => "Authenticator".to_string(),
        }
    }
}

/// Decode RFC 4648 base32 (uppercase, `=` padding optional, spaces and dashes
/// tolerated because users paste secrets in every imaginable shape).
pub fn decode_base32(input: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for raw in input.bytes() {
        let c = raw.to_ascii_uppercase();
        if c == b'=' || c == b' ' || c == b'-' || c == b'\t' || c == b'\n' || c == b'\r' {
            continue;
        }
        let value = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| Error::Totp(format!("invalid base32 character {:?}", c as char)))?;
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    // Leftover bits are padding; RFC 4648 requires them to be zero, but real
    // world secrets sometimes omit them, so they are simply dropped.
    Ok(out)
}

/// Encode bytes as RFC 4648 base32 without padding.
pub fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B test vectors (SHA-1, 8 digits).
    #[test]
    fn rfc6238_sha1_vectors() {
        let secret = b"12345678901234567890";
        let totp = Totp {
            secret: secret.to_vec(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 8,
            period: 30,
            label: None,
            issuer: None,
            counter: 0,
        };
        for (time, expected) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(totp.code_at(time).unwrap(), expected, "t={time}");
        }
    }

    /// RFC 4226 Appendix D HOTP vectors.
    #[test]
    fn rfc4226_hotp_vectors() {
        let totp = Totp {
            secret: b"12345678901234567890".to_vec(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            label: None,
            issuer: None,
            counter: 0,
        };
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(&totp.hotp(counter as u64).unwrap(), want, "counter={counter}");
        }
    }

    #[test]
    fn base32_roundtrip() {
        for case in ["JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQ", "MZXW6YTBOI"] {
            let decoded = decode_base32(case).unwrap();
            assert_eq!(encode_base32(&decoded).trim_end_matches('='), case);
        }
        // Padding and separators are tolerated.
        assert_eq!(
            decode_base32("jbsw y3dp ehpk-3pxp").unwrap(),
            decode_base32("JBSWY3DPEHPK3PXP").unwrap()
        );
        assert!(decode_base32("0189!!").is_err());
    }

    #[test]
    fn otpauth_uri_parsing() {
        let uri = "otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30&algorithm=SHA1";
        let t = Totp::parse_uri(uri).unwrap();
        assert_eq!(t.digits, 6);
        assert_eq!(t.period, 30);
        assert_eq!(t.issuer.as_deref(), Some("GitHub"));
        assert_eq!(t.label.as_deref(), Some("alice@example.com"));
        assert_eq!(t.display_name(), "GitHub: alice@example.com");
        assert_eq!(t.secret, decode_base32("JBSWY3DPEHPK3PXP").unwrap());
    }

    #[test]
    fn otpauth_invalid_inputs_are_rejected() {
        assert!(Totp::parse_uri("https://example.com").is_err());
        assert!(Totp::parse_uri("otpauth://totp/x?digits=6").is_err());
        assert!(Totp::parse_uri("otpauth://steam/x?secret=AAAA").is_err());
        assert!(Totp::parse_uri("otpauth://totp/x?secret=AAAA&digits=99").is_err());
        assert!(Totp::parse("").is_err());
    }

    #[test]
    fn uri_roundtrip() {
        let mut t = Totp::from_base32("JBSWY3DPEHPK3PXP").unwrap();
        t.issuer = Some("Acme Corp".into());
        t.label = Some("bob@acme.test".into());
        let uri = t.to_uri();
        let back = Totp::parse_uri(&uri).unwrap();
        assert_eq!(back.issuer, t.issuer);
        assert_eq!(back.label, t.label);
        assert_eq!(back.secret, t.secret);
    }

    #[test]
    fn countdown_is_within_the_period() {
        let t = Totp::from_base32("JBSWY3DPEHPK3PXP").unwrap();
        for now in [0u64, 1, 29, 30, 31, 1_700_000_000] {
            let left = t.seconds_remaining(now);
            assert!((1..=30).contains(&left), "now={now} left={left}");
            assert!((0.0..1.0).contains(&t.progress(now)));
        }
    }
}
