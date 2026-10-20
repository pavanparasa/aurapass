//! Breach checking via the Have I Been Pwned *k-anonymity* range API.
//!
//! The password is never transmitted. Only the first five hex characters of its
//! SHA-1 hash leave the machine; the API returns every suffix that shares that
//! prefix, and the match is made locally.
//!
//! An offline mode is included so the feature is testable (and usable by
//! privacy absolutists) without any network traffic.

use crate::crypto::sha1;
use crate::error::{Error, Result};
use crate::util::hex_encode;
use std::collections::HashMap;
use uuid::Uuid;

/// Where to ask for breach data.
pub const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

/// Identifies AuraPass to the API, as HIBP's terms ask.
pub const USER_AGENT: &str = concat!("AuraPass/", env!("CARGO_PKG_VERSION"));

/// The two halves of a SHA-1 hash, as used by the k-anonymity protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashParts {
    /// First five hex characters — this is what gets sent.
    pub prefix: String,
    /// Remaining 35 hex characters — this is what must match locally.
    pub suffix: String,
}

/// Split a password's SHA-1 into the prefix and suffix used by the API.
pub fn hash_parts(password: &str) -> HashParts {
    let digest = hex_encode(sha1(password.as_bytes())).to_ascii_uppercase();
    HashParts {
        prefix: digest[..5].to_string(),
        suffix: digest[5..].to_string(),
    }
}

/// A local, in-memory stand-in for the range API's response.
///
/// Used by the offline mode and by tests: keys are the 40-character suffix,
/// values the breach count.
pub type RangeResponse = HashMap<String, u32>;

/// Parse one range response body (`SUFFIX:COUNT` per line).
pub fn parse_range_response(body: &str) -> RangeResponse {
    let mut out = HashMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((suffix, count)) = line.split_once(':') else {
            continue;
        };
        let suffix = suffix.trim().to_ascii_uppercase();
        // Padded responses contain zero-count entries; keeping them is harmless
        // and lets us distinguish "checked, not found" from "not checked".
        if let Ok(count) = count.trim().parse::<u32>() {
            out.insert(suffix, count);
        }
    }
    out
}

/// How many times a password appeared in known breaches, looked up in a
/// pre-fetched range response.
pub fn count_in_range(password: &str, ranges: &RangeResponse) -> u32 {
    let parts = hash_parts(password);
    ranges.get(&parts.suffix).copied().unwrap_or(0)
}

/// Client for the live API, with a per-run prefix cache.
#[derive(Debug)]
pub struct BreachClient {
    ranges: HashMap<String, RangeResponse>,
    offline: bool,
    requests: usize,
}

impl Default for BreachClient {
    fn default() -> Self {
        Self::new()
    }
}

impl BreachClient {
    /// A client that talks to Have I Been Pwned.
    pub fn new() -> Self {
        Self {
            ranges: HashMap::new(),
            offline: false,
            requests: 0,
        }
    }

    /// A client that only consults data seeded with [`BreachClient::seed`].
    pub fn offline() -> Self {
        Self {
            ranges: HashMap::new(),
            offline: true,
            requests: 0,
        }
    }

    /// Seed a prefix, as if the API had answered for it.
    pub fn seed(&mut self, prefix: &str, response: RangeResponse) {
        self.ranges.insert(prefix.to_ascii_uppercase(), response);
    }

    /// Number of HTTP requests issued so far.
    pub fn requests(&self) -> usize {
        self.requests
    }

    /// How many times `password` has been breached.
    pub fn count(&mut self, password: &str) -> Result<u32> {
        if password.is_empty() {
            return Ok(0);
        }
        let parts = hash_parts(password);
        if !self.ranges.contains_key(&parts.prefix) {
            if self.offline {
                // Nothing known about this prefix; treat as not breached rather
                // than failing the whole audit.
                self.ranges.insert(parts.prefix.clone(), RangeResponse::new());
            } else {
                let body = self.fetch_prefix(&parts.prefix)?;
                self.ranges
                    .insert(parts.prefix.clone(), parse_range_response(&body));
            }
        }
        Ok(self
            .ranges
            .get(&parts.prefix)
            .and_then(|r| r.get(&parts.suffix))
            .copied()
            .unwrap_or(0))
    }

    #[cfg(feature = "breach")]
    fn fetch_prefix(&mut self, prefix: &str) -> Result<String> {
        let url = format!("{HIBP_RANGE_URL}{prefix}");
        self.requests += 1;
        let response = ureq::get(&url)
            .header("User-Agent", USER_AGENT)
            // Ask the API to add fake zero-count entries, so a network observer
            // cannot tell which prefix was actually interesting.
            .header("Add-Padding", "true")
            .call()
            .map_err(|e| Error::other(format!("breach check failed: {e}")))?;
        response
            .into_body()
            .read_to_string()
            .map_err(|e| Error::other(format!("could not read breach response: {e}")))
    }

    #[cfg(not(feature = "breach"))]
    fn fetch_prefix(&mut self, _prefix: &str) -> Result<String> {
        Err(Error::other(
            "this build of AuraPass was compiled without network support",
        ))
    }
}

/// Check a set of items in one pass, returning only those with a nonzero count.
///
/// Passwords are deduplicated so that ten accounts sharing one password cost a
/// single API call.
pub fn check_items(
    client: &mut BreachClient,
    items: impl IntoIterator<Item = (Uuid, String)>,
) -> Result<HashMap<Uuid, u32>> {
    let mut seen: HashMap<String, u32> = HashMap::new();
    let mut out = HashMap::new();
    for (id, password) in items {
        if password.is_empty() {
            continue;
        }
        let count = match seen.get(&password) {
            Some(c) => *c,
            None => {
                let c = client.count(&password)?;
                seen.insert(password, c);
                c
            }
        };
        if count > 0 {
            out.insert(id, count);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sha1_prefix_for_password() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let parts = hash_parts("password");
        assert_eq!(parts.prefix, "5BAA6");
        assert_eq!(parts.suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn range_parsing_ignores_junk() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:37359195\r\n\r\nnot-a-line\r\n00:0\r\n";
        let parsed = parse_range_response(body);
        assert_eq!(parsed.get("1E4C9B93F3F0682250B6CF8331B7EE68FD8"), Some(&37359195));
        assert_eq!(parsed.get("00"), Some(&0));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn offline_client_uses_seeded_data() {
        let mut client = BreachClient::offline();
        let parts = hash_parts("password");
        let mut range = RangeResponse::new();
        range.insert(parts.suffix.clone(), 37359195);
        client.seed(&parts.prefix, range);
        assert_eq!(client.count("password").unwrap(), 37359195);

        let mut client2 = BreachClient::offline();
        let mut range2 = RangeResponse::new();
        range2.insert(parts.suffix.clone(), 0);
        client2.seed(&parts.prefix, range2);
        assert_eq!(client2.count("password").unwrap(), 0);
    }

    #[test]
    fn offline_client_returns_zero_for_unknown_prefixes() {
        let mut client = BreachClient::offline();
        assert_eq!(client.count("something-new").unwrap(), 0);
    }

    #[test]
    fn items_are_deduplicated() {
        let mut client = BreachClient::offline();
        let parts = hash_parts("shared");
        let mut range = RangeResponse::new();
        range.insert(parts.suffix.clone(), 7);
        client.seed(&parts.prefix, range);

        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let found = check_items(
            &mut client,
            [(a, "shared".to_string()), (b, "shared".to_string())],
        )
        .unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[&a], 7);
        assert_eq!(client.requests(), 0);
    }
}
