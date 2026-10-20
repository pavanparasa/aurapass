//! The protocol spoken between AuraPass and the browser extensions.
//!
//! The transport is a WebSocket bound to `127.0.0.1`. Two things protect it:
//!
//! 1. **Loopback only.** The listener never binds a routable address, so the
//!    bridge is unreachable from the network.
//! 2. **End-to-end encryption with the pairing token.** Every frame is
//!    XChaCha20-Poly1305 sealed with a session key derived from the token the
//!    user copied out of the desktop app. Another local user who can connect to
//!    the port still cannot read or forge messages.
//!
//! Requests are line-delimited JSON; each line is a base64 of the encrypted
//! frame, so the transport itself never sees plaintext credentials.

use crate::crypto::{self, Key, Sealed};
use crate::error::{Error, Result};
use crate::model::{Field, Item, ItemKind};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

/// Version of this protocol. Bumped on breaking changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum size of a single decrypted frame (1 MiB).
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Wrap a message in the encrypted bridge envelope.
///
/// The cleartext is `b64(nonce) || "." || b64(ciphertext)`, which keeps the
/// frame a single line of ASCII and therefore safe inside a WebSocket text
/// message or a newline-delimited stream.
pub fn seal_frame<T: Serialize>(key: &Key, message: &T) -> Result<String> {
    let plaintext = serde_json::to_vec(message)?;
    if plaintext.len() > MAX_FRAME_BYTES {
        return Err(Error::other("bridge frame is too large"));
    }
    // The nonce is inside `Sealed`, so no AAD is needed here; the protocol
    // version is authenticated instead to prevent downgrade confusion.
    let sealed = Sealed::seal(key, &PROTOCOL_VERSION.to_be_bytes(), &plaintext)?;
    Ok(format!("{}.{}", sealed.nonce, sealed.ct))
}

/// Reverse [`seal_frame`].
pub fn open_frame<T: DeserializeOwned>(key: &Key, frame: &str) -> Result<T> {
    let (nonce, ct) = frame
        .trim()
        .split_once('.')
        .ok_or_else(|| Error::InvalidFormat("malformed bridge frame".into()))?;
    let sealed = Sealed {
        nonce: nonce.to_string(),
        ct: ct.to_string(),
        algo: Default::default(),
    };
    let plaintext = sealed.open(key, &PROTOCOL_VERSION.to_be_bytes())?;
    if plaintext.len() > MAX_FRAME_BYTES {
        return Err(Error::other("bridge frame is too large"));
    }
    serde_json::from_slice(&plaintext).map_err(Error::from)
}

/// Derive the session key for a bridge connection.
///
/// `salt` is chosen by the client and echoed by the server in the clear, so
/// both sides derive the same key without ever sending the token. Because the
/// salt is public this is not a substitute for TLS against an *active* attacker
/// who can guess the token — but the token is 256 bits of entropy, so guessing
/// is not a threat. Its job is to stop passive local sniffing and replay.
pub fn session_key(token: &str, salt: &[u8]) -> Result<Key> {
    if token.trim().is_empty() {
        return Err(Error::other("no pairing token configured"));
    }
    let base = Key::from_slice(&crypto::sha256(token.as_bytes()))?;
    base.subkey(b"aurapass/v2/bridge-session", salt)
}

/// Domain separation string for the handshake proof.
const HELLO_CONTEXT: &[u8] = b"aurapass/v2/bridge-hello";

/// The first frame a client sends, in the clear.
///
/// It carries a random salt and a proof that the client knows the pairing
/// token. The token itself never travels: the proof is
/// `HMAC-SHA256(SHA-256(token), context ‖ salt ‖ protocol)`, which is enough for
/// the server to authenticate the client and for both sides to then derive an
/// encrypted session.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClientHello {
    /// Protocol version the client speaks.
    pub protocol: u32,
    /// Human-readable client identifier, e.g. `chromium-extension/1.0.0`.
    pub client: String,
    /// Base64url-encoded 32-byte random salt.
    pub salt: String,
    /// Base64url-encoded HMAC proof.
    pub proof: String,
}

/// Compute the handshake proof for a token, salt and protocol version.
pub fn hello_proof(token: &str, salt: &[u8], protocol: u32) -> Result<String> {
    if token.trim().is_empty() {
        return Err(Error::other("no pairing token configured"));
    }
    let key = crypto::sha256(token.as_bytes());
    let mut message = Vec::with_capacity(HELLO_CONTEXT.len() + salt.len() + 4);
    message.extend_from_slice(HELLO_CONTEXT);
    message.extend_from_slice(salt);
    message.extend_from_slice(&protocol.to_be_bytes());
    Ok(crate::util::b64url_encode(crypto::hmac_sha256(
        &key, &message,
    )))
}

/// Build a hello message for a client that knows `token`.
pub fn make_client_hello(token: &str, client: &str) -> Result<(ClientHello, Vec<u8>)> {
    let salt = crypto::random_bytes::<32>().to_vec();
    let proof = hello_proof(token, &salt, PROTOCOL_VERSION)?;
    Ok((
        ClientHello {
            protocol: PROTOCOL_VERSION,
            client: client.to_string(),
            salt: crate::util::b64url_encode(&salt),
            proof,
        },
        salt,
    ))
}

/// Server side of the handshake: check the proof in constant time.
///
/// Returns the session salt on success so the caller can derive the session key.
pub fn verify_client_hello(
    token: &str,
    hello: &ClientHello,
) -> Result<Vec<u8>> {
    if hello.protocol != PROTOCOL_VERSION {
        return Err(Error::other(format!(
            "the extension speaks protocol {} but this AuraPass speaks {PROTOCOL_VERSION}",
            hello.protocol
        )));
    }
    let salt = crate::util::b64url_decode(&hello.salt)?;
    if salt.len() < 16 {
        return Err(Error::other("handshake salt is too short"));
    }
    let expected = hello_proof(token, &salt, hello.protocol)?;
    let expected = crate::util::b64url_decode(&expected)?;
    let provided = crate::util::b64url_decode(&hello.proof)?;
    if !crypto::ct_eq(&expected, &provided) {
        return Err(Error::other(
            "pairing token mismatch — copy the token again from AuraPass",
        ));
    }
    Ok(salt)
}


/// A request from the browser extension to the desktop app.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// First message of a connection. Until this succeeds the server ignores
    /// everything else.
    Hello {
        /// Protocol version the extension speaks.
        protocol: u32,
        /// Free-form client description, e.g. `chromium/128`.
        client: String,
    },
    /// Liveness check.
    Ping,
    /// Is the vault locked, and which vault is it?
    Status,
    /// Lock the vault now.
    Lock,
    /// Unlock with the master password (only when the GUI is running).
    Unlock {
        /// The master password, transported inside the encrypted frame.
        password: String,
    },
    /// Search for items matching a URL.
    MatchUrl {
        /// Page URL.
        url: String,
    },
    /// Free-text search.
    Search {
        /// Query string.
        query: String,
        /// Maximum number of results.
        limit: usize,
    },
    /// Fetch one item. `include_secrets` gates the password and TOTP.
    Item {
        /// Item id.
        id: Uuid,
        /// Whether to include the password and one-time-password secret.
        include_secrets: bool,
    },
    /// Ask for a fresh TOTP code.
    Totp {
        /// Item id.
        id: Uuid,
    },
    /// Generate a password.
    Generate {
        /// Desired length.
        length: usize,
        /// Include digits.
        digits: bool,
        /// Include symbols.
        symbols: bool,
        /// Include upper-case letters.
        uppercase: bool,
    },
    /// Tell the vault a credential was used (updates "last used").
    Used {
        /// Item id.
        id: Uuid,
    },
    /// Offer to save a login the user just submitted.
    SaveLogin {
        /// Page URL.
        url: String,
        /// Account name.
        username: String,
        /// The secret.
        password: String,
        /// Page title, used as a fallback item title.
        title: Option<String>,
    },
    /// Bring the desktop's quick assistant forward. The extension sends the
    /// screen position of the browser's toolbar button so the panel can open
    /// directly beneath it, like a native browser pop-up.
    ShowAssistant {
        /// Screen x of the anchor (the button's right edge).
        x: Option<f32>,
        /// Screen y of the anchor (the button's bottom edge).
        y: Option<f32>,
    },
}

/// The first frame of a *pairing* handshake, sent in the clear.
///
/// A browser with no token yet introduces itself with this message. The app
/// queues the request for the user, who sees a dialog naming the browser and
/// clicks Allow; only then does the app issue a secret. Nothing is typed by
/// hand and no token is displayed anywhere.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PairRequestMessage {
    /// Protocol version the client speaks.
    pub protocol: u32,
    /// Free-form client description, e.g. `chromium-extension/1.0.0`.
    pub client: String,
    /// Stable id the browser generates once and keeps.
    pub client_id: String,
    /// Friendly name shown in the approval dialog, e.g. `Chrome`.
    pub name: String,
}

/// How long a pairing request waits for the user before it is abandoned.
pub const PAIR_TIMEOUT_SECS: u64 = 180;

/// A reply from the desktop app.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// The request succeeded; `data` carries the payload.
    Ok {
        /// Request-specific payload.
        data: serde_json::Value,
    },
    /// The request failed.
    Error {
        /// Human-readable reason, safe to show in the extension popup.
        message: String,
    },
    /// The vault is locked; the extension should ask the user.
    Locked {
        /// What the extension can do about it.
        hint: String,
    },
    /// The vault is busy (an unlock is already in flight).
    Busy {},
}

impl Response {
    /// Build an `Ok` response from any serialisable payload.
    pub fn ok<T: Serialize>(payload: T) -> Self {
        match serde_json::to_value(payload) {
            Ok(data) => Response::Ok { data },
            Err(e) => Response::error(format!("could not serialise the response: {e}")),
        }
    }

    /// Build an `Error` response.
    pub fn error(message: impl Into<String>) -> Self {
        Response::Error {
            message: message.into(),
        }
    }

    /// The default "please unlock" reply.
    pub fn locked() -> Self {
        Response::Locked {
            hint: "Unlock AuraPass on the desktop, then try again.".into(),
        }
    }
}

impl From<Result<Response>> for Response {
    fn from(value: Result<Response>) -> Self {
        match value {
            Ok(r) => r,
            Err(Error::Locked) => Response::locked(),
            Err(e) => Response::error(e.to_string()),
        }
    }
}

/// Payload of [`Request::Status`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StatusPayload {
    /// Whether the vault is locked.
    pub locked: bool,
    /// Vault display name, when unlocked.
    pub vault: Option<String>,
    /// Item count, when unlocked.
    pub items: Option<usize>,
    /// AuraPass version.
    pub version: String,
    /// Protocol version.
    pub protocol: u32,
    /// Auto-lock timeout in seconds.
    pub auto_lock_secs: u64,
}

/// A trimmed-down item, what the extension popup displays.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ItemSummary {
    /// Item id.
    pub id: Uuid,
    /// Display title.
    pub title: String,
    /// Account name.
    pub username: Option<String>,
    /// Primary URL.
    pub url: Option<String>,
    /// Item type label.
    pub kind: String,
    /// Whether a TOTP secret is available.
    pub has_totp: bool,
    /// Whether the item is a favourite.
    pub favorite: bool,
}

impl From<&Item> for ItemSummary {
    fn from(item: &Item) -> Self {
        Self {
            id: item.id,
            title: item.title.clone(),
            username: item.username.clone(),
            url: item.primary_url().map(|s| s.to_string()),
            kind: item.kind.label().to_string(),
            has_totp: item.totp.is_some(),
            favorite: item.favorite,
        }
    }
}

/// Payload of [`Request::Item`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ItemPayload {
    /// The summary fields.
    #[serde(flatten)]
    pub summary: ItemSummary,
    /// The password, only when requested.
    pub password: Option<String>,
    /// Additional custom fields (`label`, `value`, `sensitive`).
    pub fields: Vec<(String, String, bool)>,
    /// Free-form notes.
    pub notes: String,
}

impl ItemPayload {
    /// Build from an item, optionally including secrets.
    pub fn from_item(item: &Item, include_secrets: bool) -> Self {
        Self {
            summary: ItemSummary::from(item),
            password: if include_secrets {
                item.password.clone()
            } else {
                None
            },
            fields: item
                .fields
                .iter()
                .filter(|f| include_secrets || !f.sensitive)
                .map(|f: &Field| (f.label.clone(), f.value.clone(), f.sensitive))
                .collect(),
            notes: if include_secrets {
                item.notes.clone()
            } else {
                String::new()
            },
        }
    }
}

/// Payload of [`Request::Totp`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TotpPayload {
    /// The current code, e.g. `123456`.
    pub code: String,
    /// Seconds until it changes.
    pub seconds_remaining: u64,
    /// Period in seconds.
    pub period: u64,
    /// Number of digits.
    pub digits: u32,
    /// Human label such as `GitHub: alice`.
    pub display: String,
}

/// Payload of [`Request::MatchUrl`] and [`Request::Search`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ItemsPayload {
    /// Matching items, best match first.
    pub items: Vec<ItemSummary>,
}

/// Payload of [`Request::Generate`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GeneratedPayload {
    /// The generated password.
    pub password: String,
    /// Estimated entropy in bits.
    pub entropy_bits: f64,
}

/// The full list of things the extension may ask for, for documentation and
/// for the "what can this connect to?" screen.
pub fn request_catalogue() -> &'static [(&'static str, &'static str)] {
    &[
        ("hello", "Authenticate to the vault with the pairing token."),
        ("ping", "Check that AuraPass is running."),
        ("status", "Report whether the vault is locked."),
        ("lock", "Lock the vault immediately."),
        ("unlock", "Unlock with the master password (requires the desktop app)."),
        ("match_url", "Find credentials that belong to a page."),
        ("search", "Search the vault by text."),
        ("item", "Fetch one item, optionally with secrets."),
        ("totp", "Get the current one-time code for an item."),
        ("generate", "Ask AuraPass for a new password."),
        ("used", "Record that a credential was used."),
        ("save_login", "Offer to store a newly submitted login."),
    ]
}

/// Kinds that the bridge will offer to fill; keeps `SecureNote` out of
/// autofill suggestions.
pub fn is_fillable(kind: ItemKind) -> bool {
    matches!(
        kind,
        ItemKind::Login | ItemKind::Password | ItemKind::BankAccount | ItemKind::Server
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_and_are_authenticated() {
        let key = session_key("a-long-token-value", b"saltsalt").unwrap();
        let frame = seal_frame(&key, &Request::Ping).unwrap();
        assert!(!frame.contains("ping"), "frames must not be readable");
        let back: Request = open_frame(&key, &frame).unwrap();
        assert_eq!(back, Request::Ping);

        // A different token must not be able to open it.
        let other = session_key("a-different-token", b"saltsalt").unwrap();
        assert!(open_frame::<Request>(&other, &frame).is_err());
    }

    #[test]
    fn tampering_with_a_frame_fails() {
        let key = session_key("tok", b"s").unwrap();
        let frame = seal_frame(&key, &Request::Lock).unwrap();
        let (nonce, ct) = frame.split_once('.').unwrap();
        let mut bytes = crate::util::b64_decode(ct).unwrap();
        bytes[0] ^= 1;
        let broken = format!("{nonce}.{}", crate::util::b64_encode(&bytes));
        assert!(open_frame::<Request>(&key, &broken).is_err());
    }

    #[test]
    fn malformed_frames_are_rejected_cleanly() {
        let key = session_key("tok", b"s").unwrap();
        assert!(open_frame::<Request>(&key, "not-a-frame").is_err());
        assert!(open_frame::<Request>(&key, "AAAA.BBBB").is_err());
        assert!(open_frame::<Request>(&key, "").is_err());
    }

    #[test]
    fn session_key_needs_a_token() {
        assert!(session_key("", b"s").is_err());
        assert!(session_key("   ", b"s").is_err());
        // The salt changes the key.
        assert_ne!(
            session_key("tok", b"one").unwrap(),
            session_key("tok", b"two").unwrap()
        );
    }

    #[test]
    fn item_payload_hides_secrets_when_asked() {
        let mut item = Item::new(ItemKind::Login, "GitHub");
        item.username = Some("alice".into());
        item.password = Some("hunter2hunter2".into());
        item.notes = "secret note".into();
        item.fields.push(Field::secret("PIN", "1234"));
        item.fields.push(Field::new("Office", "Berlin"));

        let public = ItemPayload::from_item(&item, false);
        assert!(public.password.is_none());
        assert!(public.notes.is_empty());
        assert_eq!(public.fields.len(), 1);
        assert_eq!(public.fields[0].0, "Office");

        let full = ItemPayload::from_item(&item, true);
        assert_eq!(full.password.as_deref(), Some("hunter2hunter2"));
        assert_eq!(full.fields.len(), 2);
        assert_eq!(full.notes, "secret note");
    }

    #[test]
    fn responses_serialise_with_a_status_tag() {
        let value = serde_json::to_value(Response::ok(ItemsPayload { items: vec![] })).unwrap();
        assert_eq!(value["status"], "ok");
        let value = serde_json::to_value(Response::error("nope")).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["message"], "nope");
    }

    #[test]
    fn locked_errors_map_to_the_locked_response() {
        let r: Response = Err::<Response, _>(Error::Locked).into();
        assert!(matches!(r, Response::Locked { .. }));
    }

    #[test]
    fn requests_serialise_with_a_type_tag() {
        let value = serde_json::to_value(Request::MatchUrl {
            url: "https://example.com".into(),
        })
        .unwrap();
        assert_eq!(value["type"], "match_url");
        assert_eq!(value["url"], "https://example.com");
    }

    #[test]
    fn handshake_accepts_the_right_token_and_rejects_others() {
        let token = "a-very-secret-pairing-token";
        let (hello, salt) = make_client_hello(token, "test/1.0").unwrap();
        let recovered = verify_client_hello(token, &hello).unwrap();
        assert_eq!(recovered, salt);
        assert_eq!(salt.len(), 32);

        // Both sides must land on the same session key.
        assert_eq!(
            session_key(token, &recovered).unwrap(),
            session_key(token, &salt).unwrap()
        );

        assert!(verify_client_hello("wrong-token", &hello).is_err());
    }

    #[test]
    fn handshake_rejects_old_protocols_and_bad_salts() {
        let token = "tok";
        let (mut hello, _) = make_client_hello(token, "test").unwrap();
        hello.protocol = PROTOCOL_VERSION + 1;
        assert!(verify_client_hello(token, &hello).is_err());

        let (mut hello, _) = make_client_hello(token, "test").unwrap();
        hello.salt = crate::util::b64url_encode([0u8; 4]);
        assert!(verify_client_hello(token, &hello).is_err());

        let (mut hello, _) = make_client_hello(token, "test").unwrap();
        hello.proof = crate::util::b64url_encode([1u8; 32]);
        assert!(verify_client_hello(token, &hello).is_err());
    }

    #[test]
    fn handshake_salts_are_unique() {
        let token = "tok";
        let (a, salt_a) = make_client_hello(token, "test").unwrap();
        let (b, salt_b) = make_client_hello(token, "test").unwrap();
        assert_ne!(salt_a, salt_b);
        assert_ne!(a.proof, b.proof);
    }
}
