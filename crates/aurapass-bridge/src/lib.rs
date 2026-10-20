//! The AuraPass browser bridge.
//!
//! A single-threaded-per-connection WebSocket server bound to `127.0.0.1` that
//! lets a browser extension read and write the currently open vault. It is used
//! two ways:
//!
//! * in-process by the desktop app, so the extension works while the GUI is
//!   running, and
//! * standalone via the `aurapass-bridge` binary, for headless machines.
//!
//! Security model (see [`aurapass_core::ipc`] for the wire format):
//!
//! | Threat | Mitigation |
//! |---|---|
//! | Remote attacker | listener binds `127.0.0.1` only |
//! | Another local user on the port | a browser must be approved by the user in the app; after that every frame is XChaCha20-Poly1305 sealed with that browser's own secret |
//! | Token theft from disk | per-browser secrets live in the 0600 config file, and unlock still needs the master password |
//! | Extension requesting secrets while the vault is locked | every secret-returning request checks the lock state |
//!
//! Pairing is explicit: an unknown browser sends a `pair_request`, the app asks
//! the user, and only an approval issues a secret. Nothing is ever copied and
//! pasted.

use aurapass_core::config::{BridgeConfig, PairedBrowser};
use aurapass_core::error::{Error, Result};
use aurapass_core::generator::{self, PasswordPolicy};
use aurapass_core::ipc::{
    self, ClientHello, GeneratedPayload, ItemPayload, ItemSummary, ItemsPayload, PairRequestMessage,
    Request, Response, StatusPayload, TotpPayload, PAIR_TIMEOUT_SECS, PROTOCOL_VERSION,
};
use aurapass_core::model::{Item, ItemKind};
use aurapass_core::totp::Totp;
use aurapass_core::vault::{UnlockedVault, VaultFile};
use chrono::{DateTime, Utc};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tungstenite::{Message, WebSocket, accept};
use uuid::Uuid;

pub mod console;

/// How long a client may take to complete the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many saved logins the bridge will create without user confirmation.
const MAX_AUTOSAVED_TITLE_LEN: usize = 200;

/// One connected client, tracked so the GUI can show who is listening.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// Free-form client identifier from the handshake.
    pub client: String,
    /// When it connected.
    pub since: DateTime<Utc>,
    /// How many requests it has made.
    pub requests: u64,
}

/// A browser waiting for the user to approve it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairPrompt {
    /// Correlates the dialog with the waiting connection.
    pub id: String,
    /// Stable id the browser generated for itself.
    pub client_id: String,
    /// Free-form client description, e.g. `chromium-extension/1.0.0`.
    pub client: String,
    /// Friendly name shown in the dialog, e.g. `Chrome`.
    pub name: String,
}

/// Something the bridge wants the desktop app to do.
#[derive(Debug, Clone, PartialEq)]
pub enum UiCommand {
    /// Bring the quick assistant forward, optionally at a screen position.
    ShowAssistant {
        /// Screen x of the anchor's right edge.
        x: Option<f32>,
        /// Screen y of the anchor's bottom edge.
        y: Option<f32>,
    },
}

#[derive(Debug)]
struct Inner {
    vault: Option<UnlockedVault>,
    vault_path: Option<PathBuf>,
    clients: Vec<ClientInfo>,
    last_error: Option<String>,
    /// Browsers waiting for the user to say yes or no.
    pairs: std::collections::VecDeque<PairPrompt>,
    /// Channels that wake the waiting pairing connections.
    pair_waiters: std::collections::HashMap<String, std::sync::mpsc::Sender<Option<String>>>,
    /// Browsers the user has approved, with the secret each was issued.
    paired: Vec<PairedBrowser>,
    /// Work the GUI should pick up on its next tick.
    commands: std::collections::VecDeque<UiCommand>,
    /// Set when a request changed the vault, so the GUI can pick up the copy.
    vault_touched: bool,
}

/// The shared state behind a bridge server.
#[derive(Debug)]
pub struct Bridge {
    inner: Arc<Mutex<Inner>>,
    config: BridgeConfig,
    started_at: DateTime<Utc>,
    connections: Arc<AtomicUsize>,
}

impl Bridge {
    /// A bridge with no vault loaded.
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                vault: None,
                vault_path: None,
                clients: Vec::new(),
                last_error: None,
                pairs: std::collections::VecDeque::new(),
                pair_waiters: std::collections::HashMap::new(),
                paired: config.paired.clone(),
                commands: std::collections::VecDeque::new(),
                vault_touched: false,
            })),
            config,
            started_at: Utc::now(),
            connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A bridge that already has an unlocked vault.
    pub fn with_vault(config: BridgeConfig, vault: UnlockedVault) -> Self {
        let path = vault.path().map(|p| p.to_path_buf());
        let bridge = Self::new(config);
        {
            let mut inner = bridge.inner.lock().expect("bridge mutex");
            inner.vault = Some(vault);
            inner.vault_path = path;
        }
        bridge
    }

    /// The pairing token clients must present.
    ///
    /// This is the legacy/manual token. Browsers paired through the app use
    /// their own secret instead; see [`Bridge::paired_browsers`].
    pub fn token(&self) -> &str {
        &self.config.token
    }

    /// Browsers the user has approved, newest last.
    pub fn paired_browsers(&self) -> Vec<PairedBrowser> {
        self.inner
            .lock()
            .expect("bridge mutex")
            .paired
            .clone()
    }

    /// Pairing requests the user has not answered yet.
    pub fn pending_pairs(&self) -> Vec<PairPrompt> {
        self.inner
            .lock()
            .expect("bridge mutex")
            .pairs
            .iter()
            .cloned()
            .collect()
    }

    /// Answer a pairing request. On approval the browser is issued a fresh
    /// secret, which is both remembered here and returned so the caller can
    /// persist it in the configuration file.
    pub fn resolve_pair(&self, id: &str, allow: bool) -> Option<PairedBrowser> {
        let mut inner = self.inner.lock().expect("bridge mutex");
        let Some(waiters) = inner.pair_waiters.remove(id) else {
            // Already answered, or the browser gave up.
            inner.pairs.retain(|p| p.id != id);
            return None;
        };
        let Some(prompt) = inner
            .pairs
            .iter()
            .position(|p| p.id == id)
            .and_then(|i| inner.pairs.remove(i))
        else {
            let _ = waiters.send(None);
            return None;
        };

        if !allow {
            let _ = waiters.send(None);
            return None;
        }

        let issued = PairedBrowser {
            id: prompt.client_id.clone(),
            name: prompt.name.clone(),
            token: aurapass_core::config::new_bridge_token(),
            paired_at: Utc::now().to_rfc3339(),
        };
        inner.paired.push(issued.clone());
        let _ = waiters.send(Some(issued.token.clone()));
        Some(issued)
    }

    /// Drop a browser's access.
    pub fn forget_browser(&self, id: &str) {
        self.inner
            .lock()
            .expect("bridge mutex")
            .paired
            .retain(|b| b.id != id);
    }

    /// Take the work queued for the GUI.
    pub fn take_commands(&self) -> Vec<UiCommand> {
        let mut inner = self.inner.lock().expect("bridge mutex");
        inner.commands.drain(..).collect()
    }

    /// Every secret a client may authenticate with.
    fn token_candidates(&self) -> Vec<String> {
        let paired: Vec<String> = self
            .inner
            .lock()
            .expect("bridge mutex")
            .paired
            .iter()
            .map(|b| b.token.clone())
            .collect();
        std::iter::once(self.config.token.clone())
            .chain(paired)
            .filter(|t| !t.trim().is_empty())
            .collect()
    }

    /// Verify a client hello against any approved secret. Returns the secret
    /// that matched and the session salt.
    fn verify_hello(&self, hello: &ClientHello) -> Result<(String, Vec<u8>)> {
        let mut last = None;
        for token in self.token_candidates() {
            match ipc::verify_client_hello(&token, hello) {
                Ok(salt) => return Ok((token, salt)),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            Error::other("this browser is not paired yet — open AuraPass and approve it")
        }))
    }

    /// The configured port.
    pub fn port(&self) -> u16 {
        self.config.port
    }

    /// Whether a vault is currently unlocked.
    pub fn is_locked(&self) -> bool {
        self.inner
            .lock()
            .expect("bridge mutex")
            .vault
            .is_none()
    }

    /// Replace the loaded vault, e.g. after the GUI unlocks.
    pub fn set_vault(&self, vault: Option<UnlockedVault>) {
        let mut inner = self.inner.lock().expect("bridge mutex");
        inner.vault_path = vault.as_ref().and_then(|v| v.path().map(|p| p.to_path_buf()));
        inner.vault = vault;
        inner.vault_touched = false;
    }

    /// A copy of the vault if a bridge request changed it, so the desktop app
    /// can refresh what the window shows.
    pub fn take_changed_vault(&self) -> Option<UnlockedVault> {
        let mut inner = self.inner.lock().expect("bridge mutex");
        if !inner.vault_touched {
            return None;
        }
        inner.vault_touched = false;
        inner.vault.clone()
    }

    /// Take the vault back out (the GUI owns it between requests).
    pub fn take_vault(&self) -> Option<UnlockedVault> {
        self.inner.lock().expect("bridge mutex").vault.take()
    }

    /// Remember which file to unlock when a client asks.
    pub fn set_vault_path(&self, path: Option<PathBuf>) {
        self.inner.lock().expect("bridge mutex").vault_path = path;
    }

    /// Unlock the remembered vault file with a master password.
    ///
    /// Refused when `require_gui` is set, so a malicious page cannot brute-force
    /// a locked vault without the desktop app asking the user.
    pub fn unlock(&self, password: &str, keyfile: Option<&[u8]>) -> Result<()> {
        if self.config.require_gui {
            return Err(Error::other(
                "AuraPass is configured to only unlock from the desktop app",
            ));
        }
        let path = {
            let inner = self.inner.lock().expect("bridge mutex");
            inner.vault_path.clone()
        }
        .ok_or_else(|| Error::other("no vault has been selected yet"))?;

        let file = VaultFile::load(&path)?;
        let vault = file.unlock(password, keyfile)?;
        let mut inner = self.inner.lock().expect("bridge mutex");
        inner.vault = Some(vault);
        inner.last_error = None;
        Ok(())
    }

    /// Lock and drop the vault.
    pub fn lock(&self) -> Result<()> {
        let mut inner = self.inner.lock().expect("bridge mutex");
        if let Some(vault) = inner.vault.take() {
            vault.lock()?;
        }
        Ok(())
    }

    /// Snapshot of who is connected.
    pub fn clients(&self) -> Vec<ClientInfo> {
        self.inner.lock().expect("bridge mutex").clients.clone()
    }

    /// Name of the open vault, if any.
    pub fn status_name(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("bridge mutex")
            .vault
            .as_ref()
            .map(|v| v.name().to_string())
    }

    /// Persist the vault if a request modified it.
    pub fn flush_if_dirty(&self) -> Result<()> {
        let mut inner = self.inner.lock().expect("bridge mutex");
        Self::flush(&mut inner)
    }

    /// Number of connections served since start.
    pub fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    /// When the bridge started.
    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// Flush the vault to disk if a request changed it.
    fn flush(inner: &mut Inner) -> Result<()> {
        if let Some(vault) = inner.vault.as_mut()
            && vault.is_dirty()
        {
            vault.save()?;
            inner.vault_touched = true;
        }
        Ok(())
    }

    /// Handle one request. Never panics on bad input.
    pub fn handle(&self, request: &Request) -> Response {
        let outcome = self.dispatch(request);
        match outcome {
            Ok(response) => response,
            Err(Error::Locked) => Response::locked(),
            Err(e) => Response::error(e.to_string()),
        }
    }

    fn dispatch(&self, request: &Request) -> Result<Response> {
        match request {
            Request::Hello { protocol, client } => {
                if *protocol != PROTOCOL_VERSION {
                    return Ok(Response::error(format!(
                        "this AuraPass speaks protocol {PROTOCOL_VERSION}, you asked for {protocol}"
                    )));
                }
                let mut inner = self.inner.lock().expect("bridge mutex");
                if !inner.clients.iter().any(|c| &c.client == client) {
                    inner.clients.push(ClientInfo {
                        client: client.clone(),
                        since: Utc::now(),
                        requests: 0,
                    });
                }
                drop(inner);
                Ok(Response::ok(self.status()))
            }
            Request::Ping => Ok(Response::ok(serde_json::json!({
                "pong": true,
                "version": aurapass_core::VERSION,
            }))),
            Request::Status => Ok(Response::ok(self.status())),
            Request::Lock => {
                self.lock()?;
                Ok(Response::ok(serde_json::json!({ "locked": true })))
            }
            Request::Unlock { password } => {
                self.unlock(password, None)?;
                Ok(Response::ok(self.status()))
            }
            Request::MatchUrl { url } => {
                let inner = self.inner.lock().expect("bridge mutex");
                let vault = inner.vault.as_ref().ok_or(Error::Locked)?;
                let items: Vec<ItemSummary> = vault
                    .find_for_url(url)
                    .into_iter()
                    .filter_map(|id| vault.item(id))
                    .filter(|i| ipc::is_fillable(i.kind) && i.password.is_some())
                    .map(ItemSummary::from)
                    .collect();
                Ok(Response::ok(ItemsPayload { items }))
            }
            Request::Search { query, limit } => {
                let inner = self.inner.lock().expect("bridge mutex");
                let vault = inner.vault.as_ref().ok_or(Error::Locked)?;
                let ids = vault.query(&aurapass_core::vault::VaultQuery {
                    text: query.clone(),
                    ..Default::default()
                });
                let items: Vec<ItemSummary> = ids
                    .into_iter()
                    .filter_map(|id| vault.item(id))
                    .take((*limit).clamp(1, 200))
                    .map(ItemSummary::from)
                    .collect();
                Ok(Response::ok(ItemsPayload { items }))
            }
            Request::Item { id, include_secrets } => {
                let inner = self.inner.lock().expect("bridge mutex");
                let vault = inner.vault.as_ref().ok_or(Error::Locked)?;
                let item = vault
                    .item(*id)
                    .ok_or_else(|| Error::ItemNotFound(id.to_string()))?;
                Ok(Response::ok(ItemPayload::from_item(item, *include_secrets)))
            }
            Request::Totp { id } => {
                let mut inner = self.inner.lock().expect("bridge mutex");
                let vault = inner.vault.as_ref().ok_or(Error::Locked)?;
                let item = vault
                    .item(*id)
                    .ok_or_else(|| Error::ItemNotFound(id.to_string()))?;
                let raw = item
                    .totp
                    .as_deref()
                    .ok_or_else(|| Error::Totp("this item has no one-time password".into()))?;
                let totp = Totp::parse(raw)?;
                let now = aurapass_core::now_unix();
                let code = totp.code_at(now)?;
                let payload = TotpPayload {
                    code,
                    seconds_remaining: totp.seconds_remaining(now),
                    period: totp.period,
                    digits: totp.digits,
                    display: totp.display_name(),
                };
                // Using a one-time code counts as using the credential.
                if let Some(vault) = inner.vault.as_mut() {
                    vault.note_usage(*id);
                }
                Self::flush(&mut inner)?;
                Ok(Response::ok(payload))
            }
            Request::Generate {
                length,
                digits,
                symbols,
                uppercase,
            } => {
                let policy = PasswordPolicy {
                    length: (*length).clamp(8, 128),
                    digits: *digits,
                    symbols: *symbols,
                    uppercase: *uppercase,
                    ..PasswordPolicy::default()
                };
                let password = generator::generate_password(&policy)?;
                Ok(Response::ok(GeneratedPayload {
                    password,
                    entropy_bits: policy.entropy_bits(),
                }))
            }
            Request::Used { id } => {
                let mut inner = self.inner.lock().expect("bridge mutex");
                if inner.vault.is_none() {
                    return Err(Error::Locked);
                }
                if let Some(vault) = inner.vault.as_mut() {
                    vault.note_usage(*id);
                    vault.data.push_activity(
                        aurapass_core::model::ActivityKind::Autofilled,
                        "Filled in browser",
                        None,
                    );
                }
                Self::flush(&mut inner)?;
                Ok(Response::ok(serde_json::json!({ "recorded": true })))
            }
            Request::SaveLogin {
                url,
                username,
                password,
                title,
            } => {
                let mut inner = self.inner.lock().expect("bridge mutex");
                if inner.vault.is_none() {
                    return Err(Error::Locked);
                }
                let host = aurapass_core::util::url_host(url);
                let vault = inner.vault.as_mut().ok_or(Error::Locked)?;

                // Update an existing entry for this site and account.
                if let Some(id) = vault
                    .find_for_url(url)
                    .into_iter()
                    .find(|id| {
                        vault
                            .item(*id)
                            .and_then(|i| i.username.as_deref())
                            .map(|u| u.eq_ignore_ascii_case(username))
                            .unwrap_or(false)
                    })
                {
                    if let Some(item) = vault.item_mut(id)
                        && item.password() != Some(password.as_str())
                    {
                        item.set_password(
                            password.clone(),
                            aurapass_core::vault::PASSWORD_HISTORY_LIMIT,
                        );
                    }
                    Self::flush(&mut inner)?;
                    return Ok(Response::ok(serde_json::json!({
                        "saved": true, "updated": true, "id": id,
                    })));
                }

                let item_title = title
                    .clone()
                    .filter(|t| !t.trim().is_empty())
                    .map(|t| aurapass_core::util::truncate(&t, MAX_AUTOSAVED_TITLE_LEN))
                    .or_else(|| host.clone())
                    .unwrap_or_else(|| "Saved from browser".to_string());
                let mut item = Item::new(ItemKind::Login, item_title);
                item.username = Some(username.clone());
                item.set_password(
                    password.clone(),
                    aurapass_core::vault::PASSWORD_HISTORY_LIMIT,
                );
                if !url.trim().is_empty() {
                    item.urls.push(url.clone());
                }
                let id = item.id;
                vault.data.upsert(item);
                vault.data.push_activity(
                    aurapass_core::model::ActivityKind::Created,
                    format!("Saved a login for {username}"),
                    host,
                );
                Self::flush(&mut inner)?;
                Ok(Response::ok(serde_json::json!({
                    "saved": true, "updated": false, "id": id,
                })))
            }
            Request::ShowAssistant { x, y } => {
                self.inner
                    .lock()
                    .expect("bridge mutex")
                    .commands
                    .push_back(UiCommand::ShowAssistant { x: *x, y: *y });
                Ok(Response::ok(serde_json::json!({ "shown": true })))
            }
        }
    }

    /// Build the status payload, taking the lock.
    fn status(&self) -> StatusPayload {
        let inner = self.inner.lock().expect("bridge mutex");
        match inner.vault.as_ref() {
            Some(vault) => StatusPayload {
                locked: false,
                vault: Some(vault.name().to_string()),
                items: Some(vault.stats().items),
                version: aurapass_core::VERSION.to_string(),
                protocol: PROTOCOL_VERSION,
                auto_lock_secs: vault.data.settings.auto_lock_secs,
            },
            None => StatusPayload {
                locked: true,
                vault: None,
                items: None,
                version: aurapass_core::VERSION.to_string(),
                protocol: PROTOCOL_VERSION,
                auto_lock_secs: 0,
            },
        }
    }
}

/// A running bridge server.
#[derive(Debug)]
pub struct RunningBridge {
    /// Port actually bound (may differ from the requested one).
    pub port: u16,
    shutdown: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    shared: Arc<Bridge>,
}

impl RunningBridge {
    /// The address clients should connect to.
    pub fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// The server state, so the desktop app can answer pairing requests and
    /// pick up commands the extension sent.
    pub fn bridge(&self) -> &Arc<Bridge> {
        &self.shared
    }

    /// Ask the server to stop and wait for it.
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock the accept loop so it notices the flag promptly.
        let _ = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for RunningBridge {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

/// Bind the preferred port, falling back to the next few and finally to an
/// ephemeral port. Returns the listener and the port in use.
pub fn bind_local(preferred: u16) -> Result<(TcpListener, u16)> {
    let mut candidates: Vec<u16> = (preferred..preferred.saturating_add(9)).collect();
    candidates.push(0);
    let mut last_error = None;
    for port in candidates {
        match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))) {
            Ok(listener) => {
                let actual = listener.local_addr()?.port();
                return Ok((listener, actual));
            }
            Err(e) => last_error = Some(e),
        }
    }
    Err(Error::Io(last_error.unwrap_or_else(|| {
        std::io::Error::new(ErrorKind::AddrNotAvailable, "no free port")
    })))
}

/// Start the server on a background thread.
pub fn start(bridge: Arc<Bridge>, preferred_port: u16) -> Result<RunningBridge> {
    let (listener, port) = bind_local(preferred_port)?;
    listener.set_nonblocking(true)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = shutdown.clone();
    let connections = {
        let bridge = bridge.clone();
        bridge.connections.clone()
    };
    let shared = bridge.clone();

    let thread = std::thread::Builder::new()
        .name("aurapass-bridge".into())
        .spawn(move || {
            accept_loop(listener, bridge, thread_shutdown, connections);
        })
        .map_err(Error::Io)?;

    Ok(RunningBridge {
        port,
        shutdown,
        thread: Some(thread),
        shared,
    })
}

fn accept_loop(
    listener: TcpListener,
    bridge: Arc<Bridge>,
    shutdown: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
) {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                connections.fetch_add(1, Ordering::Relaxed);
                let bridge = bridge.clone();
                let _ = std::thread::Builder::new()
                    .name("aurapass-bridge-conn".into())
                    .spawn(move || {
                        if let Err(e) = serve_connection(stream, bridge) {
                            // Normal disconnects are not worth logging loudly.
                            if !matches!(
                                e,
                                Error::Io(ref io) if io.kind() == ErrorKind::ConnectionReset
                            ) {
                                eprintln!("aurapass-bridge: connection ended: {e}");
                            }
                        }
                    });
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(60));
            }
            Err(e) => {
                eprintln!("aurapass-bridge: accept failed: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// Run the handshake and then the request loop for one client.
pub fn serve_connection(stream: TcpStream, bridge: Arc<Bridge>) -> Result<()> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_nodelay(true).ok();
    let mut socket: WebSocket<TcpStream> = accept(stream)
        .map_err(|e| Error::other(format!("websocket handshake failed: {e}")))?;

    // --- handshake ------------------------------------------------------
    let first = socket
        .read()
        .map_err(|e| Error::other(format!("no handshake received: {e}")))?;
    let text = message_text(first)
        .ok_or_else(|| Error::other("the first frame must be a text handshake"))?;

    // A browser with no secret introduces itself and waits for the user to
    // approve it in the app. Everything else is a normal authenticated hello.
    if serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
        .as_deref()
        == Some("pair_request")
    {
        return serve_pairing(socket, bridge, &text);
    }

    let hello: ClientHello = serde_json::from_str(&text)
        .map_err(|e| Error::other(format!("malformed handshake: {e}")))?;

    let (client_token, session_salt) = match bridge.verify_hello(&hello) {
        Ok(pair) => pair,
        Err(e) => {
            let reply = serde_json::json!({
                "ok": false,
                "status": "unpaired",
                "error": e.to_string(),
            });
            let _ = socket.send(Message::text(reply.to_string()));
            return Ok(());
        }
    };
    let key = ipc::session_key(&client_token, &session_salt)?;
    socket
        .send(Message::text(
            serde_json::json!({
                "ok": true,
                "protocol": PROTOCOL_VERSION,
                "version": aurapass_core::VERSION,
                "client": hello.client,
            })
            .to_string(),
        ))
        .map_err(|e| Error::other(format!("websocket send failed: {e}")))?;

    // --- requests -------------------------------------------------------
    // Once the handshake is done the client may be idle for a long time (the
    // user simply has the browser open), so timeouts are relaxed.
    socket.get_mut().set_read_timeout(Some(Duration::from_secs(3600)))?;
    let mut requests: u64 = 0;

    loop {
        let message = match socket.read() {
            Ok(m) => m,
            Err(tungstenite::Error::Io(ref e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                continue;
            }
            Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                break;
            }
            Err(e) => return Err(Error::other(format!("websocket read failed: {e}"))),
        };

        if message.is_close() {
            break;
        }
        let Some(text) = message_text(message) else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }

        requests += 1;
        let response = match ipc::open_frame::<Request>(&key, &text) {
            Ok(request) => bridge.handle(&request),
            Err(e) => Response::error(format!("could not decrypt the request: {e}")),
        };
        let frame = ipc::seal_frame(&key, &response)?;
        socket
            .send(Message::text(frame))
            .map_err(|e| Error::other(format!("websocket write failed: {e}")))?;
    }

    // Record that this client went away.
    {
        let mut inner = bridge.inner.lock().expect("bridge mutex");
        if let Some(client) = inner.clients.iter_mut().find(|c| c.client == hello.client) {
            client.requests = client.requests.saturating_add(requests);
        }
    }
    Ok(())
}

/// First contact from a browser that has no secret yet: queue an approval
/// prompt for the user and hold this connection open until they answer.
fn serve_pairing(
    mut socket: WebSocket<TcpStream>,
    bridge: Arc<Bridge>,
    text: &str,
) -> Result<()> {
    let message: PairRequestMessage = serde_json::from_str(text)
        .map_err(|e| Error::other(format!("malformed pairing request: {e}")))?;

    let reply = if message.protocol != PROTOCOL_VERSION {
        serde_json::json!({
            "ok": false,
            "status": "error",
            "error": format!(
                "this AuraPass speaks protocol {PROTOCOL_VERSION}, the extension speaks {}",
                message.protocol
            ),
        })
    } else {
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let mut inner = bridge.inner.lock().expect("bridge mutex");
            inner.pair_waiters.insert(id.clone(), tx);
            inner.pairs.push_back(PairPrompt {
                id: id.clone(),
                client_id: message.client_id.clone(),
                client: message.client.clone(),
                name: message.name.clone(),
            });
        }
        let _ = socket.send(Message::text(
            serde_json::json!({ "ok": true, "status": "pending", "id": id }).to_string(),
        ));

        match rx.recv_timeout(Duration::from_secs(PAIR_TIMEOUT_SECS)) {
            Ok(Some(token)) => serde_json::json!({
                "ok": true,
                "status": "paired",
                "token": token,
                "name": message.name,
                "client": message.client,
            }),
            Ok(None) => serde_json::json!({
                "ok": false,
                "status": "denied",
                "error": "The connection request was declined in AuraPass.",
            }),
            Err(_) => {
                {
                    let mut inner = bridge.inner.lock().expect("bridge mutex");
                    inner.pairs.retain(|p| p.id != id);
                    inner.pair_waiters.remove(&id);
                }
                serde_json::json!({
                    "ok": false,
                    "status": "timeout",
                    "error": "AuraPass did not answer the connection request.",
                })
            }
        }
    };

    socket
        .send(Message::text(reply.to_string()))
        .map_err(|e| Error::other(format!("websocket send failed: {e}")))?;
    Ok(())
}

fn message_text(message: Message) -> Option<String> {
    match message {
        Message::Text(t) => Some(t.to_string()),
        Message::Binary(b) => String::from_utf8(b.to_vec()).ok(),
        _ => None,
    }
}

/// Convenience used by the GUI: does an item exist and is it fillable?
pub fn fillable_summaries(vault: &UnlockedVault, url: &str) -> Vec<ItemSummary> {
    vault
        .find_for_url(url)
        .into_iter()
        .filter_map(|id| vault.item(id))
        .filter(|i| ipc::is_fillable(i.kind))
        .map(ItemSummary::from)
        .collect()
}

/// Look up an item by prefix of its id, for command-line convenience.
pub fn resolve_item(vault: &UnlockedVault, needle: &str) -> Result<Uuid> {
    let needle = needle.trim();
    if needle.is_empty() {
        return Err(Error::other("no item specified"));
    }
    if let Ok(id) = Uuid::parse_str(needle)
        && vault.item(id).is_some()
    {
        return Ok(id);
    }
    let lower = needle.to_lowercase();
    let mut exact: Vec<Uuid> = Vec::new();
    let mut partial: Vec<Uuid> = Vec::new();
    for item in vault.data.items.iter() {
        if item.title.to_lowercase() == lower {
            exact.push(item.id);
        } else if item.title.to_lowercase().contains(&lower)
            || item.id.to_string().starts_with(needle)
        {
            partial.push(item.id);
        }
    }
    match (exact.len(), partial.len()) {
        (1, _) => Ok(exact[0]),
        (0, 1) => Ok(partial[0]),
        (0, 0) => Err(Error::ItemNotFound(needle.to_string())),
        (_, n) => Err(Error::other(format!(
            "“{needle}” matches {n} items; use the full id from `aurapass list`"
        ))),
    }
}
