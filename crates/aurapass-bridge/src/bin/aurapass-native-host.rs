//! `aurapass-native-host` — the Firefox native-messaging relay.
//!
//! Firefox 153+ upgrades `ws://` connections from extensions to `wss://` and
//! applies Local Network Access rules to them, so a browser extension cannot
//! reliably reach a plain loopback WebSocket any more. Chromium is unaffected.
//!
//! This tiny host is started by Firefox (via the manifest installed in
//! `/usr/lib/mozilla/native-messaging-hosts/`) and speaks the browser's
//! length-prefixed native-messaging protocol on stdin/stdout. On the other side
//! it connects to the same local AuraPass bridge the Chromium extension uses
//! and relays the already-encrypted frames verbatim. No vault data is parsed
//! here, and the pairing/encryption protocol is unchanged.
//!
//! The extension drives the port: it sends `{"type":"connect","port":N}`,
//! then `{"type":"frame","data":"..."}` for every sealed frame. The host
//! answers with `ready`, `frame`, `error` and `close` messages.

use std::io::{self, Read, Write};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message};

const DEFAULT_PORT: u16 = aurapass_core::DEFAULT_BRIDGE_PORT;

/// Largest native message Firefox accepts in either direction.
const MAX_NATIVE_MESSAGE: usize = 1024 * 1024;

enum Relay {
    Frame(String),
    Close,
}

fn main() {
    if let Err(error) = run() {
        // stdout belongs to the native-messaging protocol. Diagnostics go to
        // stderr, where Firefox's browser console can show them.
        eprintln!("aurapass-native-host: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let first = match read_native(&mut input)? {
        Some(message) => message,
        None => return Ok(()),
    };
    drop(input);

    let port = first
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(DEFAULT_PORT);

    let url = format!("ws://127.0.0.1:{port}");
    let (mut socket, _) = match connect(&url) {
        Ok(pair) => pair,
        Err(error) => {
            write_native(&json!({
                "type": "error",
                "message": format!("AuraPass is not running on port {port}: {error}"),
            }))?;
            return Ok(());
        }
    };

    // A short timeout lets the relay notice a frame from the browser and a
    // frame from AuraPass without needing a second socket or an async runtime.
    if let MaybeTlsStream::Plain(stream) = socket.get_mut() {
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .context("could not set the bridge socket timeout")?;
    }

    write_native(&json!({ "type": "ready", "port": port }))?;

    // The browser writes to the host's stdin. Read it on its own thread so the
    // main loop can also poll the bridge socket.
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("aurapass-native-stdin".into())
        .spawn(move || {
            let stdin = io::stdin();
            let mut input = stdin.lock();
            loop {
                match read_native(&mut input) {
                    Ok(Some(message)) => match message.get("type").and_then(Value::as_str) {
                        Some("frame") => {
                            let Some(data) = message.get("data").and_then(Value::as_str) else {
                                continue;
                            };
                            if tx.send(Relay::Frame(data.to_string())).is_err() {
                                break;
                            }
                        }
                        Some("close") => {
                            let _ = tx.send(Relay::Close);
                            break;
                        }
                        _ => {}
                    },
                    Ok(None) => {
                        let _ = tx.send(Relay::Close);
                        break;
                    }
                    Err(_) => {
                        let _ = tx.send(Relay::Close);
                        break;
                    }
                }
            }
        })
        .context("could not start the native-messaging reader")?;

    let mut output = io::stdout().lock();
    loop {
        loop {
            match rx.try_recv() {
                Ok(Relay::Frame(text)) => {
                    socket
                        .send(Message::text(text))
                        .context("could not forward a browser frame")?;
                }
                Ok(Relay::Close) => {
                    let _ = socket.close(None);
                    let _ = socket.flush();
                    return Ok(());
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    let _ = socket.close(None);
                    let _ = socket.flush();
                    return Ok(());
                }
            }
        }

        match socket.read() {
            Ok(Message::Text(text)) => {
                write_frame(&mut output, &text)?;
            }
            Ok(Message::Binary(bytes)) => {
                if let Ok(text) = String::from_utf8(bytes.to_vec()) {
                    write_frame(&mut output, &text)?;
                }
            }
            Ok(Message::Ping(payload)) => {
                let _ = socket.send(Message::Pong(payload));
            }
            Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => {}
            Ok(Message::Close(_)) => {
                write_close(&mut output, 1006, "AuraPass closed the connection.")?;
                return Ok(());
            }
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                write_close(&mut output, 1006, "AuraPass closed the connection.")?;
                return Ok(());
            }
            Err(error) => {
                let message = format!("AuraPass bridge error: {error}");
                write_close(&mut output, 1006, &message)?;
                return Ok(());
            }
        }
    }
}

fn read_native<R: Read>(input: &mut R) -> Result<Option<Value>> {
    let mut length = [0u8; 4];
    match input.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_ne_bytes(length) as usize;
    if length == 0 || length > MAX_NATIVE_MESSAGE {
        anyhow::bail!("native message has an invalid length ({length})");
    }
    let mut body = vec![0u8; length];
    input.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

fn write_frame<W: Write>(output: &mut W, text: &str) -> Result<()> {
    write_native_to(output, &json!({ "type": "frame", "data": text }))
}

fn write_close<W: Write>(output: &mut W, code: u16, reason: &str) -> Result<()> {
    write_native_to(
        output,
        &json!({ "type": "close", "code": code, "reason": reason }),
    )
}

fn write_native(message: &Value) -> Result<()> {
    let mut output = io::stdout().lock();
    write_native_to(&mut output, message)
}

fn write_native_to<W: Write>(output: &mut W, message: &Value) -> Result<()> {
    let body = serde_json::to_vec(message)?;
    if body.len() > MAX_NATIVE_MESSAGE {
        anyhow::bail!("native message is too large ({} bytes)", body.len());
    }
    output.write_all(&(body.len() as u32).to_ne_bytes())?;
    output.write_all(&body)?;
    output.flush()?;
    Ok(())
}
