//! The pairing handshake: an unknown browser asks, the user answers in the
//! app, and the issued secret is the only thing that authenticates afterwards.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aurapass_bridge::{Bridge, start};
use aurapass_core::config::BridgeConfig;
use aurapass_core::ipc::{self, ClientHello, PROTOCOL_VERSION};
use serde_json::{Value, json};
use tungstenite::{Message, connect};

/// Read one text frame, failing the test instead of hanging forever.
fn read_json(socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>) -> Value {
    socket
        .read()
        .expect("a reply")
        .into_text()
        .expect("a text frame")
        .parse()
        .expect("valid json")
}

#[test]
fn pairing_issues_a_token_that_authenticates() {
    let mut config = BridgeConfig::default();
    config.token.clear();
    let bridge = Arc::new(Bridge::new(config));
    let running = start(bridge.clone(), 0).expect("start the bridge");
    let url = format!("ws://127.0.0.1:{}/", running.port);

    // --- a browser with no secret asks to connect -----------------------
    let (mut socket, _) = connect(&url).expect("connect");
    socket
        .send(Message::text(
            json!({
                "type": "pair_request",
                "protocol": PROTOCOL_VERSION,
                "client": "test-extension/1.0.0",
                "client_id": "client-1",
                "name": "Test Browser",
            })
            .to_string(),
        ))
        .expect("send");

    let pending = read_json(&mut socket);
    assert_eq!(pending["status"], "pending", "{pending}");

    // --- the app shows the dialog and the user clicks Allow -------------
    let prompt = {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(prompt) = bridge.pending_pairs().into_iter().next() {
                break prompt;
            }
            assert!(Instant::now() < deadline, "the request never reached the app");
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    assert_eq!(prompt.name, "Test Browser");
    assert_eq!(prompt.client_id, "client-1");

    let issued = bridge
        .resolve_pair(&prompt.id, true)
        .expect("approval issues a secret");
    assert!(!issued.token.trim().is_empty());
    assert_eq!(bridge.paired_browsers().len(), 1);

    let reply = read_json(&mut socket);
    assert_eq!(reply["status"], "paired", "{reply}");
    assert_eq!(reply["token"], issued.token.as_str());

    // --- the issued secret opens a normal session -----------------------
    let (mut authed, _) = connect(&url).expect("connect again");
    let salt = aurapass_core::crypto::random_bytes::<32>();
    let hello = ClientHello {
        protocol: PROTOCOL_VERSION,
        client: "test-extension/1.0.0".into(),
        salt: aurapass_core::util::b64url_encode(salt),
        proof: ipc::hello_proof(&issued.token, &salt, PROTOCOL_VERSION).expect("proof"),
    };
    authed
        .send(Message::text(serde_json::to_string(&hello).expect("json")))
        .expect("send hello");
    let welcome = read_json(&mut authed);
    assert_eq!(welcome["ok"], true, "{welcome}");

    // And the session really is encrypted with that secret.
    let key = ipc::session_key(&issued.token, &salt).expect("session key");
    let frame = ipc::seal_frame(&key, &aurapass_core::ipc::Request::Status).expect("seal");
    authed.send(Message::text(frame)).expect("send request");
    let sealed = authed.read().expect("reply").into_text().expect("text");
    let response: aurapass_core::ipc::Response =
        ipc::open_frame(&key, &sealed).expect("decrypt");
    assert!(
        matches!(response, aurapass_core::ipc::Response::Ok { .. }),
        "{response:?}"
    );
}

#[test]
fn a_declined_request_issues_nothing() {
    let mut config = BridgeConfig::default();
    config.token.clear();
    let bridge = Arc::new(Bridge::new(config));
    let running = start(bridge.clone(), 0).expect("start the bridge");
    let url = format!("ws://127.0.0.1:{}/", running.port);

    let (mut socket, _) = connect(&url).expect("connect");
    socket
        .send(Message::text(
            json!({
                "type": "pair_request",
                "protocol": PROTOCOL_VERSION,
                "client": "test-extension/1.0.0",
                "client_id": "client-2",
                "name": "Declined Browser",
            })
            .to_string(),
        ))
        .expect("send");
    assert_eq!(read_json(&mut socket)["status"], "pending");

    let prompt = {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(prompt) = bridge.pending_pairs().into_iter().next() {
                break prompt;
            }
            assert!(Instant::now() < deadline, "the request never reached the app");
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    assert!(bridge.resolve_pair(&prompt.id, false).is_none());
    let reply = read_json(&mut socket);
    assert_eq!(reply["status"], "denied", "{reply}");
    assert!(bridge.paired_browsers().is_empty());
}
