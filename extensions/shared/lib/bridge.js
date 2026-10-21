//! WebSocket client for the AuraPass browser bridge.
//!
//! This is the half of the extension that talks to the desktop app. It performs
//! the pairing handshake, keeps a live encrypted session, and exposes a small
//! promise-based API (`client.status()`, `client.item(id)`, …) on top of the
//! sealed request/response protocol described in `aurapass_core::ipc`.
//!
//! It is deliberately transport-agnostic about *how* the token was obtained:
//! callers pass a token string, and everything else (salt, proof, session key,
//! frame sealing) happens here. That keeps the popup, the service worker and
//! the content script from each re-implementing the crypto.
//!
//! Usage:
//!
//! ```js
//! import { AuraPassBridge } from "./lib/bridge.js";
//!
//! const bridge = new AuraPassBridge({ token, client: "chromium/1.0.0" });
//! await bridge.connect();
//! const status = await bridge.status();
//! ```

import {
  PROTOCOL_VERSION,
  b64urlEncode,
  b64urlDecode,
  helloProof,
  openFrame,
  randomBytes,
  sealFrame,
  sessionKey,
} from "./crypto.js";

/** Default port the desktop app and `aurapass-bridge` prefer. */
export const DEFAULT_PORT = 8974;

/** Ports tried if the default is busy (mirrors `aurapass_bridge::bind_local`). */
export const PORT_SPAN = 9;

/** How long to wait for the pairing handshake acknowledgement. */
export const HANDSHAKE_TIMEOUT_MS = 8000;

/** How long the initial loopback socket may take to open. */
export const CONNECT_TIMEOUT_MS = 5000;

/** How long to wait for a single request/response round trip. */
export const REQUEST_TIMEOUT_MS = 15000;

/** How long a connection request may sit in front of the user in the app. */
export const PAIR_TIMEOUT_MS = 185000;

/** Thrown for any bridge-level failure, with a message fit for the popup. */
export class BridgeError extends Error {
  constructor(message, code = "bridge") {
    super(message);
    this.name = "BridgeError";
    this.code = code;
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Turn an array-of-strings reason into a friendly message. */
function describe(event, fallback) {
  if (event && typeof event === "object" && "message" in event && event.message) {
    return String(event.message);
  }
  return fallback;
}

/**
 * A single connection to AuraPass.
 *
 * The class is intentionally tolerant of reconnects: [`request`] reopens the
 * socket and re-runs the handshake if the previous one dropped, as long as a
 * token is configured.
 */
export class AuraPassBridge {
  /**
   * @param {object} options
   * @param {string} options.token Pairing token copied from the desktop app.
   * @param {string} [options.client] Client identifier sent in the handshake.
   * @param {string} [options.host] Host, defaults to `127.0.0.1`.
   * @param {number} [options.port] Preferred port, defaults to {@link DEFAULT_PORT}.
   * @param {boolean} [options.autoReconnect] Retry once on a dropped socket.
   * @param {(url: string) => WebSocket} [options.createSocket] Transport
   *   factory. Firefox passes one that uses native messaging, so the browser
   *   never opens a TCP connection to localhost.
   */
  constructor(options = {}) {
    this.token = options.token || "";
    this.client = options.client || `aurapass-extension/${PROTOCOL_VERSION}`;
    this.host = options.host || "127.0.0.1";
    this.port = options.port || DEFAULT_PORT;
    this.autoReconnect = options.autoReconnect !== false;
    this.createSocket = typeof options.createSocket === "function"
      ? options.createSocket
      : (url) => new WebSocket(url);

    /** @type {WebSocket | null} */
    this.socket = null;
    /** @type {Uint8Array | null} */
    this.key = null;
    this.connectedPort = null;
    /** Requests waiting for a reply, oldest first. */
    this.pending = [];
    this.status = null;
    /** In-flight connection attempt, so concurrent calls share one socket. */
    this._connectPromise = null;
  }

  /** Whether a handshake has completed and a session key is available. */
  get isConnected() {
    return this.key !== null && this.socket !== null && this.socket.readyState === 1;
  }

  /** The `ws://` URL for a port. */
  url(port = this.port) {
    return `ws://${this.host}:${port}`;
  }

  /**
   * Open the socket and authenticate. Resolves with the status payload.
   *
   * @param {object} [opts]
   * @param {boolean} [opts.scan] Try the default port and the next few.
   */
  async connect(opts = {}) {
    if (this.isConnected) return this.status;
    // Two requests can arrive while the socket is still handshaking (a page
    // report and a save click, for example). Each one used to open its own
    // socket and overwrite `this.key`, so replies from the losing socket failed
    // authentication. Share one attempt instead.
    if (this._connectPromise) return this._connectPromise;
    const attempt = this._connect(opts);
    this._connectPromise = attempt;
    try {
      return await attempt;
    } finally {
      if (this._connectPromise === attempt) this._connectPromise = null;
    }
  }

  async _connect(opts = {}) {
    if (!this.token || !this.token.trim()) {
      throw new BridgeError(
        "This browser is not connected to AuraPass yet.",
        "no-token",
      );
    }
    if (this.isConnected) return this.status;

    const ports = opts.scan === false
      ? [this.port]
      : Array.from({ length: PORT_SPAN }, (_, i) => this.port + i);

    let lastError = null;
    for (const port of ports) {
      try {
        this.status = await this._connectTo(port);
        this.connectedPort = port;
        return this.status;
      } catch (error) {
        lastError = error;
        this._teardown();
      }
    }
    throw lastError || new BridgeError("Could not reach AuraPass.");
  }

  /** Establish one session on one port. */
  _connectTo(port) {
    return new Promise((resolve, reject) => {
      let socket;
      try {
        socket = this.createSocket(this.url(port));
      } catch (error) {
        reject(new BridgeError(describe(error, "AuraPass is not running."), "offline"));
        return;
      }
      socket.binaryType = "arraybuffer";

      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        try { socket.close(); } catch { /* ignore */ }
        reject(new BridgeError("AuraPass did not answer the pairing handshake.", "timeout"));
      }, HANDSHAKE_TIMEOUT_MS);

      const fail = (reason, code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { socket.close(); } catch { /* ignore */ }
        reject(new BridgeError(reason, code));
      };

      socket.addEventListener("error", (event) => {
        fail(describe(event, "Could not connect to AuraPass."), "offline");
      });
      socket.addEventListener("close", () => {
        // If the handshake already finished this is a normal drop; the next
        // request will reconnect.
        if (!settled) fail("AuraPass closed the connection.", "offline");
        else this._onDisconnect();
      });
      socket.addEventListener("message", async (event) => {
        if (!settled) {
          let ack;
          try {
            ack = JSON.parse(typeof event.data === "string" ? event.data : decoder.decode(event.data));
          } catch {
            fail("AuraPass sent a malformed handshake reply.", "protocol");
            return;
          }
          if (!ack.ok) {
            // "unpaired" means the app no longer recognises the stored
            // secret (reinstall, config reset, restored profile). It is
            // distinct from a request the user declined, which must not be
            // retried automatically.
            fail(
              ack.error || "Pairing failed.",
              ack.status === "unpaired" ? "unpaired" : "pairing",
            );
            return;
          }
          settled = true;
          clearTimeout(timer);
          this.socket = socket;
          resolve(ack);
          return;
        }
        this._onFrame(event.data);
      });

      // Send the plaintext hello as soon as the socket is open.
      socket.addEventListener("open", async () => {
        try {
          const salt = randomBytes(32);
          const proof = await helloProof(this.token, salt, PROTOCOL_VERSION);
          this.key = await sessionKey(this.token, salt);
          socket.send(JSON.stringify({
            protocol: PROTOCOL_VERSION,
            client: this.client,
            salt: b64urlEncode(salt),
            proof,
          }));
        } catch (error) {
          fail(describe(error, "Could not build the pairing handshake."), "crypto");
        }
      });
    });
  }

  /**
   * Ask the desktop app for access.
   *
   * The app shows the user a dialog naming this browser; approving it issues a
   * secret that is returned here. Nothing is typed or copied by hand.
   *
   * @param {object} options
   * @param {string} options.clientId Stable id this browser generated once.
   * @param {string} options.name Friendly name shown in the app's dialog.
   * @returns {Promise<string>} the issued secret
   */
  async pair({ clientId, name }) {
    const ports = Array.from({ length: PORT_SPAN }, (_, i) => this.port + i);
    let lastError = null;
    for (const port of ports) {
      try {
        return await this._pairOn(port, clientId, name);
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new BridgeError("AuraPass is not running.", "offline");
  }

  /** One connection request on one port. */
  _pairOn(port, clientId, name) {
    return new Promise((resolve, reject) => {
      let socket;
      try {
        socket = this.createSocket(this.url(port));
      } catch (error) {
        reject(new BridgeError(describe(error, "AuraPass is not running."), "offline"));
        return;
      }

      let settled = false;
      let timer = null;
      const fail = (reason, code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { socket.close(); } catch { /* ignore */ }
        reject(new BridgeError(reason, code));
      };

      // The long timeout is for the user's approval in the desktop app, and
      // only makes sense after the socket is open. A blocked loopback socket
      // must fail quickly so the next candidate port gets a chance.
      timer = setTimeout(() => {
        fail("Could not reach AuraPass on this port.", "offline");
      }, CONNECT_TIMEOUT_MS);

      socket.addEventListener("error", () => {
        fail("Could not reach AuraPass. Is the desktop app running?", "offline");
      });
      socket.addEventListener("close", () => {
        if (!settled) fail("AuraPass closed the connection before approving it.", "pairing");
      });
      socket.addEventListener("message", (event) => {
        let reply;
        try {
          reply = JSON.parse(typeof event.data === "string" ? event.data : decoder.decode(event.data));
        } catch {
          fail("AuraPass sent a malformed reply.", "protocol");
          return;
        }
        if (reply.ok && reply.status === "paired" && reply.token) {
          settled = true;
          clearTimeout(timer);
          try { socket.close(); } catch { /* ignore */ }
          resolve(reply.token);
          return;
        }
        if (reply.status === "pending") return;
        fail(reply.error || "The connection request was declined in AuraPass.", "pairing");
      });
      socket.addEventListener("open", () => {
        clearTimeout(timer);
        timer = setTimeout(() => {
          fail("AuraPass did not answer the connection request.", "timeout");
        }, PAIR_TIMEOUT_MS);
        socket.send(JSON.stringify({
          type: "pair_request",
          protocol: PROTOCOL_VERSION,
          client: this.client,
          client_id: clientId,
          name,
        }));
      });
    });
  }

  /** Force a fresh session, e.g. after approval. */
  async reconnect() {
    this._teardown();
    return this.connect();
  }

  /** Close the socket and forget the session key. */
  disconnect() {
    this._teardown();
  }

  _teardown() {
    const socket = this.socket;
    this.socket = null;
    this.key = null;
    this.connectedPort = null;
    if (socket) {
      try { socket.close(); } catch { /* ignore */ }
    }
    for (const entry of this.pending.splice(0)) {
      clearTimeout(entry.timer);
      entry.reject(new BridgeError("The connection to AuraPass closed.", "offline"));
    }
  }

  _onDisconnect() {
    this.key = null;
    this.socket = null;
    this.connectedPort = null;
    // Pending work cannot complete on a dead socket.
    for (const entry of this.pending.splice(0)) {
      clearTimeout(entry.timer);
      entry.reject(new BridgeError("The connection to AuraPass closed.", "offline"));
    }
  }

  /** Decrypt and route one server frame to the oldest pending request. */
  _onFrame(data) {
    const entry = this.pending.shift();
    if (!entry) return;
    clearTimeout(entry.timer);
    let response;
    try {
      const text = typeof data === "string" ? data : decoder.decode(data);
      response = openFrame(this.key, text);
    } catch (error) {
      entry.reject(new BridgeError(describe(error, "AuraPass sent an unreadable reply."), "crypto"));
      return;
    }
    entry.resolve(response);
  }

  /**
   * Send one request and resolve with the *payload* when the reply is `ok`.
   *
   * `locked`, `error` and `busy` replies are turned into rejected promises so
   * callers can just `try { … } catch`.
   *
   * @param {object} request Tagged request, e.g. `{ type: "ping" }`.
   * @returns {Promise<any>} the `data` from an `ok` response.
   */
  async request(request) {
    if (!this.isConnected) {
      await this.connect();
    }
    const key = this.key;
    const response = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.pending.indexOf(entry);
        if (index >= 0) this.pending.splice(index, 1);
        reject(new BridgeError("AuraPass did not answer in time.", "timeout"));
      }, REQUEST_TIMEOUT_MS);
      const entry = { resolve, reject, timer };
      this.pending.push(entry);
      try {
        this.socket.send(sealFrame(key, request));
      } catch (error) {
        clearTimeout(timer);
        const index = this.pending.indexOf(entry);
        if (index >= 0) this.pending.splice(index, 1);
        reject(new BridgeError(describe(error, "Could not send the request."), "offline"));
      }
    });
    return unwrap(response);
  }

  // ------------------------------------------------------- typed requests

  /** Liveness check; resolves with `{ pong, version }`. */
  ping() {
    return this.request({ type: "ping" });
  }

  /** Lock/unlock state and vault name. */
  async getStatus() {
    this.status = await this.request({ type: "status" });
    return this.status;
  }

  /** Lock the vault on the desktop. */
  lock() {
    return this.request({ type: "lock" });
  }

  /**
   * Unlock the vault with the master password.
   *
   * Only works when the desktop app is running and configured to allow it;
   * otherwise the bridge replies `locked`/`error`.
   */
  unlock(password) {
    return this.request({ type: "unlock", password });
  }

  /** Credentials that match a page URL. */
  async matchUrl(url) {
    const data = await this.request({ type: "match_url", url });
    return data.items || [];
  }

  /** Free-text search. */
  async search(query, limit = 20) {
    const data = await this.request({ type: "search", query, limit });
    return data.items || [];
  }

  /** Fetch one item, optionally including the password and TOTP secret. */
  item(id, includeSecrets = false) {
    return this.request({ type: "item", id, include_secrets: includeSecrets });
  }

  /** The current one-time code for an item. */
  totp(id) {
    return this.request({ type: "totp", id });
  }

  /** Ask the desktop app to generate a password. */
  generate(options = {}) {
    return this.request({
      type: "generate",
      length: options.length ?? 20,
      digits: options.digits ?? true,
      symbols: options.symbols ?? true,
      uppercase: options.uppercase ?? true,
    });
  }

  /** Record that a credential was used. */
  used(id) {
    return this.request({ type: "used", id });
  }

  /** Offer to save a login the user just submitted. */
  saveLogin({ url, username, password, title }) {
    return this.request({
      type: "save_login",
      url,
      username,
      password,
      title: title ?? null,
    });
  }
}

/** Turn a bridge response into a resolved value or a rejection. */
export function unwrap(response) {
  if (!response || typeof response !== "object") {
    throw new BridgeError("AuraPass sent an empty reply.", "protocol");
  }
  switch (response.status) {
    case "ok":
      return response.data;
    case "locked":
      throw new BridgeError(response.hint || "Unlock AuraPass on the desktop.", "locked");
    case "busy":
      throw new BridgeError("AuraPass is busy; try again in a moment.", "busy");
    case "error":
      throw new BridgeError(response.message || "AuraPass reported an error.", "error");
    default:
      throw new BridgeError("AuraPass sent an unknown reply.", "protocol");
  }
}

/** True when a page URL is one the bridge should be asked about. */
export function isInjectableUrl(url) {
  if (!url) return false;
  return /^https?:\/\//i.test(url) || /^file:\/\//i.test(url);
}

/** A stable, human label for an item summary, for popup menus. */
export function labelFor(item) {
  if (!item) return "(unknown)";
  const user = item.username ? ` — ${item.username}` : "";
  return `${item.title || "(untitled)"}${user}`;
}

export { b64urlDecode, b64urlEncode, decoder, encoder };
