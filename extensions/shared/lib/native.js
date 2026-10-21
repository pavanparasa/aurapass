//! Firefox native-messaging transport.
//!
//! Firefox 153+ applies HTTPS-Only and Local Network Access rules to WebSocket
//! connections from extensions, so `ws://127.0.0.1:8974` is silently upgraded
//! to `wss://` and never reaches AuraPass. Chrome does not do that, which is
//! why the same extension worked there and appeared to hang in Firefox.
//!
//! Instead of fighting those browser policies, Firefox talks to a small native
//! host installed by the AuraPass package. The host relays the same sealed
//! frames to the desktop bridge. This is the same pattern KeePassXC and Enpass
//! use: the extension never opens a TCP connection itself.
//!
//! A [`NativeSocket`] deliberately looks like the small part of the WebSocket
//! API the bridge uses (`addEventListener`, `send`, `close`, `readyState`).
//! If the native host is not installed, it falls back to a normal WebSocket so
//! unpacked installations and older Firefox versions keep working.

import { api } from "./ext.js";

/** Name from the native-messaging manifest installed by the .deb. */
export const HOST_NAME = "aurapass_bridge";

const CONNECT_TIMEOUT_MS = 4000;

/** A WebSocket-shaped wrapper around `runtime.connectNative`. */
export class NativeSocket {
  /** @param {string} url The bridge URL, used only for the port and fallback. */
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.binaryType = "arraybuffer";
    this.listeners = new Map();
    this.port = null;
    this.fallback = null;
    this.closed = false;
    this.timer = setTimeout(() => {
      if (this.readyState === 0) this._fallback("The AuraPass native host did not start.");
    }, CONNECT_TIMEOUT_MS);
    this._openNative();
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(listener);
  }

  send(data) {
    if (this.readyState !== 1) {
      throw new Error("AuraPass is not connected.");
    }
    if (this.port) {
      this.port.postMessage({ type: "frame", data: String(data) });
    } else if (this.fallback) {
      this.fallback.send(data);
    }
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.readyState = 3;
    clearTimeout(this.timer);
    this._closeNative();
    const socket = this.fallback;
    this.fallback = null;
    if (socket) {
      try { socket.close(); } catch { /* already gone */ }
    }
  }

  // --------------------------------------------------------------- internal

  _emit(type, event = {}) {
    for (const listener of this.listeners.get(type) || []) {
      try {
        listener(event);
      } catch {
        // A listener must not break delivery to the other listeners.
      }
    }
  }

  _port() {
    try {
      const port = Number(new URL(this.url).port);
      return Number.isFinite(port) && port > 0 ? port : 8974;
    } catch {
      return 8974;
    }
  }

  _openNative() {
    let port;
    try {
      port = api.runtime.connectNative(HOST_NAME);
    } catch {
      this._fallback();
      return;
    }
    this.port = port;

    port.onMessage.addListener((message) => {
      if (this.port !== port || this.closed) return;
      if (!message || typeof message !== "object") return;
      switch (message.type) {
        case "ready":
          if (this.readyState === 0) {
            clearTimeout(this.timer);
            this.readyState = 1;
            this._emit("open");
          }
          break;
        case "frame":
          this._emit("message", { data: message.data });
          break;
        case "error":
          if (this.readyState === 0) this._fallback(message.message);
          else this._fail(message.message || "The AuraPass native host failed.");
          break;
        case "close":
          if (this.readyState === 0) this._fallback(message.reason);
          else this._closeFromHost(message.code, message.reason);
          break;
        default:
          break;
      }
    });

    port.onDisconnect.addListener(() => {
      if (this.port !== port || this.closed) return;
      const message = api.runtime.lastError && api.runtime.lastError.message;
      if (this.readyState === 0) this._fallback(message);
      else this._closeFromHost(1006, message || "The AuraPass native host stopped.");
    });

    try {
      port.postMessage({ type: "connect", port: this._port() });
    } catch {
      this._fallback();
    }
  }

  _fallback(nativeMessage) {
    if (this.fallback || this.closed) return;
    clearTimeout(this.timer);
    this._closeNative();

    let socket;
    try {
      socket = new WebSocket(this.url);
    } catch (error) {
      this._fail(
        (nativeMessage ? `${nativeMessage} ` : "")
        + (error && error.message ? error.message : "AuraPass is not running."),
      );
      return;
    }
    this.fallback = socket;
    socket.binaryType = this.binaryType;

    socket.addEventListener("open", () => {
      if (this.closed) return;
      this.readyState = 1;
      this._emit("open");
    });
    socket.addEventListener("message", (event) => {
      if (!this.closed) this._emit("message", event);
    });
    socket.addEventListener("error", () => {
      if (!this.closed) this._emit("error", { message: "Could not reach AuraPass." });
    });
    socket.addEventListener("close", (event) => {
      if (this.closed) return;
      this.closed = true;
      this.readyState = 3;
      this._emit("close", { code: event.code, reason: event.reason });
    });
  }

  _fail(message) {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.timer);
    this.readyState = 3;
    this._closeNative();
    const socket = this.fallback;
    this.fallback = null;
    if (socket) {
      try { socket.close(); } catch { /* already gone */ }
    }
    this._emit("error", { message });
    this._emit("close", { code: 1006, reason: message });
  }

  _closeFromHost(code, reason) {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.timer);
    this.readyState = 3;
    this._closeNative();
    this._emit("close", { code: code || 1006, reason: reason || "" });
  }

  _closeNative() {
    const port = this.port;
    this.port = null;
    if (port) {
      try { port.disconnect(); } catch { /* already gone */ }
    }
  }
}
