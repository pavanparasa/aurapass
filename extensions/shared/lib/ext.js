//! Small helpers shared by every extension page.
//!
//! Chrome and Firefox disagree about the WebExtension namespace (`chrome` vs
//! `browser`) and about whether APIs return promises or take callbacks. Rather
//! than branch at every call site, everything goes through [`api`] and
//! [`promisify`], which work in both browsers and in both API styles.

/** The WebExtension namespace, whichever one this browser exposes. */
export const api = globalThis.browser ?? globalThis.chrome;

/** Where the pairing token, port and preferences live. */
export const STORAGE_DEFAULTS = Object.freeze({
  /** Secret issued by the app when the user approved this browser. */
  token: "",
  /** Stable id for this browser installation, generated on first use. */
  clientId: "",
  /** Friendly name shown in the app's approval dialog. */
  pairedName: "",
  port: 8974,
  autofill: true,
  showBadge: true,
  savePrompt: true,
  injectInFrames: true,
  fillOnPageLoad: false,
  /** "system", "light" or "dark" — the extension follows the app's choice. */
  appearance: "system",
  /** Whether the user made AuraPass their default password manager. */
  defaultManager: false,
});

/** Bridge port range to probe, mirroring `aurapass_bridge::bind_local`. */
export const PORT_SPAN = 9;

/**
 * Call a callback-style WebExtension API as a promise.
 *
 * Works for `chrome.*` (which needs the callback) and for `browser.*` (which
 * accepts one too). `lastError` is read synchronously, as required.
 *
 * @param {Function} fn
 * @param {any} thisArg
 * @param {...any} args
 */
export function promisify(fn, thisArg, ...args) {
  return new Promise((resolve, reject) => {
    try {
      fn.call(thisArg, ...args, (result) => {
        const error = api.runtime?.lastError;
        if (error) reject(new Error(error.message));
        else resolve(result);
      });
    } catch (error) {
      reject(error);
    }
  });
}

/** Read settings, filling in defaults for anything not yet stored. */
export async function getSettings() {
  const stored = await promisify(api.storage.local.get, api.storage.local, { ...STORAGE_DEFAULTS });
  return { ...STORAGE_DEFAULTS, ...(stored || {}) };
}

/** Merge a patch into the stored settings and return the whole set. */
export async function saveSettings(patch) {
  await promisify(api.storage.local.set, api.storage.local, patch);
  return getSettings();
}

/** Send a message to the background service worker and await its reply. */
export function sendToBackground(message) {
  return promisify(api.runtime.sendMessage, api.runtime, message);
}

/** Ask a specific tab's content script something. */
export function sendToTab(tabId, message) {
  return promisify(api.tabs.sendMessage, api.tabs, tabId, message);
}

/** The active tab in the current window, or null. */
export async function activeTab() {
  const tabs = await promisify(api.tabs.query, api.tabs, { active: true, currentWindow: true });
  return tabs && tabs.length ? tabs[0] : null;
}

/** Escape text before putting it in HTML. */
export function escapeHtml(text) {
  return String(text ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** The host of a URL, or an empty string. */
export function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

/** A friendly name for the browser this extension is running in. */
export function browserName() {
  const ua = navigator.userAgent;
  if (/Edg\//.test(ua)) return "Edge";
  if (/OPR\//.test(ua)) return "Opera";
  if (/Firefox\//.test(ua)) return "Firefox";
  if (/Chrome\//.test(ua)) return "Chrome";
  return "Browser";
}

/** A stable id for this browser installation, created on first use. */
export async function ensureClientId() {
  const settings = await getSettings();
  if (settings.clientId) return settings.clientId;
  const id = crypto.randomUUID();
  await saveSettings({ clientId: id, pairedName: browserName() });
  return id;
}

/** True when the user's chosen appearance resolves to dark. */
export function prefersDark(appearance) {
  if (appearance === "dark") return true;
  if (appearance === "light") return false;
  return globalThis.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}

/** A short, friendly description of a bridge error. */
export function describeError(error) {
  if (!error) return "Something went wrong.";
  if (typeof error === "string") return error;
  const code = error.code;
  const message = error.message || String(error);
  switch (code) {
    case "no-token":
      return "This browser is not connected to AuraPass yet. Start the desktop app, then click Connect and approve the request.";
    case "unpaired":
      return "AuraPass no longer recognises this browser. Click Connect to approve it again.";
    case "offline":
      return "AuraPass is not running. Start the desktop app or `aurapass-bridge`.";
    case "pairing":
      return message || "AuraPass declined the connection request.";
    case "locked":
      return "The vault is locked. Unlock AuraPass on the desktop.";
    case "timeout":
      return "AuraPass did not answer in time.";
    default:
      return message;
  }
}

/** Copy text to the clipboard, returning whether it worked. */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fall back to the old execCommand path for pages without clipboard access.
    try {
      const area = document.createElement("textarea");
      area.value = text;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand("copy");
      area.remove();
      return ok;
    } catch {
      return false;
    }
  }
}
