//! The AuraPass extension background worker.
//!
//! This is the only piece of the extension that ever sees the pairing token or
//! plaintext credentials. Pages and content scripts talk to it with
//! `runtime.sendMessage`, never to the bridge directly, so a compromised page
//! cannot read the vault even if it can talk to the extension.
//!
//! Responsibilities:
//!
//! * keep one encrypted WebSocket session to AuraPass open,
//! * answer popup/content queries (`status`, `matches`, `item`, `totp`, …),
//! * push fills into the active tab,
//! * keep the toolbar badge showing how many logins match the current page.

import { AuraPassBridge } from "./lib/bridge.js";
import { NativeSocket } from "./lib/native.js";
import {
  api,
  browserName,
  copyText,
  describeError,
  ensureClientId,
  getSettings,
  hostOf,
  promisify,
  saveSettings,
  sendToTab,
} from "./lib/ext.js";

/** Service-worker-local state; lost when the worker stops, rebuilt on demand. */
let bridge = null;
let bridgeKey = "";
let lastStatus = null;

/** tabId -> ItemSummary[] for the page currently loaded there. */
const pageMatches = new Map();

const VERSION = api.runtime.getManifest().version;
// Firefox exposes both `browser` and `chrome` now, so the presence of either
// namespace says nothing about the browser. The extension URL scheme is stable
// and is what the native-messaging transport depends on.
const BROWSER = (() => {
  try {
    return api.runtime.getURL("").startsWith("moz-extension:")
      ? "firefox"
      : "chromium";
  } catch {
    return "chromium";
  }
})();
const USE_NATIVE =
  BROWSER === "firefox" && typeof api.runtime.connectNative === "function";

// --------------------------------------------------------------- connection

/** Build (or rebuild) the bridge for the current settings. */
async function ensureBridge(force = false) {
  const settings = await getSettings();
  const key = `${settings.token}\u0000${settings.port}`;
  if (force && bridge) {
    bridge.disconnect();
    bridge = null;
    bridgeKey = "";
  }
  if (bridge && bridgeKey === key && bridge.isConnected) return bridge;
  if (bridge && bridgeKey !== key) {
    bridge.disconnect();
    bridge = null;
  }
  if (!bridge) {
    bridge = new AuraPassBridge({
      token: settings.token,
      port: settings.port,
      client: `aurapass-${BROWSER}-extension/${VERSION}`,
      autoReconnect: false,
      createSocket: USE_NATIVE ? (url) => new NativeSocket(url) : undefined,
    });
    bridgeKey = key;
  }
  return bridge;
}

/**
 * Run `body` with a connected bridge, turning any failure into a structured
 * error the popup can render.
 */
async function withBridge(body, { force = false, allowPair = false } = {}) {
  try {
    let client = await ensureBridge(force);

    // No secret yet: the user has not approved this browser. Only an explicit
    // user action may ask; background polls stay silent so a page load never
    // pops a dialog.
    if (!client.token) {
      if (!allowPair) {
        const error = new Error("This browser is not connected to AuraPass yet.");
        error.code = "no-token";
        throw error;
      }
      const clientId = await ensureClientId();
      const name = browserName();
      const token = await client.pair({ clientId, name });
      await saveSettings({ token, pairedName: name });
      client.disconnect();
      bridge = null;
      bridgeKey = "";
      client = await ensureBridge();
    }

    await client.connect();
    const value = await body(client);
    lastStatus = { connected: true, at: Date.now() };
    return { ok: true, ...value };
  } catch (error) {
    lastStatus = { connected: false, at: Date.now() };
    return failure(error);
  }
}

function failure(error) {
  return {
    ok: false,
    error: { message: describeError(error), code: (error && error.code) || "error" },
  };
}

function ok(payload) {
  return { ok: true, ...payload };
}

// -------------------------------------------------------- pending save prompts

/**
 * When a page submits a login, the content script stores the candidate here
 * *before* the page navigates. The next page in the same tab claims it and
 * shows the save banner. A page-local timer cannot do that: a classic form
 * post destroys the old document, and with it every timeout and banner.
 *
 * `storage.session` is memory-backed, extension-only and cleared when the
 * browser exits, which is the right lifetime for a plaintext password that is
 * waiting for one click. A short TTL stops stale candidates from reappearing
 * on an unrelated later page if the user navigates away.
 */
const PENDING_SAVE_KEY = "aurapass.pendingSaves";
const PENDING_SAVE_TTL_MS = 5 * 60 * 1000;
let pendingSaveFallback = new Map();

function pendingSaveArea() {
  try {
    return api.storage && api.storage.session ? api.storage.session : null;
  } catch {
    return null;
  }
}

async function readPendingSaves() {
  const area = pendingSaveArea();
  if (area) {
    try {
      const data = await promisify(area.get, area, PENDING_SAVE_KEY);
      return (data && data[PENDING_SAVE_KEY]) || {};
    } catch {
      // Fall through to the in-memory copy.
    }
  }
  return Object.fromEntries(pendingSaveFallback);
}

async function writePendingSaves(saves) {
  const area = pendingSaveArea();
  if (area) {
    try {
      await promisify(area.set, area, { [PENDING_SAVE_KEY]: saves });
      return;
    } catch {
      // Fall through to the in-memory copy.
    }
  }
  pendingSaveFallback = new Map(Object.entries(saves));
}

function prunePendingSaves(saves) {
  const now = Date.now();
  for (const [key, candidate] of Object.entries(saves)) {
    if (!candidate || !candidate.savedAt
      || now - candidate.savedAt > PENDING_SAVE_TTL_MS) {
      delete saves[key];
    }
  }
  return saves;
}

async function putPendingSave(tabId, candidate) {
  const saves = prunePendingSaves(await readPendingSaves());
  saves[String(tabId)] = { ...candidate, savedAt: Date.now() };
  await writePendingSaves(saves);
}

async function takePendingSave(tabId) {
  const saves = prunePendingSaves(await readPendingSaves());
  const key = String(tabId);
  const candidate = saves[key];
  delete saves[key];
  await writePendingSaves(saves);
  return candidate || null;
}

async function expirePendingSaves() {
  const saves = prunePendingSaves(await readPendingSaves());
  await writePendingSaves(saves);
}

async function dropPendingSave(tabId) {
  const saves = await readPendingSaves();
  if (!(String(tabId) in saves)) return;
  delete saves[String(tabId)];
  await writePendingSaves(saves);
}

// ------------------------------------------------------------------- badges

/** Draw the match count on the toolbar icon for one tab. */
async function updateBadge(tabId, count) {
  const settings = await getSettings();
  const text = settings.showBadge && count > 0 ? String(Math.min(count, 99)) : "";
  try {
    await promisify(api.action.setBadgeText, api.action, { tabId, text });
    if (text) {
      await promisify(api.action.setBadgeBackgroundColor, api.action, {
        tabId,
        color: "#4f46e5",
      });
    }
  } catch {
    // The tab may have gone away; nothing to do.
  }
}

/** Refresh the cached matches (and the badge) for a tab. */
async function refreshMatches(tabId, url) {
  if (!url || !/^https?:/i.test(url)) {
    pageMatches.delete(tabId);
    await updateBadge(tabId, 0);
    return [];
  }
  const result = await withBridge(async (client) => ({
    items: await client.matchUrl(url),
  }));
  const items = result.ok ? result.items : [];
  pageMatches.set(tabId, items);
  await updateBadge(tabId, items.length);
  return items;
}

// ------------------------------------------------------------------ content

/** Make sure the content script is present in a tab before talking to it. */
async function ensureContentScript(tabId) {
  try {
    await sendToTab(tabId, { type: "aurapass:ping" });
    return true;
  } catch {
    if (!api.scripting) return false;
    try {
      await promisify(api.scripting.executeScript, api.scripting, {
        target: { tabId, allFrames: true },
        files: ["content.js"],
      });
      return true;
    } catch {
      return false;
    }
  }
}

// ----------------------------------------------------------------- requests

const handlers = {
  async "aurapass:status"() {
    const settings = await getSettings();
    const result = await withBridge(async (client) => {
      const status = await client.getStatus();
      return { status };
    });
    if (!result.ok) {
      return ok({
        connected: false,
        configured: Boolean(settings.token),
        browser: settings.pairedName || browserName(),
        error: result.error,
      });
    }
    return ok({
      connected: true,
      configured: true,
      browser: settings.pairedName || browserName(),
      status: result.status,
    });
  },

  async "aurapass:connect"() {
    const attempt = () =>
      withBridge(async (client) => ({ status: await client.getStatus() }), {
        force: true,
        allowPair: true,
      });

    let result = await attempt();
    // The app may have forgotten this browser (reinstall, config reset,
    // restored profile). Forget the dead secret and ask for approval once
    // more instead of leaving the extension in a permanent dead end.
    if (!result.ok && result.error && result.error.code === "unpaired") {
      await saveSettings({ token: "", pairedName: "" });
      if (bridge) {
        try {
          bridge.disconnect();
        } catch {
          // Already gone.
        }
      }
      bridge = null;
      bridgeKey = "";
      result = await attempt();
    }

    if (!result.ok) return ok({ connected: false, error: result.error });
    return ok({ connected: true, status: result.status });
  },

  async "aurapass:lock"() {
    return withBridge(async (client) => {
      await client.lock();
      pageMatches.clear();
      return { locked: true };
    });
  },

  async "aurapass:unlock"(message) {
    const result = await withBridge(async (client) => ({
      status: await client.unlock(String(message.password ?? "")),
    }));
    return result.ok ? result : result;
  },

  async "aurapass:matches"(message, sender) {
    const url = message.url || (sender.tab && sender.tab.url) || "";
    const items = await refreshMatches(sender.tab ? sender.tab.id : -1, url);
    return ok({ items });
  },

  async "aurapass:cached-matches"(message, sender) {
    const tabId = sender.tab ? sender.tab.id : message.tabId;
    return ok({ items: pageMatches.get(tabId) || [] });
  },

  async "aurapass:search"(message) {
    const query = String(message.query ?? "");
    const limit = Number(message.limit ?? 30);
    return withBridge(async (client) => ({ items: await client.search(query, limit) }));
  },

  async "aurapass:item"(message) {
    const id = String(message.id);
    const secrets = Boolean(message.secrets);
    return withBridge(async (client) => ({ item: await client.item(id, secrets) }));
  },

  async "aurapass:totp"(message) {
    const id = String(message.id);
    return withBridge(async (client) => ({ totp: await client.totp(id) }));
  },

  async "aurapass:generate"(message) {
    const options = message.options || {};
    return withBridge(async (client) => ({ generated: await client.generate(options) }));
  },

  async "aurapass:used"(message) {
    const id = String(message.id);
    return withBridge(async (client) => ({ recorded: Boolean((await client.used(id)).recorded) }));
  },

  async "aurapass:save"(message) {
    return withBridge(async (client) => {
      const outcome = await client.saveLogin({
        url: String(message.url ?? ""),
        username: String(message.username ?? ""),
        password: String(message.password ?? ""),
        title: message.title ?? null,
      });
      return { outcome };
    });
  },

  /**
   * A page is about to submit a login. Capture it before navigation destroys
   * the document; the destination page (or a timer on an SPA) claims it.
   */
  async "aurapass:save-candidate"(message, sender) {
    const tabId = sender.tab && sender.tab.id;
    if (tabId === undefined || tabId === null) return ok({ stored: false });
    const password = String(message.password ?? "");
    if (!password) return ok({ stored: false });
    await putPendingSave(tabId, {
      username: String(message.username ?? "").slice(0, 512),
      password: password.slice(0, 4096),
      url: String(message.url ?? "").slice(0, 4096),
      title: String(message.title ?? "").slice(0, 512),
    });
    return ok({ stored: true });
  },

  /** The top frame asks for (and atomically consumes) its pending candidate. */
  async "aurapass:pending-save"(message, sender) {
    if (!sender.tab) return ok({ pending: null });
    if (sender.frameId !== undefined && sender.frameId !== 0) {
      return ok({ pending: null });
    }
    return ok({ pending: await takePendingSave(sender.tab.id) });
  },

  /** Popup asks for a credential to be typed into the page. */
  async "aurapass:fill"(message, sender) {
    const tabId = message.tabId ?? (sender.tab && sender.tab.id);
    if (tabId === undefined || tabId === null) {
      return failure({ message: "No active tab to fill.", code: "no-tab" });
    }
    const id = String(message.id);
    const includeTotp = Boolean(message.withTotp);
    const result = await withBridge(async (client) => {
      const item = await client.item(id, true);
      let totp = null;
      if (includeTotp && item.has_totp) {
        try {
          totp = await client.totp(id);
        } catch {
          totp = null;
        }
      }
      return { item, totp };
    });
    if (!result.ok) return result;

    const ready = await ensureContentScript(tabId);
    if (!ready) {
      return failure({ message: "AuraPass cannot fill forms on this page.", code: "no-content" });
    }
    try {
      const response = await sendToTab(tabId, {
        type: "aurapass:fill",
        item: result.item,
        totp: result.totp,
      });
      // Record usage; a failure here must not hide a successful fill.
      withBridge((client) => client.used(id)).catch(() => {});
      return ok({ filled: Boolean(response && response.filled), fields: (response && response.fields) || 0 });
    } catch (error) {
      return failure({ message: describeError(error), code: "no-content" });
    }
  },

  /** Popup asks for the generated password to be typed into the page. */
  async "aurapass:fill-generated"(message, sender) {
    const tabId = message.tabId ?? (sender.tab && sender.tab.id);
    if (tabId === undefined || tabId === null) {
      return failure({ message: "No active tab to fill.", code: "no-tab" });
    }
    await ensureContentScript(tabId);
    try {
      const response = await sendToTab(tabId, {
        type: "aurapass:fill-password",
        password: message.password,
      });
      return ok({ filled: Boolean(response && response.filled) });
    } catch (error) {
      return failure({ message: describeError(error), code: "no-content" });
    }
  },

  async "aurapass:copy"(message) {
    // The popup does its own clipboard work; this exists for the content script.
    return ok({ copied: await copyText(String(message.text ?? "")) });
  },

  async "aurapass:settings"() {
    return ok({ settings: await getSettings() });
  },

  async "aurapass:save-settings"(message) {
    const settings = await saveSettings(message.patch || {});
    bridge = null;
    bridgeKey = "";
    lastStatus = null;
    // Pages that are already open apply the new appearance immediately.
    try {
      const tabs = await promisify(api.tabs.query, api.tabs, {});
      await Promise.allSettled(
        (tabs || [])
          .filter((tab) => tab.id !== undefined && tab.id !== null)
          .map((tab) => sendToTab(tab.id, { type: "aurapass:settings-changed", settings })),
      );
    } catch {
      // Tabs without a content script (browser pages) simply skip this.
    }
    return ok({ settings });
  },

  /** Content script reports what it found on the page. */
  async "aurapass:page"(message, sender) {
    const tabId = sender.tab ? sender.tab.id : message.tabId;
    if (tabId === undefined || tabId === null) return ok({ items: [] });
    const settings = await getSettings();
    if (!settings.autofill) {
      pageMatches.delete(tabId);
      await updateBadge(tabId, 0);
      return ok({ items: [] });
    }
    const items = await refreshMatches(tabId, message.url);
    if (message.wantFill && settings.fillOnPageLoad && items.length > 0) {
      // Fill silently on load for single-match pages, like a native manager.
      try {
        const full = await withBridge((client) => client.item(items[0].id, true));
        if (full.ok) {
          await sendToTab(tabId, { type: "aurapass:fill", item: full.item, silent: true });
        }
      } catch {
        // Ignore: the user can still fill from the popup.
      }
    }
    return ok({ items });
  },

  /** Revoke this browser's access on both sides. */
  async "aurapass:forget"() {
    try {
      const client = await ensureBridge();
      client.disconnect();
    } catch {
      // Offline is fine: the stored secret is what matters.
    }
    bridge = null;
    bridgeKey = "";
    pageMatches.clear();
    return ok({ forgotten: true });
  },

  /**
   * The popup was opened: ask the desktop app to show its quick assistant,
   * then the popup closes itself. Pairing happened in `aurapass:connect`
   * already; never start a second, invisible approval request from here.
   */
  async "aurapass:open-assistant"(message) {
    const x = message.x == null ? null : Number(message.x);
    const y = message.y == null ? null : Number(message.y);
    return withBridge(async (client) => {
      await client.request({ type: "show_assistant", x, y });
      return { shown: true };
    });
  },

  async "aurapass:ping"() {
    return ok({ pong: true });
  },
};

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object" || typeof message.type !== "string") {
    sendResponse(ok({ ignored: true }));
    return false;
  }
  const handler = handlers[message.type];
  if (!handler) {
    sendResponse(failure({ message: `unknown request: ${message.type}`, code: "unknown" }));
    return false;
  }
  Promise.resolve(handler(message, sender)).then(
    (response) => sendResponse(response),
    (error) => sendResponse(failure(error)),
  );
  // Keep the message channel open for the async reply.
  return true;
});

// -------------------------------------------------------------- tab lifecycle

api.tabs.onRemoved.addListener((tabId) => {
  pageMatches.delete(tabId);
  dropPendingSave(tabId).catch(() => {});
});

api.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab && tab.url) {
    pageMatches.delete(tabId);
    updateBadge(tabId, 0);
  }
});

// Keep the service worker (and the socket) warm while the user browses.
if (api.alarms) {
  api.alarms.create("aurapass-keepalive", { periodInMinutes: 1 });
  api.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name !== "aurapass-keepalive") return;
    try {
      const settings = await getSettings();
      await expirePendingSaves();
      if (!settings.token) return;
      const client = await ensureBridge();
      if (!client.token) return;
      await client.ping();
    } catch {
      // Offline is a normal state; the next user action retries.
    }
  });
}

api.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    // Nothing to configure: the first click on the toolbar button asks the
    // desktop app for access.
    await saveSettings({ pairedName: browserName() });
  }
});
