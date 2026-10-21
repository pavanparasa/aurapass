//! The AuraPass toolbar popup.
//!
//! Reads state from the background worker and renders one of four views: the
//! setup prompt (no token yet), offline, locked, or the match list. Everything
//! it shows comes from the background; the popup itself never touches the
//! socket or the token.

import {
  activeTab,
  api,
  copyText,
  describeError,
  escapeHtml,
  getSettings,
  hostOf,
  sendToBackground,
} from "./lib/ext.js";

const app = document.getElementById("app");
const subtitle = document.getElementById("subtitle");
const toastEl = document.getElementById("toast");

const state = {
  settings: null,
  status: null,
  items: [],
  view: "loading",
  error: null,
  query: "",
  tab: null,
  generated: null,
};

// ---------------------------------------------------------------- utilities

function el(html) {
  // Parsed as a document, not assigned to innerHTML: the markup here is static
  // and any interpolated value has already been through escapeHtml().
  const doc = new DOMParser().parseFromString(html.trim(), "text/html");
  return doc.body.firstElementChild;
}

let toastTimer = null;
function toast(message) {
  toastEl.textContent = message;
  toastEl.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toastEl.hidden = true;
  }, 2200);
}

function initials(text) {
  const value = String(text || "?").trim();
  return value ? value[0].toUpperCase() : "?";
}

function iconButton(label, title, onClick) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.title = title;
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    onClick();
  });
  return button;
}

// ------------------------------------------------------------------ actions

async function fillItem(id) {
  const reply = await sendToBackground({
    type: "aurapass:fill",
    id,
    tabId: state.tab ? state.tab.id : undefined,
    submit: true,
  });
  if (reply.ok && reply.filled) {
    window.close();
    return;
  }
  if (reply.ok) {
    toast("Nothing to fill on this page.");
    return;
  }
  toast(reply.error ? reply.error.message : "Could not fill.");
}

async function copyPassword(id) {
  const reply = await sendToBackground({ type: "aurapass:item", id, secrets: true });
  if (reply.ok && reply.item && reply.item.password) {
    toast((await copyText(reply.item.password)) ? "Password copied" : "Copy failed");
  } else {
    toast("No password stored for this item.");
  }
}

async function copyTotp(id) {
  const reply = await sendToBackground({ type: "aurapass:totp", id });
  if (reply.ok && reply.totp) {
    const ok = await copyText(reply.totp.code);
    toast(ok ? `${reply.totp.code} copied · ${reply.totp.seconds_remaining}s` : "Copy failed");
  } else {
    toast(reply.error ? reply.error.message : "No one-time password.");
  }
}

async function doSearch(query) {
  state.query = query;
  if (!query.trim()) {
    return loadMatches();
  }
  const reply = await sendToBackground({ type: "aurapass:search", query, limit: 30 });
  state.items = reply.ok ? reply.items : [];
  state.view = "list";
  paintList();
  updateSubtitle();
}

async function loadMatches() {
  if (state.view !== "list") return;
  const reply = await sendToBackground({
    type: "aurapass:matches",
    url: state.tab ? state.tab.url : undefined,
  });
  state.items = reply.ok ? reply.items : [];
  state.view = "list";
  paintList();
  updateSubtitle();
}

function updateSubtitle() {
  if (!state.settings || !state.settings.token) {
    subtitle.textContent = "Not connected";
    return;
  }
  if (state.view === "offline") {
    subtitle.textContent = "Not running";
    return;
  }
  if (state.view === "locked") {
    subtitle.textContent = "Locked";
    return;
  }
  if (state.status) {
    const name = state.status.vault || "vault";
    const count = state.items.length;
    subtitle.textContent = count > 0
      ? `${name} · ${count} match${count === 1 ? "" : "es"}`
      : name;
    return;
  }
  subtitle.textContent = "Connecting…";
}

// ------------------------------------------------------------------ renders

function render() {
  app.replaceChildren();
  updateSubtitle();
  document.getElementById("lock").disabled = state.view === "setup" || state.view === "offline";
  document.getElementById("generate").disabled = state.view === "setup" || state.view === "offline";

  switch (state.view) {
    case "loading":
      app.append(el(`<div class="empty">Connecting to AuraPass…</div>`));
      break;
    case "setup":
      renderSetup();
      break;
    case "pairing":
      renderPairing();
      break;
    case "offline":
      renderOffline();
      break;
    case "locked":
      renderLocked();
      break;
    case "generate":
      renderGenerator();
      break;
    default:
      renderList();
  }
}

function openOptions() {
  if (api.runtime.openOptionsPage) api.runtime.openOptionsPage();
}

function renderSetup() {
  const card = el(`
    <div class="card">
      <h3>Connect to AuraPass</h3>
      <p>AuraPass is not running on this computer. Start it, then click below — the app will ask you to allow this browser.</p>
      <div class="actions">
        <button class="primary" id="pair">Connect</button>
        <button class="secondary" id="go-options">Settings</button>
      </div>
    </div>
  `);
  card.querySelector("#pair").addEventListener("click", connect);
  card.querySelector("#go-options").addEventListener("click", openOptions);
  app.append(card);
}

function renderPairing() {
  const card = el(`
    <div class="card">
      <h3>Approve this browser</h3>
      <p>AuraPass is asking you to allow <strong>${escapeHtml(state.pairingName || "this browser")}</strong>. Approve it in the desktop app; this window will close on its own.</p>
      <div class="pairing-wait"><span class="spinner"></span> Waiting for AuraPass…</div>
      <div class="actions">
        <button class="secondary" id="cancel">Cancel</button>
      </div>
    </div>
  `);
  card.querySelector("#cancel").addEventListener("click", () => window.close());
  app.append(card);
}

function renderOffline() {
  const message = state.error ? escapeHtml(describeError(state.error)) : "AuraPass is not running.";
  const card = el(`
    <div class="card">
      <h3>Can’t reach AuraPass</h3>
      <div class="notice error">${message}</div>
      <p>Start the desktop app, or run <code>aurapass-bridge</code> on a headless machine, then retry.</p>
      <div class="actions">
        <button class="primary" id="retry">Retry</button>
        <button class="secondary" id="settings">Settings</button>
      </div>
    </div>
  `);
  card.querySelector("#retry").addEventListener("click", connect);
  card.querySelector("#settings").addEventListener("click", openOptions);
  app.append(card);
}

function renderLocked() {
  const card = el(`
    <div class="card">
      <h3>Vault is locked</h3>
      <p>Unlock AuraPass on the desktop, or type the master password here if the desktop app allows remote unlock.</p>
      <div class="field">
        <label for="master">Master password</label>
        <input id="master" type="password" autocomplete="current-password" />
      </div>
      <div class="actions">
        <button class="primary" id="unlock">Unlock</button>
      </div>
    </div>
  `);
  const submit = async () => {
    const password = card.querySelector("#master").value;
    if (!password) return;
    const reply = await sendToBackground({ type: "aurapass:unlock", password });
    if (reply.ok) {
      state.status = reply.status;
      await reload();
    } else {
      toast(reply.error ? reply.error.message : "Unlock failed.");
    }
  };
  card.querySelector("#unlock").addEventListener("click", submit);
  card.querySelector("#master").addEventListener("keydown", (event) => {
    if (event.key === "Enter") submit();
  });
  app.append(card);
}

function renderList() {
  const shell = el(`
    <div>
      <div class="search">
        <input id="q" type="text" placeholder="Search the vault…" autocomplete="off" spellcheck="false" />
        <button class="clear" id="clear" title="Clear" hidden>✕</button>
      </div>
      <ul class="items" id="list"></ul>
    </div>
  `);
  const input = shell.querySelector("#q");
  const clear = shell.querySelector("#clear");
  input.value = state.query;
  clear.hidden = !state.query;
  let debounce = null;
  input.addEventListener("input", () => {
    clear.hidden = !input.value;
    clearTimeout(debounce);
    debounce = setTimeout(() => doSearch(input.value), 180);
  });
  clear.addEventListener("click", () => {
    input.value = "";
    clear.hidden = true;
    doSearch("");
    input.focus();
  });
  app.append(shell);
  paintList();
}

function paintList() {
  const list = document.getElementById("list");
  if (!list) return;
  list.replaceChildren();
  if (!state.items.length) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = state.query
      ? `No items match “${state.query}”.`
      : state.tab && state.tab.url
        ? `No saved logins for ${hostOf(state.tab.url) || "this page"}.`
        : "No logins to show.";
    list.append(empty);
    updateSubtitle();
    return;
  }
  for (const item of state.items) {
    const row = document.createElement("li");
    row.className = "item";

    const avatar = document.createElement("div");
    avatar.className = "avatar";
    avatar.textContent = initials(item.title);

    const meta = document.createElement("div");
    meta.className = "meta";
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = item.title || "(untitled)";
    const user = document.createElement("div");
    user.className = "user";
    user.textContent = item.username || item.url || item.kind || "";
    meta.append(title, user);

    const tools = document.createElement("div");
    tools.className = "tools";
    if (item.has_totp) {
      tools.append(iconButton("⏱", "Copy one-time code", () => copyTotp(item.id)));
    }
    tools.append(iconButton("⧉", "Copy password", () => copyPassword(item.id)));

    row.append(avatar, meta, tools);
    row.addEventListener("click", () => fillItem(item.id));
    list.append(row);
  }
  updateSubtitle();
}

function renderGenerator() {
  const card = el(`
    <div class="card">
      <h3>Generate a password</h3>
      <div class="field">
        <label for="len">Length: <span id="lenval">${state.generated ? state.generatedLength : 20}</span></label>
        <input id="len" type="range" min="8" max="64" value="${state.generated ? state.generatedLength : 20}" />
      </div>
      <div class="actions" style="flex-direction:column">
        <label><input type="checkbox" id="digits" checked /> Digits</label>
        <label><input type="checkbox" id="symbols" checked /> Symbols</label>
        <label><input type="checkbox" id="uppercase" checked /> Upper case</label>
      </div>
      <button class="primary" id="roll">Generate</button>
      <div id="result"></div>
    </div>
  `);
  const length = card.querySelector("#len");
  const lengthValue = card.querySelector("#lenval");
  length.addEventListener("input", () => {
    lengthValue.textContent = length.value;
  });
  const roll = async () => {
    const reply = await sendToBackground({
      type: "aurapass:generate",
      options: {
        length: Number(length.value),
        digits: card.querySelector("#digits").checked,
        symbols: card.querySelector("#symbols").checked,
        uppercase: card.querySelector("#uppercase").checked,
      },
    });
    const result = card.querySelector("#result");
    result.replaceChildren();
    if (!reply.ok) {
      result.append(el(`<div class="notice error">${escapeHtml(reply.error.message)}</div>`));
      return;
    }
    state.generated = reply.generated.password;
    state.generatedLength = Number(length.value);
    const box = el(`<div class="result"><code></code>
      <button class="ghost" id="copy">Copy</button>
      <button class="ghost" id="fill">Fill</button></div>`);
    box.querySelector("code").textContent = reply.generated.password;
    box.querySelector("#copy").addEventListener("click", async () => {
      toast((await copyText(reply.generated.password)) ? "Copied" : "Copy failed");
    });
    box.querySelector("#fill").addEventListener("click", async () => {
      const filled = await sendToBackground({
        type: "aurapass:fill-generated",
        password: reply.generated.password,
        tabId: state.tab ? state.tab.id : undefined,
      });
      if (filled.ok && filled.filled) window.close();
      else toast(filled.error ? filled.error.message : "Nothing to fill.");
    });
    result.append(box);
  };
  card.querySelector("#roll").addEventListener("click", roll);
  app.append(card);
  if (state.generated) {
    // Keep the last password visible while adjusting the policy.
    const result = card.querySelector("#result");
    const box = el(`<div class="result"><code></code>
      <button class="ghost" id="copy">Copy</button>
      <button class="ghost" id="fill">Fill</button></div>`);
    box.querySelector("code").textContent = state.generated;
    box.querySelector("#copy").addEventListener("click", async () =>
      toast((await copyText(state.generated)) ? "Copied" : "Copy failed"));
    box.querySelector("#fill").addEventListener("click", async () => {
      const filled = await sendToBackground({
        type: "aurapass:fill-generated",
        password: state.generated,
        tabId: state.tab ? state.tab.id : undefined,
      });
      if (filled.ok && filled.filled) window.close();
      else toast(filled.error ? filled.error.message : "Nothing to fill.");
    });
    result.append(box);
  }
}

// --------------------------------------------------------------- lifecycle

/**
 * Ask the desktop app to show its quick assistant.
 *
 * The coordinates are kept for protocol compatibility with older desktop
 * builds. Current builds centre the 400x450 panel on the screen, so this
 * window simply closes once the app confirms it is showing.
 */
async function handOffToAssistant() {
  const reply = await sendToBackground({
    type: "aurapass:open-assistant",
    x: Math.round(window.screenX + window.outerWidth),
    y: Math.round(window.screenY),
  });
  if (reply && reply.ok && reply.shown) {
    window.close();
    return true;
  }
  return false;
}

async function connect() {
  state.view = state.settings && state.settings.token ? "loading" : "pairing";
  state.pairingName = state.settings ? state.settings.pairedName : "";
  render();
  let reply;
  try {
    reply = await sendToBackground({ type: "aurapass:connect" });
  } catch (error) {
    // The background worker can be absent while Firefox starts it, or the
    // native/WebSocket transport can fail before it answers. Show that instead
    // of leaving the "Waiting for AuraPass…" spinner running forever.
    state.view = "offline";
    state.error = { message: describeError(error), code: "offline" };
    render();
    return;
  }
  if (!reply.ok || reply.connected !== true) {
    state.settings = await getSettings();
    state.view = reply.error && reply.error.code === "no-token" ? "setup" : "offline";
    state.error = reply.error;
    render();
    return;
  }
  state.status = reply.status;
  state.settings = await getSettings();
  if (await handOffToAssistant()) return;
  await reload();
}

async function reload() {
  state.settings = await getSettings();
  state.tab = await activeTab();
  if (!state.settings.token) {
    state.view = "setup";
    render();
    return;
  }
  const reply = await sendToBackground({ type: "aurapass:status" });
  if (!reply.ok || !reply.connected) {
    state.view = "offline";
    state.error = reply.error || { message: "AuraPass is not running." };
    render();
    return;
  }
  state.status = reply.status;
  if (state.status.locked) {
    state.view = "locked";
    render();
    return;
  }
  state.error = null;
  state.view = "list";
  render();
  await loadMatches();
}

document.getElementById("refresh").addEventListener("click", connect);
document.getElementById("lock").addEventListener("click", async () => {
  const reply = await sendToBackground({ type: "aurapass:lock" });
  if (reply.ok) {
    toast("Vault locked");
    await reload();
  } else {
    toast(reply.error ? reply.error.message : "Could not lock.");
  }
});
document.getElementById("generate").addEventListener("click", () => {
  state.view = "generate";
  render();
});
document.getElementById("options").addEventListener("click", openOptions);

/**
 * Apply the appearance chosen for the login surfaces. The settings page always
 * keeps the light app styling; the popup and the in-page menu follow this.
 */
function applyAppearance(appearance) {
  if (appearance === "light" || appearance === "dark") {
    document.documentElement.dataset.theme = appearance;
  } else {
    delete document.documentElement.dataset.theme;
  }
}

/**
 * Start-up: an approved browser hands the click over to the desktop app so the
 * whole experience lives in one window. Unpaired browsers ask for approval.
 *
 * Always verify first.  A stored secret can be stale after a reinstall or a
 * profile restore; `aurapass:connect` detects that and asks for approval
 * again, while a direct hand-off would only show "not approved" forever.
 */
async function boot() {
  try {
    state.settings = await getSettings();
    applyAppearance(state.settings.appearance);
    await connect();
  } catch (error) {
    state.view = "offline";
    state.error = { message: describeError(error), code: "offline" };
    render();
  }
}

boot();
