//! The AuraPass extension options page.
//!
//! Everything here is local preference: appearance, what the extension may do
//! on a page, and which browser is connected. Pairing itself never needs a
//! token — the app asks the user and issues one behind the scenes.

import {
  api,
  browserName,
  describeError,
  getSettings,
  saveSettings,
  sendToBackground,
} from "./lib/ext.js";

const statusEl = document.getElementById("status");
const connection = document.getElementById("connection");
const browserNameEl = document.getElementById("browser-name");
const browserState = document.getElementById("browser-state");
const connectButton = document.getElementById("connect");
const forgetButton = document.getElementById("forget");
const about = document.getElementById("about");
const defaultHint = document.getElementById("default-hint");

const switches = {
  autofill: document.getElementById("autofill"),
  savePrompt: document.getElementById("savePrompt"),
  fillOnPageLoad: document.getElementById("fillOnPageLoad"),
  showBadge: document.getElementById("showBadge"),
  injectInFrames: document.getElementById("injectInFrames"),
  defaultManager: document.getElementById("defaultManager"),
};

const themeButtons = [...document.querySelectorAll("[data-theme-choice]")];

let settings = null;

function showStatus(message, kind) {
  if (!message) {
    statusEl.hidden = true;
    return;
  }
  statusEl.textContent = message;
  statusEl.className = `status ${kind}`;
  statusEl.hidden = false;
}

/**
 * Reflect the saved choice. The theme applies to the login menu drawn inside
 * web pages; the settings page itself always keeps the light app styling.
 */
function applyAppearance(appearance) {
  for (const button of themeButtons) {
    button.setAttribute(
      "aria-checked",
      String(button.dataset.themeChoice === (appearance || "system")),
    );
  }
}

function paintConnection() {
  const name = (settings && (settings.pairedName || browserName())) || "This browser";
  const paired = Boolean(settings && settings.token);
  browserNameEl.textContent = name;
  browserState.textContent = paired
    ? "Approved by AuraPass on this computer"
    : "Not connected yet";
  connectButton.hidden = paired;
  forgetButton.hidden = !paired;

  connection.textContent = paired ? "Connected" : "Not connected";
  connection.className = `pill ${paired ? "ok" : "off"}`;
}

async function save(patch) {
  settings = { ...settings, ...patch };
  await saveSettings(patch);
  paintConnection();
}

async function checkConnection() {
  const reply = await sendToBackground({ type: "aurapass:status" });
  if (reply.ok && reply.connected) {
    const status = reply.status || {};
    const vault = status.vault || "vault";
    connection.textContent = status.locked ? "Locked" : "Connected";
    connection.className = `pill ${status.locked ? "warn" : "ok"}`;
    showStatus(`Reachable: “${vault}”${status.locked ? " (locked)" : ""}.`, "ok");
    return;
  }
  showStatus(describeError(reply.error), "bad");
  connection.textContent = "Offline";
  connection.className = "pill off";
}

async function connect() {
  connectButton.disabled = true;
  showStatus("Check AuraPass — approve this browser there.", "ok");
  const reply = await sendToBackground({ type: "aurapass:connect" });
  connectButton.disabled = false;
  settings = await getSettings();
  paintConnection();
  if (reply.ok && reply.connected === true) {
    showStatus(`Approved. ${browserName()} can now use your vault.`, "ok");
    await checkConnection();
  } else {
    showStatus(describeError(reply.error), "bad");
  }
}

async function load() {
  settings = await getSettings();
  applyAppearance(settings.appearance);
  switches.autofill.checked = settings.autofill !== false;
  switches.savePrompt.checked = settings.savePrompt !== false;
  switches.fillOnPageLoad.checked = Boolean(settings.fillOnPageLoad);
  switches.showBadge.checked = settings.showBadge !== false;
  switches.injectInFrames.checked = settings.injectInFrames !== false;
  switches.defaultManager.checked = Boolean(settings.defaultManager);
  defaultHint.hidden = !settings.defaultManager;
  paintConnection();

  const manifest = api.runtime.getManifest();
  about.textContent = `AuraPass extension ${manifest.version} · loopback-only bridge · nothing leaves this computer`;
}

// ------------------------------------------------------------------- wiring

for (const button of themeButtons) {
  button.addEventListener("click", async () => {
    const appearance = button.dataset.themeChoice;
    applyAppearance(appearance);
    await save({ appearance });
  });
}

for (const [key, input] of Object.entries(switches)) {
  input.addEventListener("change", async () => {
    await save({ [key]: input.checked });
    if (key === "defaultManager") {
      defaultHint.hidden = !input.checked;
      if (input.checked) {
        // Extensions cannot write this preference; open the page that can.
        try {
          await api.tabs.create({ url: "chrome://settings/passwords" });
        } catch {
          /* Firefox and locked-down builds have no such page. */
        }
      }
    }
  });
}

connectButton.addEventListener("click", connect);
forgetButton.addEventListener("click", async () => {
  await save({ token: "", pairedName: browserName() });
  await sendToBackground({ type: "aurapass:forget" });
  showStatus("Access revoked. This browser will ask again next time.", "ok");
});

document.getElementById("lock").addEventListener("click", async () => {
  const reply = await sendToBackground({ type: "aurapass:lock" });
  if (reply.ok) showStatus("Vault locked.", "ok");
  else showStatus(describeError(reply.error), "bad");
});

document.getElementById("open-app").addEventListener("click", async () => {
  await sendToBackground({ type: "aurapass:open-assistant", x: null, y: null });
});

load();
