#!/usr/bin/env node
// End-to-end interop test: drives a live `aurapass-bridge` with the same
// JavaScript client the browser extensions use.
//
//   node extensions/tools/test-bridge.mjs --token <t> --port 8791
//
// It asserts the shapes the extension code depends on, and exercises every
// request the popup can make.

import { AuraPassBridge, BridgeError, labelFor } from "../shared/lib/bridge.js";

const args = process.argv.slice(2);
function arg(name, fallback) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

const token = arg("token", process.env.AURAPASS_BRIDGE_TOKEN || "");
const port = Number(arg("port", process.env.AURAPASS_BRIDGE_PORT || 8974));

let passed = 0;
let failed = 0;

function check(name, condition, detail = "") {
  if (condition) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function section(title) {
  console.log(title);
}

async function expectError(name, fn, code) {
  try {
    await fn();
    failed++;
    console.log(`  FAIL ${name} (no error thrown)`);
  } catch (error) {
    if (error instanceof BridgeError && (!code || error.code === code)) {
      passed++;
      console.log(`  ok   ${name} (${error.code})`);
    } else {
      failed++;
      console.log(`  FAIL ${name} — wrong error: ${error && error.message}`);
    }
  }
}

const bridge = new AuraPassBridge({
  token,
  client: "aurapass-interop/1.0.0",
  port,
  autoReconnect: false,
});

try {
  section("handshake");
  const ack = await bridge.connect({ scan: false });
  check("handshake acknowledged", ack && ack.ok === true);
  check("protocol matches", ack.protocol === 1);
  check("session key derived", bridge.isConnected);

  section("ping");
  const pong = await bridge.ping();
  check("pong", pong.pong === true, JSON.stringify(pong));
  check("version reported", typeof pong.version === "string");

  section("status");
  const status = await bridge.getStatus();
  check("vault is unlocked", status.locked === false);
  check("vault name", status.vault === "Interop Vault", status.vault);
  check("item count", status.items >= 3, String(status.items));
  check("auto-lock reported", typeof status.auto_lock_secs === "number");

  section("match_url");
  const github = await bridge.matchUrl("https://github.com/login");
  check("finds the GitHub login", github.some((i) => i.title === "GitHub"), JSON.stringify(github));
  check("does not expose the password", github.every((i) => !("password" in i)));
  const example = await bridge.matchUrl("https://example.com/account");
  check("finds both example.com URLs", example.some((i) => i.title === "Example Site"));
  const nowhere = await bridge.matchUrl("https://no-such-site.invalid/");
  check("empty for an unknown site", nowhere.length === 0);

  section("search");
  const found = await bridge.search("example", 10);
  check("search finds Example Site", found.some((i) => i.title === "Example Site"));
  check("summary has the fields the popup needs", found.every((i) =>
    typeof i.id === "string" && typeof i.title === "string" &&
    typeof i.has_totp === "boolean" && typeof i.favorite === "boolean"));
  const capped = await bridge.search("", 1);
  check("respects the limit", capped.length <= 1, String(capped.length));

  section("item");
  const githubId = github.find((i) => i.title === "GitHub").id;
  const full = await bridge.item(githubId, true);
  check("password included when asked", full.password === "hunter2hunter2", String(full.password));
  check("username included", full.username === "alice@example.com");
  check("kind included", typeof full.kind === "string");
  const publicOnly = await bridge.item(githubId, false);
  check("password hidden by default", publicOnly.password === null || publicOnly.password === undefined);
  check("notes hidden by default", !publicOnly.notes);

  section("totp");
  const totpItem = (await bridge.search("TOTP", 5)).find((i) => i.title === "TOTP Site");
  check("totp item is flagged", totpItem && totpItem.has_totp === true);
  const code = await bridge.totp(totpItem.id);
  check("six-digit code", /^[0-9]{6}$/.test(code.code), code.code);
  check("seconds remaining", code.seconds_remaining >= 0 && code.seconds_remaining < 30);
  await expectError("totp on a non-totp item is an error",
    () => bridge.totp(githubId), "error");

  section("generate");
  const generated = await bridge.generate({ length: 24, digits: true, symbols: true, uppercase: true });
  check("generated length", generated.password.length === 24, generated.password);
  check("entropy reported", typeof generated.entropy_bits === "number");

  section("save_login");
  // Unique per run so the test is repeatable against a long-lived vault. The
  // registrable domain must be unique too: the bridge matches a URL against a
  // whole site, not just the exact host.
  const nonce = Math.random().toString(36).slice(2, 10);
  const site = `https://aurapass-test-${nonce}.com`;
  const saved = await bridge.saveLogin({
    url: `${site}/signin`,
    username: "dave",
    password: "brand-new-password",
    title: `New Site ${nonce}`,
  });
  check("created a new login", saved.saved === true && saved.updated === false);
  const updated = await bridge.saveLogin({
    url: `${site}/other`,
    username: "dave",
    password: "rotated-password",
    title: `New Site ${nonce}`,
  });
  check("updated the existing login", updated.saved === true && updated.updated === true && updated.id === saved.id);
  const stored = await bridge.item(saved.id, true);
  check("the new password stuck", stored.password === "rotated-password", String(stored.password));

  section("used");
  const used = await bridge.used(saved.id);
  check("usage recorded", used.recorded === true);

  section("labelFor");
  check("human label", labelFor({ title: "GitHub", username: "alice" }) === "GitHub — alice");

  section("bad token");
  const wrong = new AuraPassBridge({ token: "definitely-not-the-token", port, autoReconnect: false });
  await expectError("wrong token is rejected", () => wrong.connect({ scan: false }), "pairing");

  section("missing token");
  const none = new AuraPassBridge({ token: "", port, autoReconnect: false });
  await expectError("empty token is rejected", () => none.connect(), "no-token");
} catch (error) {
  failed++;
  console.log(`  FATAL ${error && error.stack ? error.stack : error}`);
} finally {
  bridge.disconnect();
}

console.log("");
if (failed === 0) {
  console.log(`All ${passed} bridge checks passed.`);
  process.exit(0);
} else {
  console.log(`${failed} of ${passed + failed} bridge checks failed.`);
  process.exit(1);
}
