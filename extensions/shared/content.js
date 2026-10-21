//! In-page autofill for AuraPass.
//!
//! Runs as a *classic* content script in every frame. It never talks to the
//! bridge and never sees the pairing token: it asks the background worker for
//! the matches, and the background pushes a decrypted item back only when the
//! user actually picks one.
//!
//! What it does:
//!
//! * finds login forms (a visible `input[type=password]` plus a nearby text
//!   input),
//! * shows a small dropdown of matching AuraPass logins when a field is focused,
//! * fills username/password/TOTP with the native setters so React and Vue
//!   notice the change,
//! * offers to save a login that the page submitted but the vault does not know.

(() => {
  if (window.__aurapassInjected) return;
  window.__aurapassInjected = true;

  const api = globalThis.browser ?? globalThis.chrome;
  const HOST_ID = "__aurapass_overlay_host";

  /** Matches for this page, from the background worker. */
  let matches = [];
  /** The last credential we typed, so we can spot edits worth saving. */
  let lastFilled = null;
  /** The user's preferences, fetched once at start-up. */
  let prefs = null;
  /** The shadow root holding the dropdown and the save banner. */
  let shadow = null;
  /** Timer that claims a pending save on single-page forms. */
  let saveTimer = null;
  /** Login field -> the little AuraPass button sitting inside its right edge. */
  const fieldTriggers = new Map();
  let triggerScanQueued = false;
  let triggerObserver = null;

  /** The appearance the user picked for the in-page menu ("system" default). */
  function resolvedTheme() {
    const appearance = prefs && prefs.appearance;
    if (appearance === "dark") return "dark";
    if (appearance === "light") return "light";
    return globalThis.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  /** The menu and the save banner follow the extension's appearance setting. */
  function applyTheme() {
    const theme = resolvedTheme();
    if (shadow && shadow.host) shadow.host.dataset.apTheme = theme;
    // Set the attribute on the surfaces themselves as well. Some pages create
    // their own shadow roots or rewrite attributes on our host; the panel keeps
    // its colours either way.
    if (panel) panel.dataset.apTheme = theme;
    if (banner) banner.dataset.apTheme = theme;
    for (const trigger of fieldTriggers.values()) trigger.dataset.apTheme = theme;
  }

  // ------------------------------------------------------------- messaging

  function send(message) {
    return new Promise((resolve) => {
      try {
        api.runtime.sendMessage(message, (reply) => {
          const error = api.runtime.lastError;
          resolve(error ? { ok: false, error: { message: error.message } } : reply);
        });
      } catch {
        resolve({ ok: false, error: { message: "extension context lost" } });
      }
    });
  }

  // --------------------------------------------------------------- geometry

  function isVisible(el) {
    if (!el || el.disabled || el.readOnly) return false;
    if (el.type === "hidden") return false;
    const style = window.getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none") return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function passwordFields() {
    return [...document.querySelectorAll("input[type=password]")].filter(isVisible);
  }

  const USERNAME_HINTS = /user|email|login|account|phone|mobile|name|handle/i;
  /** Buttons that commonly submit a sign-in or sign-up form. */
  const SAVE_BUTTON = /sign\s?up|sign\s?in|log\s?in|register|create|join|get\s+started|continue|next|submit/i;

  /** The most plausible username field for a password input. */
  function usernameFieldFor(password) {
    const form = password.form;
    const scope = form || document;
    const candidates = [...scope.querySelectorAll(
      "input[type=text], input[type=email], input[type=tel], input:not([type])",
    )].filter(isVisible);

    // Prefer an explicit autocomplete hint anywhere in the form.
    const explicit = candidates.find((el) => /username|email/i.test(el.autocomplete || ""));
    if (explicit) return explicit;

    // Otherwise take the nearest one *before* the password field.
    const passwordTop = password.getBoundingClientRect().top;
    let best = null;
    let bestDistance = Infinity;
    for (const el of candidates) {
      if (el === password) continue;
      const distance = passwordTop - el.getBoundingClientRect().top;
      if (distance < 0) continue;
      const hinted = USERNAME_HINTS.test(
        `${el.name} ${el.id} ${el.placeholder} ${el.getAttribute("aria-label") || ""}`,
      );
      const score = hinted ? distance - 1e6 : distance;
      if (score < bestDistance) {
        bestDistance = score;
        best = el;
      }
    }
    if (best) return best;

    // Last resort: a hint-labelled field anywhere, even after the password.
    return candidates.find((el) =>
      USERNAME_HINTS.test(`${el.name} ${el.id} ${el.placeholder}`),
    ) || null;
  }

  /** Every login form on the page, de-duplicated. */
  function loginForms() {
    const forms = [];
    for (const password of passwordFields()) {
      const key = password.form || password;
      if (!forms.some((f) => f.key === key)) {
        forms.push({ key, password, username: usernameFieldFor(password) });
      }
    }
    return forms;
  }

  // ---------------------------------------------------------------- filling

  function setValue(input, value) {
    if (!input || value === undefined || value === null) return false;
    const proto = input instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    if (setter) setter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  }

  function focusField(input) {
    try {
      input.focus({ preventScroll: true });
    } catch {
      /* ignore */
    }
  }

  /** Click the login button (or submit the form) after a fill. */
  function submitLogin(entry) {
    if (!entry) return;
    const form = entry.key instanceof HTMLFormElement ? entry.key : null;
    const scope = form || document;
    const rect = entry.password.getBoundingClientRect();
    const buttons = [...scope.querySelectorAll(
      "button, input[type=submit], input[type=image], [role=button]",
    )].filter(isVisible);
    const label = (el) => `${el.textContent || ""} ${el.value || ""} ${el.getAttribute("aria-label") || ""}`;
    const submitish = buttons
      .filter((el) => /log\s?in|sign\s?in|signin|continue|next|submit|enter|unlock/i.test(label(el)))
      .map((el) => {
        const box = el.getBoundingClientRect();
        // Prefer the control closest to the password field, and below it.
        return { el, distance: Math.abs(box.top - rect.bottom) + Math.abs(box.left - rect.left) / 4 };
      })
      .sort((a, b) => a.distance - b.distance)[0];
    if (submitish) {
      submitish.el.click();
      return;
    }
    if (form && typeof form.requestSubmit === "function") {
      form.requestSubmit();
      return;
    }
    const fallback = scope.querySelector("button[type=submit], input[type=submit]");
    if (fallback) fallback.click();
    else if (form) form.submit();
  }

  /** Fill every login form on the page with one item. */
  function fillItem(item, { silent = false, submit = false } = {}) {
    const passwordValue = item.password ?? "";
    const forms = loginForms();
    let filledFields = 0;
    let submitTarget = null;

    for (const form of forms) {
      if (form.username && item.username) {
        setValue(form.username, item.username);
        filledFields += 1;
      }
      if (form.password && passwordValue) {
        setValue(form.password, passwordValue);
        filledFields += 1;
        submitTarget = submitTarget || form;
      } else if (form.password && !passwordValue) {
        // A "username-only" fill is still useful on two-step login pages.
        focusField(form.password);
      }
      // Any extra password inputs (confirm fields) get the same secret only
      // when they are visually paired with the first one.
    }

    // If the page has no form at all, fall back to raw inputs.
    if (forms.length === 0) {
      const passwords = passwordFields();
      if (passwords.length && passwordValue) {
        setValue(passwords[0], passwordValue);
        filledFields += 1;
        submitTarget = {
          key: passwords[0].form || passwords[0],
          password: passwords[0],
          username: null,
        };
      }
      const username = passwords[0] ? usernameFieldFor(passwords[0]) : null;
      if (username && item.username) {
        setValue(username, item.username);
        filledFields += 1;
      }
    }

    lastFilled = {
      username: item.username || "",
      password: passwordValue,
      id: item.id,
    };

    if (!silent) {
      const first = forms[0];
      focusField((first && (first.password || first.username)) || passwordFields()[0] || document.body);
      hideOverlay();
    }
    if (submit && submitTarget) {
      // Give React/Vue a frame to digest the new values before the click.
      const target = submitTarget;
      setTimeout(() => submitLogin(target), 150);
    }
    return filledFields;
  }

  /** Type a generated password into the focused (or first) password field. */
  function fillGenerated(password) {
    const fields = passwordFields();
    const target = fields.find((el) => el === document.activeElement) || fields[0];
    if (!target) return 0;
    setValue(target, password);
    // Many sign-up forms have a "repeat password" box right below.
    const other = fields.find((el) => el !== target);
    if (other && other.form === target.form) {
      const distance = Math.abs(other.getBoundingClientRect().top - target.getBoundingClientRect().top);
      if (distance < 120) setValue(other, password);
    }
    lastFilled = { username: "", password, id: null };
    return 1;
  }

  // ------------------------------------------------------------------- UI

  function ensureShadow() {
    if (shadow && shadow.host.isConnected) return shadow;
    const host = document.createElement("div");
    host.id = HOST_ID;
    host.style.all = "initial";
    host.style.position = "fixed";
    host.style.zIndex = "2147483647";
    host.style.top = "0";
    host.style.left = "0";
    host.style.width = "0";
    host.style.height = "0";
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .panel, .banner, .trigger {
        --ap-accent: #4f46e5;
        --ap-accent-soft: #eef2ff;
        --ap-ink: #14161c;
        --ap-muted: #6b7280;
        --ap-line: #e6e8ee;
        --ap-panel: #ffffff;
        --ap-well: #f7f8fa;
        color-scheme: light;
      }
      /* Dark mode belongs to this menu, not to the extension's own pages. */
      :host([data-ap-theme="dark"]) .panel,
      :host([data-ap-theme="dark"]) .banner,
      :host([data-ap-theme="dark"]) .trigger,
      .panel[data-ap-theme="dark"],
      .banner[data-ap-theme="dark"],
      .trigger[data-ap-theme="dark"] {
        --ap-accent: #818cf8;
        --ap-accent-soft: #232544;
        --ap-ink: #eef0f6;
        --ap-muted: #9aa1ad;
        --ap-line: #2a2d36;
        --ap-panel: #1d1f25;
        --ap-well: #22242b;
        color-scheme: dark;
      }
      .panel {
        position: fixed; width: 280px; min-width: 0; max-width: none;
        max-height: calc(100vh - 16px);
        display: flex; flex-direction: column;
        box-sizing: border-box;
        background: var(--ap-panel); color: var(--ap-ink);
        border: 1px solid var(--ap-line);
        border-radius: 12px;
        box-shadow: 0 12px 34px rgba(15,23,42,.22), 0 2px 6px rgba(15,23,42,.08);
        font: 13px/1.45 Inter, -apple-system, "Segoe UI", Roboto, sans-serif;
        overflow: hidden;
        animation: ap-in 90ms ease-out;
      }
      @keyframes ap-in { from { opacity: 0; transform: translateY(-3px); } }
      .trigger {
        position: fixed;
        box-sizing: border-box;
        width: 24px; height: 24px;
        display: flex; align-items: center; justify-content: center;
        margin: 0; padding: 0;
        border: 1px solid var(--ap-line);
        border-radius: 7px;
        background: var(--ap-panel);
        color: var(--ap-accent);
        box-shadow: 0 1px 3px rgba(15,23,42,.14);
        cursor: pointer;
        opacity: .94;
        pointer-events: auto;
        animation: ap-trigger-in 100ms ease-out;
      }
      .trigger:hover { background: var(--ap-accent-soft); opacity: 1; }
      .trigger:focus-visible { outline: 2px solid var(--ap-accent); outline-offset: 1px; }
      .trigger svg { width: 15px; height: 15px; display: block; }
      @keyframes ap-trigger-in { from { opacity: 0; transform: scale(.9); } }
      .brand {
        display: flex; align-items: center; gap: 7px;
        padding: 9px 11px; color: var(--ap-ink);
        border-bottom: 1px solid var(--ap-line);
        font-weight: 650; letter-spacing: .01em;
        flex: none;
      }
      .search, .foot { flex: none; }
      ul { flex: 1 1 auto; }
      .brand .mark {
        width: 16px; height: 16px; border-radius: 5px;
        background: radial-gradient(120% 120% at 20% 0%, #a5b4fc 0%, #4f46e5 60%, #3730a3 100%);
        box-shadow: inset 0 1px 0 rgba(255,255,255,.4);
        flex: none;
      }
      .brand .spacer { margin-left: auto; font-weight: 500; color: var(--ap-muted); font-size: 11.5px; }
      .search { padding: 6px 8px 4px; }
      .search input {
        width: 100%; box-sizing: border-box;
        padding: 6px 9px; border-radius: 7px;
        border: 1px solid var(--ap-line);
        background: var(--ap-well); color: var(--ap-ink);
        font: inherit; font-size: 12.5px; outline: none;
      }
      .search input::placeholder { color: var(--ap-muted); }
      .search input:focus { border-color: var(--ap-accent); }
      ul { list-style: none; margin: 0; padding: 4px 5px 5px; max-height: 268px; min-height: 0; overflow: auto; }
      li {
        display: flex; align-items: center; gap: 9px;
        padding: 8px; border-radius: 9px; cursor: pointer;
      }
      li:hover, li.active { background: var(--ap-accent-soft); }
      li.note {
        cursor: default; color: var(--ap-muted); font-size: 11.5px;
        padding: 7px 8px 4px;
      }
      li.note:hover { background: transparent; }
      .title { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .user { color: var(--ap-muted); font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .avatar {
        width: 26px; height: 26px; border-radius: 8px; flex: none;
        background: var(--ap-accent-soft); color: var(--ap-accent);
        display: flex; align-items: center; justify-content: center;
        font-weight: 700; font-size: 12px;
      }
      .empty, .foot { padding: 9px 11px; color: var(--ap-muted); font-size: 12px; }
      .foot {
        border-top: 1px solid var(--ap-line); background: var(--ap-well);
        display: flex; align-items: center; gap: 6px;
      }
      button.link {
        all: unset; cursor: pointer; color: var(--ap-accent); font-weight: 600;
      }
      .banner {
        position: fixed;
        left: 50%; top: 50%;
        width: min(420px, calc(100vw - 32px));
        box-sizing: border-box;
        transform: translate(-50%, -50%);
        background: var(--ap-panel); color: var(--ap-ink);
        border: 1px solid var(--ap-line);
        border-radius: 16px;
        box-shadow: 0 24px 64px rgba(15,23,42,.34), 0 4px 14px rgba(15,23,42,.12);
        font: 14px/1.5 Inter, -apple-system, "Segoe UI", Roboto, sans-serif;
        padding: 22px; display: flex; flex-direction: column; gap: 13px;
        animation: ap-banner-in 140ms ease-out;
      }
      @keyframes ap-banner-in {
        from { opacity: 0; transform: translate(-50%, -46%) scale(.985); }
        to { opacity: 1; transform: translate(-50%, -50%) scale(1); }
      }
      .banner h4 { margin: 0; font-size: 17px; font-weight: 650; letter-spacing: -.01em; }
      .banner .subject {
        margin: 0; color: var(--ap-ink); font-size: 15px; font-weight: 600;
        line-height: 1.35; overflow-wrap: anywhere;
      }
      .banner p { margin: 0; color: var(--ap-muted); font-size: 13.5px; word-break: break-word; }
      .row { display: flex; gap: 10px; justify-content: flex-end; margin-top: 3px; }
      .row button {
        all: unset; cursor: pointer; padding: 9px 17px; border-radius: 9px;
        font-weight: 600; font-size: 13px;
      }
      .row button.primary { background: var(--ap-accent); color: #fff; }
      .row button.primary:hover { filter: brightness(1.06); }
      .row button.ghost { color: var(--ap-muted); }
      .row button.ghost:hover { background: var(--ap-well); }
    `;
    root.append(style);
    (document.body || document.documentElement).append(host);
    shadow = root;
    applyTheme();
    return shadow;
  }

  let panel = null;
  let panelAnchor = null;
  let panelCount = null;
  let panelList = null;
  let overlayQuery = "";

  function hideOverlay() {
    if (panel) {
      panel.remove();
      panel = null;
    }
    panelAnchor = null;
    panelCount = null;
    panelList = null;
    overlayQuery = "";
    scheduleTriggerRefresh();
  }

  // ---------------------------------------------------------- field triggers

  const TRIGGER_SIZE = 24;

  /** The username/password inputs that should carry a small AuraPass button. */
  function triggerFields() {
    const fields = new Set();
    for (const form of loginForms()) {
      if (form.username) fields.add(form.username);
      if (form.password) fields.add(form.password);
    }
    return [...fields];
  }

  function removeAllTriggers() {
    for (const trigger of fieldTriggers.values()) trigger.remove();
    fieldTriggers.clear();
  }

  function hideTriggers() {
    for (const trigger of fieldTriggers.values()) trigger.style.display = "none";
  }

  function ensureTrigger(field) {
    let trigger = fieldTriggers.get(field);
    if (trigger && trigger.isConnected) return trigger;
    const root = ensureShadow();
    trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "trigger";
    trigger.dataset.apTheme = resolvedTheme();
    trigger.tabIndex = -1;
    trigger.title = "Open AuraPass";
    trigger.setAttribute("aria-label", "Open AuraPass logins");
    trigger.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="10" width="14" height="10" rx="2"></rect><path d="M8 10V7a4 4 0 0 1 8 0v3"></path></svg>';
    trigger.addEventListener("mousedown", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (matches.length) showOverlay(field);
    });
    trigger.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
    });
    root.append(trigger);
    fieldTriggers.set(field, trigger);
    return trigger;
  }

  function positionTrigger(field, trigger) {
    if (!field.isConnected || !isVisible(field)) {
      trigger.style.display = "none";
      return;
    }
    const rect = field.getBoundingClientRect();
    if (rect.width < TRIGGER_SIZE + 8 || rect.height < 18
      || rect.bottom < 0 || rect.top > window.innerHeight
      || rect.right < 0 || rect.left > window.innerWidth) {
      trigger.style.display = "none";
      return;
    }
    trigger.style.display = "flex";
    trigger.style.left = `${Math.round(rect.right - TRIGGER_SIZE - 4)}px`;
    trigger.style.top = `${Math.round(rect.top + (rect.height - TRIGGER_SIZE) / 2)}px`;
  }

  /** Rebuild/position the icons. Cheap enough to call on scroll and DOM changes. */
  function refreshFieldTriggers() {
    if ((prefs && prefs.autofill === false) || !matches.length) {
      removeAllTriggers();
      return;
    }
    if (panel) {
      hideTriggers();
      return;
    }
    const wanted = triggerFields().filter(isVisible);
    const keep = new Set(wanted);
    for (const [field, trigger] of fieldTriggers) {
      if (!keep.has(field) || !field.isConnected) {
        trigger.remove();
        fieldTriggers.delete(field);
      }
    }
    for (const field of wanted) {
      positionTrigger(field, ensureTrigger(field));
    }
  }

  function scheduleTriggerRefresh() {
    if (triggerScanQueued) return;
    triggerScanQueued = true;
    // Coalesce bursts of DOM/scroll events; the icons only need to land a
    // frame or two after the layout settles.
    setTimeout(() => {
      triggerScanQueued = false;
      refreshFieldTriggers();
    }, 80);
  }

  function initials(title) {
    const text = String(title || "?").trim();
    return text ? text[0].toUpperCase() : "?";
  }

  /** The bridge should already deduplicate, but never show a wrong count. */
  function uniqueItems(items) {
    const seen = new Set();
    return (Array.isArray(items) ? items : []).filter((item) => {
      if (!item || !item.id || seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    });
  }

  /** Items matching every word in the little search box, ignoring case. */
  function searchedMatches(query) {
    const terms = String(query || "")
      .trim()
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);
    if (!terms.length) return matches;
    return matches.filter((item) => {
      const hay = `${item.title || ""} ${item.username || ""} ${item.url || ""}`.toLowerCase();
      return terms.every((term) => hay.includes(term));
    });
  }

  function chooseOverlayItem(item) {
    hideOverlay();
    send({ type: "aurapass:fill", id: item.id, submit: true }).then((reply) => {
      if (!reply || !reply.ok) {
        showBanner("Could not fill", (reply && reply.error && reply.error.message) || "Try again.");
      }
    });
  }

  /** Redraw the list and the live count for the current search text. */
  function renderOverlayList(query = "") {
    if (!panelList) return;
    overlayQuery = query;
    const found = searchedMatches(query);
    if (panelCount) {
      panelCount.textContent = `${found.length} login${found.length === 1 ? "" : "s"}`;
    }

    panelList.replaceChildren();
    // A page can legitimately have hundreds of logins for one domain. Draw a
    // sane window; the search box narrows the rest instantly.
    const LIMIT = 60;
    for (const item of found.slice(0, LIMIT)) {
      const li = document.createElement("li");
      li.tabIndex = 0;
      li.setAttribute("role", "option");
      const avatar = document.createElement("div");
      avatar.className = "avatar";
      avatar.textContent = initials(item.title);
      const text = document.createElement("div");
      text.style.minWidth = "0";
      const title = document.createElement("div");
      title.className = "title";
      title.textContent = item.title || "(untitled)";
      text.append(title);
      if (item.username) {
        const user = document.createElement("div");
        user.className = "user";
        user.textContent = item.username;
        text.append(user);
      }
      li.append(avatar, text);

      const choose = () => chooseOverlayItem(item);
      li.addEventListener("mousedown", (event) => {
        event.preventDefault();
        event.stopPropagation();
        choose();
      });
      li.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          choose();
        }
      });
      panelList.append(li);
    }

    if (!found.length) {
      const empty = document.createElement("li");
      empty.className = "note";
      empty.textContent = query.trim()
        ? "No logins match that search."
        : "No logins match this website.";
      panelList.append(empty);
    } else if (found.length > LIMIT) {
      const note = document.createElement("li");
      note.className = "note";
      note.textContent = `Showing ${LIMIT} of ${found.length} — keep typing to narrow.`;
      panelList.append(note);
    }

    positionOverlay(panelAnchor);
  }

  function showOverlay(anchor) {
    if (!matches.length) return;
    const root = ensureShadow();
    hideOverlay();
    panelAnchor = anchor;

    panel = document.createElement("div");
    panel.className = "panel";
    panel.dataset.apTheme = resolvedTheme();
    hideTriggers();

    const brand = document.createElement("div");
    brand.className = "brand";
    const dot = document.createElement("span");
    dot.className = "mark";
    brand.append(dot, document.createTextNode("AuraPass"));
    panelCount = document.createElement("span");
    panelCount.className = "spacer";
    brand.append(panelCount);
    panel.append(brand);

    const search = document.createElement("div");
    search.className = "search";
    const input = document.createElement("input");
    input.type = "search";
    input.placeholder = "Search logins";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.setAttribute("aria-label", "Search logins");
    input.addEventListener("input", () => renderOverlayList(input.value));
    // Firefox's native clear button emits `search` rather than `input`.
    input.addEventListener("search", () => renderOverlayList(input.value));
    input.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        hideOverlay();
        focusField(anchor);
      } else if (event.key === "Enter") {
        const first = searchedMatches(input.value)[0];
        if (first) {
          event.preventDefault();
          chooseOverlayItem(first);
        }
      }
    });
    search.append(input);
    panel.append(search);

    panelList = document.createElement("ul");
    panelList.setAttribute("role", "listbox");
    panel.append(panelList);

    const foot = document.createElement("div");
    foot.className = "foot";
    const open = document.createElement("button");
    open.className = "link";
    open.textContent = "Open AuraPass";
    open.addEventListener("mousedown", (event) => {
      event.preventDefault();
      openPopup();
    });
    foot.append(open);
    panel.append(foot);

    root.append(panel);
    renderOverlayList("");
    // The dropdown opens because the user clicked a login field. Move the
    // caret into search straight away so they can filter without a second
    // click.
    input.focus({ preventScroll: true });
    input.setSelectionRange(input.value.length, input.value.length);
  }

  function positionOverlay(anchor) {
    if (!panel || !anchor) return;
    const rect = anchor.getBoundingClientRect();
    const wanted = Math.max(rect.width, 240);
    panel.style.width = `${Math.min(wanted, window.innerWidth - 16)}px`;
    const width = panel.offsetWidth || wanted;
    const height = panel.offsetHeight || 260;
    let left = rect.left;
    let top = rect.bottom + 6;
    if (left + width > window.innerWidth - 8) left = Math.max(8, window.innerWidth - width - 8);
    if (top + height > window.innerHeight - 8) {
      const above = rect.top - height - 6;
      top = above > 8 ? above : Math.max(8, window.innerHeight - height - 8);
    }
    panel.style.left = `${Math.max(8, left)}px`;
    panel.style.top = `${top}px`;
  }

  function openPopup() {
    // Nothing to do: the browser owns the popup. Just tell the user.
    showBanner("AuraPass", "Click the AuraPass icon in the toolbar.");
  }

  let banner = null;

  function showBanner(title, body, actions = [], subject = "") {
    const root = ensureShadow();
    if (banner) banner.remove();
    banner = document.createElement("div");
    banner.className = "banner";
    banner.dataset.apTheme = resolvedTheme();
    const heading = document.createElement("h4");
    heading.textContent = title;
    const paragraph = document.createElement("p");
    paragraph.textContent = body;
    banner.append(heading);
    if (subject) {
      const line = document.createElement("p");
      line.className = "subject";
      line.textContent = subject;
      banner.append(line);
    }
    banner.append(paragraph);
    if (actions.length) {
      const row = document.createElement("div");
      row.className = "row";
      for (const action of actions) {
        const button = document.createElement("button");
        button.className = action.primary ? "primary" : "ghost";
        button.textContent = action.label;
        button.addEventListener("click", () => {
          banner?.remove();
          banner = null;
          action.run();
        });
        row.append(button);
      }
      banner.append(row);
    }
    if (!actions.length) {
      const row = document.createElement("div");
      row.className = "row";
      const dismiss = document.createElement("button");
      dismiss.className = "ghost";
      dismiss.textContent = "Dismiss";
      dismiss.addEventListener("click", () => {
        banner?.remove();
        banner = null;
      });
      row.append(dismiss);
      banner.append(row);
    }
    root.append(banner);
    setTimeout(() => {
      if (banner && banner.isConnected && !banner.querySelector("button.primary")) {
        banner.remove();
        banner = null;
      }
    }, 9000);
  }

  // ------------------------------------------------------------ save prompt

  function formCredentials(form) {
    const forms = loginForms();
    const entry = forms.find((f) => f.key === form) || forms[0];
    if (!entry) return null;
    const password = entry.password ? entry.password.value : "";
    const username = entry.username ? entry.username.value : "";
    if (!password && !username) return null;
    return { username, password };
  }

  function hostLabel(url) {
    try {
      return new URL(url || location.href).host || location.host;
    } catch {
      return location.host;
    }
  }

  /** The credentials to offer, unless they were just filled from the vault. */
  function candidateFor(form) {
    const credentials = formCredentials(form);
    if (!credentials || !credentials.password) return null;
    if (lastFilled && lastFilled.password === credentials.password
      && lastFilled.username === credentials.username) {
      return null; // Already in the vault; nothing new to offer.
    }
    return {
      username: credentials.username,
      password: credentials.password,
      url: location.href,
      title: document.title || location.host,
    };
  }

  /**
   * Capture the login *before* the page navigates. A classic form post destroys
   * this document, including any timeout and banner, so the background holds
   * the candidate for the next page in this tab. Single-page forms stay put;
   * the timer claims the same candidate and shows it here.
   */
  function captureSave(form) {
    if (prefs && prefs.savePrompt === false) return;
    const candidate = candidateFor(form);
    if (!candidate) return;
    send({ type: "aurapass:save-candidate", ...candidate });
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      saveTimer = null;
      claimPendingSave();
    }, 900);
  }

  /** Claim the candidate stored before navigation, if this is the top frame. */
  async function claimPendingSave() {
    if (window.top !== window) return;
    const reply = await send({ type: "aurapass:pending-save" });
    if (!reply || !reply.ok || !reply.pending) return;
    if (prefs && prefs.savePrompt === false) return;
    const candidate = reply.pending;
    if (lastFilled && lastFilled.password === candidate.password
      && lastFilled.username === candidate.username) {
      return;
    }
    offerSave(candidate);
  }

  function offerSave(candidate) {
    if (!candidate || !candidate.password) return;
    const knownItem = matches.find((item) =>
      (item.username || "").toLowerCase() === (candidate.username || "").toLowerCase());
    const host = hostLabel(candidate.url);
    const loginTitle = (
      (knownItem && knownItem.title)
      || candidate.title
      || document.title
      || host
    ).trim() || host;

    showBanner(
      knownItem ? "Update this login?" : "Save this login to AuraPass?",
      `${candidate.username || "(no username)"} — ${host}`,
      [
        {
          label: "Save",
          primary: true,
          run: async () => {
            showBanner("Saving…", "Writing to the open AuraPass vault…");
            const reply = await send({
              type: "aurapass:save",
              url: candidate.url || location.href,
              username: candidate.username,
              password: candidate.password,
              title: loginTitle,
            });
            const outcome = reply && reply.ok ? reply.outcome : null;
            if (outcome && outcome.saved) {
              lastFilled = { ...candidate, id: outcome.id };
              showBanner(
                outcome.updated ? "Login updated" : "Login saved",
                outcome.updated
                  ? "The password was updated in AuraPass."
                  : "Stored in the open AuraPass vault.",
              );
              report();
            } else {
              showBanner(
                "Could not save",
                (reply && reply.error && reply.error.message)
                  || "AuraPass did not confirm the save. Is the vault unlocked?",
              );
            }
          },
        },
        { label: "Not now", run: () => {} },
      ],
      loginTitle,
    );
  }

  function watchForms() {
    document.addEventListener(
      "submit",
      (event) => {
        const form = event.target;
        if (form instanceof HTMLFormElement && form.querySelector("input[type=password]")) {
          captureSave(form);
        }
      },
      true,
    );
    // Single-page apps often never fire `submit` and many use a plain button.
    document.addEventListener(
      "click",
      (event) => {
        const target = event.target;
        if (!(target instanceof Element)) return;
        const button = target.closest(
          "button, input[type=submit], input[type=button], [role=button]",
        );
        if (!button) return;
        const text = `${button.textContent || ""} ${button.value || ""} ${button.getAttribute("aria-label") || ""}`;
        if (!SAVE_BUTTON.test(text)) return;
        if (!passwordFields().length) return;
        const form = button.closest("form")
          || (passwordFields()[0] && passwordFields()[0].form);
        captureSave(form);
      },
      true,
    );
  }

  // ------------------------------------------------------------- page scan

  function report() {
    const hasPassword = passwordFields().length > 0;
    if (!hasPassword && window.top !== window) return;
    send({
      type: "aurapass:page",
      url: location.href,
      title: document.title,
      hasPassword,
      wantFill: hasPassword,
    }).then((reply) => {
      if (reply && reply.ok && Array.isArray(reply.items)) {
        matches = uniqueItems(reply.items);
        if (panel) renderOverlayList(overlayQuery);
        else scheduleTriggerRefresh();
      }
    });
  }

  function attachFieldListeners() {
    document.addEventListener("focusin", () => {
      if (prefs && prefs.autofill === false) return;
      scheduleTriggerRefresh();
    }, true);
    document.addEventListener("focusout", () => {
      // Let a click or Tab into the panel land before hiding.
      setTimeout(() => {
        if (!panel) return;
        // Focus inside a shadow root is reported on the root, not on
        // `document.activeElement`, so check the shadow root first.
        if (shadow && shadow.activeElement && panel.contains(shadow.activeElement)) return;
        if (document.activeElement && panel.contains(document.activeElement)) return;
        hideOverlay();
      }, 150);
    }, true);
    const reposition = () => {
      if (panel) hideOverlay();
      else scheduleTriggerRefresh();
    };
    window.addEventListener("scroll", reposition, true);
    document.addEventListener("scroll", reposition, true);
    window.addEventListener("resize", reposition);
    if (globalThis.MutationObserver && !triggerObserver) {
      triggerObserver = new MutationObserver(scheduleTriggerRefresh);
      triggerObserver.observe(document.documentElement, { childList: true, subtree: true });
    }
  }

  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || typeof message !== "object") {
      sendResponse({ ok: false });
      return false;
    }
    switch (message.type) {
      case "aurapass:ping":
        sendResponse({ ok: true, pong: true });
        return false;
      case "aurapass:fill": {
        const fields = fillItem(message.item || {}, {
          silent: Boolean(message.silent),
          submit: Boolean(message.submit),
        });
        sendResponse({ ok: true, filled: fields > 0, fields });
        return false;
      }
      case "aurapass:fill-password": {
        const filled = fillGenerated(String(message.password ?? ""));
        sendResponse({ ok: true, filled: filled > 0 });
        return false;
      }
      case "aurapass:updated-matches":
        matches = uniqueItems(message.items);
        if (panel) renderOverlayList(overlayQuery);
        else scheduleTriggerRefresh();
        sendResponse({ ok: true });
        return false;
      case "aurapass:settings-changed":
        if (message.settings) prefs = message.settings;
        applyTheme();
        if (prefs && prefs.autofill === false) removeAllTriggers();
        else scheduleTriggerRefresh();
        sendResponse({ ok: true });
        return false;
      default:
        sendResponse({ ok: false, error: { message: "unknown request" } });
        return false;
    }
  });

  // ------------------------------------------------------------------ boot

  async function boot() {
    if (!document.body) {
      document.addEventListener("DOMContentLoaded", boot, { once: true });
      return;
    }
    // Read the preferences once; every behaviour below is gated on them.
    const reply = await send({ type: "aurapass:settings" });
    if (reply && reply.ok && reply.settings) prefs = reply.settings;

    // Honour the "work inside frames" preference: a sub-frame that the user
    // opted out of stops here, before it touches the page.
    if (window.top !== window) {
      if (prefs && prefs.injectInFrames === false) return;
      if (!passwordFields().length) return;
    }
    // The app's appearance choice can change while this page is open.
    globalThis.matchMedia?.("(prefers-color-scheme: dark)")
      .addEventListener?.("change", applyTheme);

    // Save prompts are independent of autofill. Someone who turned the
    // dropdown off still expects the browser to offer to store a new login.
    watchForms();
    if (!prefs || prefs.autofill !== false) {
      attachFieldListeners();
      report();
    }
    if (window.top === window) claimPendingSave();
  }

  boot();
  window.addEventListener("pageshow", () => {
    if (!prefs || prefs.autofill !== false) report();
  });
})();
