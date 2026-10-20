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
      .panel, .banner {
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
      .panel[data-ap-theme="dark"],
      .banner[data-ap-theme="dark"] {
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
        position: fixed; right: 16px; bottom: 16px; max-width: 324px;
        background: var(--ap-panel); color: var(--ap-ink);
        border: 1px solid var(--ap-line);
        border-radius: 13px;
        box-shadow: 0 14px 36px rgba(15,23,42,.26), 0 2px 6px rgba(15,23,42,.08);
        font: 13px/1.45 Inter, -apple-system, "Segoe UI", Roboto, sans-serif;
        padding: 13px; display: flex; flex-direction: column; gap: 9px;
        animation: ap-in 120ms ease-out;
      }
      .banner h4 { margin: 0; font-size: 13.5px; font-weight: 650; }
      .banner p { margin: 0; color: var(--ap-muted); font-size: 12px; word-break: break-all; }
      .row { display: flex; gap: 8px; justify-content: flex-end; }
      .row button {
        all: unset; cursor: pointer; padding: 6px 11px; border-radius: 8px;
        font-weight: 600; font-size: 12px;
      }
      .row button.primary { background: var(--ap-accent); color: #fff; }
      .row button.ghost { color: var(--ap-muted); }
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

  /** Items matching the little search box, ignoring case. */
  function searchedMatches(query) {
    const needle = String(query || "").trim().toLowerCase();
    if (!needle) return matches;
    return matches.filter((item) =>
      `${item.title || ""} ${item.username || ""}`.toLowerCase().includes(needle));
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

  function showBanner(title, body, actions = []) {
    const root = ensureShadow();
    if (banner) banner.remove();
    banner = document.createElement("div");
    banner.className = "banner";
    banner.dataset.apTheme = resolvedTheme();
    const heading = document.createElement("h4");
    heading.textContent = title;
    const paragraph = document.createElement("p");
    paragraph.textContent = body;
    banner.append(heading, paragraph);
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

  function offerSave(form) {
    if (prefs && prefs.savePrompt === false) return;
    const credentials = formCredentials(form);
    if (!credentials || !credentials.password) return;
    if (lastFilled && lastFilled.password === credentials.password
      && lastFilled.username === credentials.username) {
      return; // Nothing new to offer.
    }
    const known = matches.some((item) =>
      (item.username || "").toLowerCase() === (credentials.username || "").toLowerCase());
    if (known && lastFilled && lastFilled.id) return;

    showBanner(
      known ? "Update this login?" : "Save this login to AuraPass?",
      `${credentials.username || "(no username)"} — ${location.host}`,
      [
        {
          label: "Save",
          primary: true,
          run: async () => {
            const reply = await send({
              type: "aurapass:save",
              url: location.href,
              username: credentials.username,
              password: credentials.password,
              title: document.title || location.host,
            });
            if (reply && reply.ok) {
              lastFilled = { ...credentials, id: reply.outcome && reply.outcome.id };
              showBanner("Saved", "Stored in AuraPass.");
            } else {
              showBanner("Could not save", (reply && reply.error && reply.error.message) || "Try again.");
            }
          },
        },
        { label: "Not now", run: () => {} },
      ],
    );
  }

  function watchForms() {
    document.addEventListener(
      "submit",
      (event) => {
        const form = event.target;
        if (form instanceof HTMLFormElement && form.querySelector("input[type=password]")) {
          // Let the page navigate first, then offer to save.
          setTimeout(() => offerSave(form), 400);
        }
      },
      true,
    );
    // Single-page apps often never fire `submit`.
    document.addEventListener(
      "click",
      (event) => {
        const target = event.target;
        if (!(target instanceof Element)) return;
        const button = target.closest("button, input[type=submit], [role=button]");
        if (!button) return;
        const text = `${button.textContent || ""} ${button.value || ""} ${button.getAttribute("aria-label") || ""}`;
        if (!/sign\s?in|log\s?in|submit|continue|next/i.test(text)) return;
        const form = button.closest("form")
          || (passwordFields()[0] && passwordFields()[0].form);
        if (form) setTimeout(() => offerSave(form), 600);
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
      }
    });
  }

  function attachFieldListeners() {
    const handler = (event) => {
      if (prefs && prefs.autofill === false) return;
      const target = event.target;
      if (!(target instanceof HTMLInputElement)) return;
      const isPassword = target.type === "password";
      const isUsername = !isPassword && USERNAME_HINTS.test(
        `${target.name} ${target.id} ${target.autocomplete} ${target.placeholder}`,
      );
      if (!isPassword && !isUsername) return;
      if (!matches.length) return;
      showOverlay(target);
    };
    document.addEventListener("focusin", handler, true);
    document.addEventListener("focusout", (event) => {
      // Let a click or Tab into the panel land before hiding.
      setTimeout(() => {
        if (!panel) return;
        // Focus inside a shadow root is reported on the root, not on
        // `document.activeElement`, so check the shadow root first.
        if (shadow && shadow.activeElement && panel.contains(shadow.activeElement)) return;
        if (document.activeElement && panel.contains(document.activeElement)) return;
        hideOverlay();
      }, 150);
      void event;
    }, true);
    window.addEventListener("scroll", () => {
      if (panel) hideOverlay();
    }, true);
    window.addEventListener("resize", () => {
      if (panel) hideOverlay();
    });
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
        sendResponse({ ok: true });
        return false;
      case "aurapass:settings-changed":
        if (message.settings) prefs = message.settings;
        applyTheme();
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
    if (prefs && prefs.autofill === false) return;

    // Honour the "work inside frames" preference: a sub-frame that the user
    // opted out of stops here, before it touches the page.
    if (window.top !== window) {
      if (prefs && prefs.injectInFrames === false) return;
      if (!passwordFields().length) return;
    }
    // The app's appearance choice can change while this page is open.
    globalThis.matchMedia?.("(prefers-color-scheme: dark)")
      .addEventListener?.("change", applyTheme);
    watchForms();
    attachFieldListeners();
    report();
  }

  boot();
  window.addEventListener("pageshow", report);
})();
