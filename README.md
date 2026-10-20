# AuraPass

A local-first password manager for Linux, with a graphical app, a scriptable
command-line tool, and browser extensions for Chromium and Firefox.

Everything stays on your computer. There is no account, no sync service and no
telemetry. The vault is one file that you can copy, back up or delete. When the
browser extensions talk to AuraPass they do it over a WebSocket bound to
`127.0.0.1`, encrypted end to end with a pairing token.

```
aurapass 1.0.0
 ├── aurapass-desktop   iced graphical application   (also hosts the bridge)
 ├── aurapass           command-line tool
 ├── aurapass-bridge    headless host for the browser bridge
 └── extensions/        Chromium and Firefox extensions (MV3)
```

## Features

* **Vault** — Argon2id key derivation, XChaCha20-Poly1305 authenticated
  encryption, a versioned documented container, atomic `0600` writes, and
  optional key files.
* **Items** — logins, passwords, credit cards, identities, SSH keys, API keys,
  Wi-Fi, software licences, databases, servers and secure notes, each with
  URLs, notes, custom (optionally secret) fields, tags and categories.
* **One-time passwords** — TOTP and HOTP, RFC 6238/4226 compliant, usable from
  the CLI, the desktop app and the browser popup.
* **Generator** — diceware passphrases from the EFF long word list, PINs, and
  passwords with an entropy estimate.
* **Health** — a weakness/reuse/age audit, optional Have I Been Pwned breach
  checks by hash prefix (k-anonymity: the password never leaves the machine),
  and per-item password history.
* **Import/export** — Enpass JSON and CSV, Bitwarden JSON and CSV, LastPass
  CSV, 1Password CSV, Chrome CSV, KeePass CSV, and a generic CSV/JSON, with
  format auto-detection. Export to CSV, JSON or an encrypted backup.
* **Browser integration** — autofill, TOTP, save prompts, a search popup and a
  generator, over an authenticated loopback bridge.
* **Desktop shell** — a tray icon with a menu, close-to-tray, a **quick
  assistant** pop-up with a generator and a session-only history, a light or
  dark theme, and crisply drawn icons throughout (no emoji).
* **Unlock PIN** — the master password is asked once per desktop login; after
  that a 4–12 digit PIN reopens the vault. The PIN is bound to the current boot
  and logind session and can be changed or removed in Settings → Security.
* **Utilities** — activity log, bin with restore, favourites, and a
  `--json` mode on the commands meant for scripting.

## Security model

| Concern | Approach |
|---|---|
| Data at rest | Argon2id + XChaCha20-Poly1305, authenticated header, `0600` |
| Data in transit | loopback-only WebSocket, token-authenticated, sealed frames |
| A malicious web page | content scripts never hold the token or reach the bridge |
| Memory | decrypted keys and passwords use `zeroize` |
| Damage to the vault file | atomic replace; the previous file survives a failed write |
| Unlock PIN | the master key is wrapped again under Argon2id(PIN), tied to the boot/logind session and disabled after five wrong tries — a convenience for a trusted desktop, not a substitute for the master password |
| Privacy | no telemetry; breach checks send only a 5-character SHA-1 prefix |

## Limitations

AuraPass is a working clone, not a finished commercial product. Known limits:

* **One writer at a time.** The desktop app, the CLI and a standalone
  `aurapass-bridge` all read and write the same vault file. If two of them are
  open on the same vault, the last one to save wins. Run one at a time.
* **No sync.** The vault is a single file. Copy it yourself if you want it on
  more than one machine, and do not edit it from two machines at once.
* **Remote unlock is opt-in.** The popup can only unlock a vault when the
  desktop app (or `aurapass-bridge --allow-remote-unlock`) permits it.
* **Autofill is heuristic.** It recognises login forms by their structure and
  autocomplete hints. Unusual or heavily scripted sign-in pages may need a
  manual copy from the popup.
* **Linux only.** There is no macOS or Windows build. The graphical app needs
  X11 (or XWayland, which every current Ubuntu session provides) but no GPU: it
  renders in software. It deliberately runs through XWayland on Wayland
  desktops, because Wayland gives clients no way to unmap a window into the tray
  or to centre and style the frameless quick-assistant panel reliably.
* **The extension is not a browser-settings switch.** Browsers do not let an
  extension disable their built-in password manager. The *Make AuraPass my
  password manager* toggle opens the browser's own password settings and
  explains what to turn off.
* **Memory.** Measured with `scripts/mem.sh` on a 1180x760 window:

  | state | RSS | PSS | GPU-driver mappings |
  |---|---|---|---|
  | locked, idle | 38 MB | 23 MB | 0 |
  | unlocked, idle | 42 MB | 27 MB | 0 |
  | unlocked, bridge running | 42 MB | 34 MB | 0 |

## Credit and licence

AuraPass is independent software. It was inspired by the way other password
managers to solve the problems of memory usage, speed & simpler UI/UX.

Licensed under either of

* Apache License, Version 2.0
* MIT license

at your option.
