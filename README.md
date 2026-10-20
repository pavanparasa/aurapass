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

## Install

### Debian package

```sh
packaging/build-deb.sh
sudo apt install ./dist/aurapass_1.0.0_amd64.deb
```

This installs `aurapass-desktop`, `aurapass` and `aurapass-bridge`, a desktop
entry, icons, man pages, and the browser extensions under
`/usr/share/aurapass/extensions/`.

### From source

The build environment lives inside the repository; nothing is installed
system-wide.

```sh
scripts/bootstrap-toolchain.sh     # one-off, downloads Rust into .toolchain/
source scripts/env.sh              # required in every shell: sets PATH and target dir
cargo build --release --workspace
```

Binaries land in `target/release/`. To run the desktop app without installing:

```sh
cargo build -p aurapass-gui
./target/debug/aurapass-desktop
```

## Quick start

```sh
aurapass init ~/AuraPass/personal.aurapass
aurapass add -t GitHub -u alice --generate -U https://github.com --totp 'JBSWY3DPEHPK3PXP'
aurapass list
aurapass get GitHub password | wl-copy
aurapass otp GitHub
aurapass audit --breach
```

Every command accepts a vault path (`-v`), or reads `$AURAPASS_VAULT`, or uses
the most recently opened vault.

For scripting, keep the password out of the process list with a file or stdin:

```sh
printf '%s\n' "$MASTER" | aurapass --password-stdin list --json
```

## The desktop app

`aurapass-desktop` opens the vault, and once a vault is unlocked it stays out of
the way.

* **Tray icon.** AuraPass registers a StatusNotifierItem with a menu: *Open
  AuraPass*, *Quick assistant*, *Lock vault*, *Quit*. The icon is monochrome and
  drawn at runtime, so it suits a dark panel; **Settings → Appearance** has a
  *dark tray icon* switch for light panels.
* **Close to tray.** Closing the window hides it — the menu bar's *Quit* (or the
  tray's) really quits. Both behaviours are switches in the settings window.
* **Quick assistant.** *Quick assistant* opens the generator as a compact,
  always-on-top **400×450** panel centred on the screen, with rounded corners,
  a subtle border and shadow: password, passphrase and PIN modes, a live
  entropy estimate, and a **session-only** history you can copy from. Nothing
  in that history is ever written to disk, and the panel folds away as soon as
  you click somewhere else.
* **Open at login.** **Settings → Startup** enables or disables a per-user XDG
  autostart entry. It writes only `~/.config/autostart/aurapass.desktop`; no
  root access or system-wide change is involved, and the vault still starts
  locked.
* **Look and feel.** iced with the `tiny-skia` software renderer, so the
  interface is drawn on the CPU: no GPU, no EGL, no OpenGL driver, and no
  Mesa/`libLLVM` mapping in the process. A light theme by default (with a dark
  option, or follow the system), one purple accent, generous spacing, and
  [Lucide](https://lucide.dev) icons bundled with the app — so the artwork is
  crisp, inherits the theme's text colour, and depends on no system icon
  theme. Type is [Inter](https://rsms.me/inter), bundled as a variable font.

Settings and remembered vaults live in
`${XDG_CONFIG_HOME:-~/.config}/aurapass/config.json`. Set `AURAPASS_CONFIG_DIR`
to point them somewhere else.

If the tray icon does not appear, the desktop needs a StatusNotifier host:
GNOME users should have the *AppIndicator and KStatusNotifierItem* extension
enabled. Without a host, AuraPass notices that the tray could not register and
falls back to quitting on close, so the window is never lost.

## Browser extensions

```sh
./extensions/build.sh --zip
```

writes, for each browser, a `.zip` (the folder itself: unpack it to *Load
unpacked*, or upload it to the Chrome Web Store / AMO), plus a signed
`aurapass-chromium-1.0.0.crx` and an `aurapass-firefox-1.0.0.xpi`.

* **Chromium** — `chrome://extensions` → Developer mode → *Load unpacked* →
  `extensions/chromium` (in the package:
  `/usr/share/aurapass/extensions/chromium`). If Chrome is a Flatpak it cannot
  see `/usr/share`; copy the folder into your home first:
  `cp -r /usr/share/aurapass/extensions/chromium ~/.local/share/aurapass-chromium`
  and load that path.
* **Firefox** — `about:debugging#/runtime/this-firefox` → *Load Temporary
  Add-on* → `extensions/firefox/manifest.json`, or install the `.xpi`.

The bridge is reachable only from `127.0.0.1`. Approval issues a per-browser
secret; the handshake proves knowledge of it with an HMAC, derives a session key
with HKDF, and then seals every frame with XChaCha20-Poly1305 — so another local
user who can open the port still cannot read or forge a message. See
`extensions/README.md` for the full threat model.

## Vault format

```
offset  size         field
0       16           magic, "aurapass-vault\0"
16      4            format version (little-endian u32)
20      4            JSON header length (little-endian u32)
24      header_len   header JSON  (authenticated, not encrypted)
...     ...          body: XChaCha20-Poly1305 ciphertext of the item database
```

The header holds the KDF parameters, the wrapped master key and a random
nonce; it is authenticated as associated data, so a tampered header fails to
decrypt. The master key is wrapped with a key derived from the master password
(Argon2id) and the same for a key file when one is configured. Writes go to a
temporary file that is fsynced and renamed, so a crash cannot leave a
half-written vault.

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

## Repository layout

```
crates/aurapass-core     library: crypto, vault format, model, importers, audit
crates/aurapass-cli      the `aurapass` binary
crates/aurapass-gui      the `aurapass-desktop` binary
crates/aurapass-bridge   the bridge server and the `aurapass-bridge` binary
extensions/              Chromium and Firefox MV3 extensions
packaging/               Debian packaging and the .deb builder
scripts/                 in-repo toolchain bootstrap and env
vendor/iced_tiny_skia/   iced 0.14.1's renderer, with one local patch
```

### One patched dependency

`vendor/iced_tiny_skia/` is a copy of iced's software renderer, wired in with
`[patch.crates-io]`. Its `present()` always damages the whole window rather
than asking iced to diff one frame against the last: that diff merges damage
rectangles in a single pass, so overlapping translucent layers (anti-aliased
text, card shadows, the modal scrim) were composited more than once per frame
and crept towards black. The patch is marked with an "AuraPass patch" comment
in `src/window/compositor.rs`; everything else is upstream. See [NOTICE](NOTICE)
for attribution.

## Testing

```sh
source scripts/env.sh
cargo test --workspace                 # core, CLI, GUI and bridge unit tests
node extensions/tools/test-crypto.mjs  # ChaCha20/Poly1305/XChaCha20 RFC vectors
```
```sh
scripts/shoot.sh                       # the locked and unlocked windows
scripts/shoot.sh editor generator      # the main window with a dialog open
```
Memory is measured with `scripts/mem.sh`, which reports RSS, PSS and whether
any GPU driver is mapped.

The bridge also has a live interop test that drives a real `aurapass-bridge`
with the same JavaScript client the extension ships:

```sh
aurapass-bridge --vault ./my.aurapass --password-file ./pw --port 8791 &
node extensions/tools/test-bridge.mjs --token "$(aurapass bridge-info | awk '/Token:/{print $2}')" --port 8791
```

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
managers solve the problems of memory usage, speed & simpler UI/UX.

Licensed under either of

* Apache License, Version 2.0
* MIT license

at your option.
