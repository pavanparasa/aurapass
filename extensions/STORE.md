# Submitting AuraPass to the extension stores

Both stores accept a **zip of the extension folder**; neither accepts our local
`.crx`. The store signs the package with its own key and serves that signed
copy to users.

| Store | Upload | Notes |
| --- | --- | --- |
| Chrome Web Store | `dist/aurapass-chromium-1.0.0.zip` | The dashboard re-packages and signs it; our `.crx` is not uploadable. |
| Firefox AMO | `dist/aurapass-firefox-1.0.0.xpi` (or the `.zip`) | AMO signs the `.xpi`; the unsigned file only installs in Developer Edition/Nightly. |

## Why the local `.crx` says `CRX_REQUIRED_PROOF_MISSING`

Chrome only installs a `.crx` that carries the Web Store's proof, or one that a
managed device receives through enterprise policy. A locally built, correctly
signed CRX is still rejected when dragged onto `chrome://extensions`; this has
been true since Chrome 75 and is not a defect in the package. There is no
manifest flag or signature that can change it.

Use **Load unpacked** for local installs (the `.deb` ships the folder at
`/usr/share/aurapass/extensions/chromium`), or publish the zip and install from
the store. Keep the `.crx` for policy/enterprise deployments and archives.

## Listing copy

- **Name:** AuraPass
- **Summary (≤132 chars):** Offline-first password manager. Fill logins and
  one-time codes from your own encrypted AuraPass vault — no cloud, no account.
- **Category:** Productivity → Password manager
- **Language:** English
- **Single purpose:** Fill saved credentials and one-time codes from a local
  AuraPass vault into web pages, and offer to save new logins.

### Description

AuraPass is the browser companion for the AuraPass desktop password manager. It
talks only to the AuraPass application running on the same computer, over the
loopback interface, and only after you approve the browser in the app.

- Fills usernames, passwords and one-time codes.
- Suggests the logins that match the page you are on.
- Offers to save a login you just used.
- Shows the matching logins inside the page, in light or dark mode.
- No account, no telemetry, no remote server. The vault stays encrypted on your
  computer.

AuraPass for Linux is required; the extension cannot read a vault by itself.

## Permission justifications

| Permission | Why |
| --- | --- |
| `storage` | Remember the approval secret, the bridge port and the display preferences. |
| `activeTab` / `scripting` | Fill the page the user is looking at when they pick a login. |
| `clipboardWrite` | Copy a password or one-time code when the user asks. |
| `alarms` | Wake the background worker periodically to reconnect to the local app. |
| `http://*/*`, `https://*/*` | Detect login forms and fill them on the sites the user visits. Nothing leaves the browser except the loopback connection. |
| Host `ws://127.0.0.1` | Not requested: WebSocket connections do not need a host permission. |

## Privacy practices (Chrome Web Store questionnaire)

- Does the extension collect or use personal data? **No data leaves the
  device.** Credentials are read from the local AuraPass vault and written into
  the page the user chose.
- Sold to third parties: **no**.
- Used for purposes unrelated to the single purpose: **no**.
- Used to determine creditworthiness: **no**.
- The extension stores a per-browser pairing secret and preferences locally.
- Privacy policy URL: see `PRIVACY.md`; host that text on a public URL before
  submitting (the dashboard requires a link).

## Assets the dashboard asks for

- 128×128 store icon: `extensions/shared/icons/icon128.png`.
- At least one screenshot, 1280×800 or 640×400 (Chrome), and at least one
  1280×800 or 640×480 (AMO). Take these from the popup, the in-page login menu
  and the options page after a real install.
- Small promotional tile 440×280 (Chrome, optional).
- A public privacy-policy URL (required by Chrome for password managers).

## Before every upload

```sh
./extensions/build.sh --test --zip
node tools/test-crypto.mjs        # if not covered by --test
```

Then check that `manifest.json` still validates in `chrome://extensions` and in
`about:debugging`, and that the version is bumped in both manifests.
