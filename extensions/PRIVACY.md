# AuraPass browser extension — privacy policy

_Last updated: 20 October 2026_

AuraPass is an offline-first password manager. The browser extension exists for
one purpose: to fill credentials from **your own** AuraPass vault into web pages
you choose, and to offer to save new logins back to that vault.

## What the extension handles

- **Vault credentials** (site, username, password, one-time-code secret) are
  requested from the AuraPass application running on the same computer, over a
  connection bound to `127.0.0.1`. They are written into the page you selected
  and are not kept by the extension.
- **A pairing secret** issued by the desktop app is stored in the browser's
  local extension storage, so the app recognises this browser.
- **Preferences** (theme, autofill toggles) are stored locally in the browser.
- **The addresses and titles of pages you visit** are read locally to find login
  forms and matching entries. They are not transmitted anywhere except to the
  local AuraPass app, and are not retained after the page is closed.

## What the extension never does

- No account, registration or sign-in.
- No analytics, telemetry, crash reporting or advertising.
- No connection to a remote server. The only network peer is the AuraPass
  application on `127.0.0.1`.
- No selling, sharing or transferring of data to third parties.
- No collection of health, financial, authentication or personal communications
  data beyond the credentials you explicitly ask it to fill.

## Storage and deletion

Everything the extension stores stays in the browser profile on your computer.
Removing the extension, or using **Forget this browser** in AuraPass, deletes
the pairing secret. Uninstalling the AuraPass desktop application and deleting
its config directory removes the vault references and the pairing list.

## Contact

The extension is published by **pa1**. For questions about this policy, open an
issue in the AuraPass project or contact the publisher address shown on the
store listing.
