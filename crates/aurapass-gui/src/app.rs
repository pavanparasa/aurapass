//! Application state, messages and the root layout.
//!
//! AuraPass follows the Elm shape iced asks for: one [`AppState`], one
//! [`Message`] enum, one `update` and one `view`. Screens live in their own
//! modules and expose `Message` / `update` / `view` triples; this file owns the
//! chrome that wraps them and the things that are genuinely global — the vault,
//! the tray, the browser bridge, the clipboard timer and the auto-lock clock.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use aurapass_bridge::RunningBridge;
use aurapass_core::config::AppConfig;
use aurapass_core::pin::MAX_PIN_ATTEMPTS;
use aurapass_core::vault::{SortOrder, UnlockedVault, VaultFile};
use chrono::Local;
use iced::widget::{column, container, row, Stack};
use iced::{Alignment, Element, Length, Subscription, Task, Theme};
use uuid::Uuid;

use crate::assistant::AssistantState;
use crate::browse::BrowseState;
use crate::editor::EditorState;
use crate::glyph::{self, Glyph};
use crate::theme::{self, Tokens};
use crate::tools::{self, ToolsState};
use crate::tray::{Tray, TrayCommand};
use crate::unlock::UnlockState;
use crate::widgets as w;

/// The size of the compact quick-assistant pop-up.
pub const POPUP_SIZE: iced::Size = iced::Size::new(400.0, 450.0);

/// Corner radius of the compact quick-assistant panel.
pub const POPUP_RADIUS: f32 = 10.0;

/// Transparent margin around the assistant used for its drop shadow.
pub const POPUP_SHADOW_MARGIN: f32 = 12.0;

/// The assistant's outer window: the 400x450 panel plus room for the shadow.
pub const POPUP_WINDOW_SIZE: iced::Size = iced::Size::new(
    POPUP_SIZE.width + POPUP_SHADOW_MARGIN * 2.0,
    POPUP_SIZE.height + POPUP_SHADOW_MARGIN * 2.0,
);

/// The smallest the full window may get before the three panes stop making
/// sense. The pop-up is allowed to be smaller, so this is raised and lowered
/// around `POPUP_SIZE` as the window changes role.
pub const MAIN_MIN_SIZE: iced::Size = iced::Size::new(900.0, 620.0);

/// Which top-level screen is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// No vault is open.
    Unlock,
    /// The browser.
    Main,
}

/// Move the assistant to the exact centre of the monitor it is on.
fn center_on_monitor(id: iced::window::Id) -> Task<Message> {
    iced::window::monitor_size(id).then(move |maybe| match maybe {
        Some(size) => iced::window::move_to(
            id,
            iced::Point::new(
                ((size.width - POPUP_WINDOW_SIZE.width) / 2.0).max(0.0),
                ((size.height - POPUP_WINDOW_SIZE.height) / 2.0).max(0.0),
            ),
        ),
        None => Task::none(),
    })
}

/// A transient message in the bottom-right corner.
#[derive(Debug, Clone)]
pub struct Toast {
    /// What to say.
    pub text: String,
    /// Whether it reports a failure.
    pub error: bool,
    /// When it appeared; toasts expire after a few seconds.
    pub at: Instant,
}

/// An action that needs explicit confirmation first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmAction {
    /// Move an item to the bin.
    Trash(Uuid),
    /// Destroy every item in the bin.
    EmptyBin,
    /// Delete a category, leaving its items uncategorised.
    DeleteCategory(Uuid),
}

/// A yes/no dialog.
#[derive(Debug, Clone)]
pub struct Confirm {
    /// Headline.
    pub title: String,
    /// Explanation.
    pub body: String,
    /// Label on the affirmative button.
    pub yes: String,
    /// Whether the affirmative action is destructive (colours the button red).
    pub danger: bool,
    /// What to run when confirmed.
    pub action: ConfirmAction,
}

/// Everything that can happen.
#[derive(Debug, Clone)]
pub enum Message {
    // ------------------------------------------------------------ lifecycle
    /// The window id has been resolved.
    Ready(Option<iced::window::Id>),
    /// A 500 ms heartbeat: tray polling, auto-lock, toasts, the clipboard timer.
    Tick(Instant),
    /// A window event.
    Window(iced::window::Id, iced::window::Event),
    /// The desktop's colour preference, for `system` theme mode.
    SystemTheme(iced::theme::Mode),
    /// A keyboard event no widget claimed.
    Key(iced::keyboard::Event),

    // -------------------------------------------------------------- commands
    /// Lock the vault.
    Lock,
    /// Ask before doing something irreversible.
    Ask(ConfirmAction),
    /// The user confirmed.
    Confirm,
    /// The user declined.
    Dismiss,
    /// Allow the browser that is asking to connect.
    PairAllow,
    /// Refuse the browser that is asking to connect.
    PairDeny,
    /// Switch to the next theme (system → light → dark).
    CycleTheme,

    // ---------------------------------------------------------------- screens
    /// The unlock / create-vault screen.
    Unlock(crate::unlock::Message),
    /// The browser.
    Browse(crate::browse::Message),
    /// The item editor.
    Editor(crate::editor::Message),
    /// The auxiliary dialogs.
    Tools(crate::tools::Message),
    /// The quick assistant.
    Assistant(crate::assistant::Message),
}

/// The whole application.
pub struct AppState {
    /// Persistent preferences.
    pub config: AppConfig,
    /// Which screen is showing.
    pub screen: Screen,
    /// Unlock-screen form state.
    pub unlock: UnlockState,
    /// The open vault, when unlocked.
    pub vault: Option<UnlockedVault>,
    /// Browser state: filters and selection.
    pub browse: BrowseState,
    /// The item being edited, when the editor is open.
    pub editor: Option<EditorState>,
    /// Auxiliary dialogs.
    pub tools: ToolsState,
    /// The quick assistant.
    pub assistant: AssistantState,

    /// The main window.
    pub window: iced::window::Id,
    /// The last known window size, in logical pixels.
    pub window_size: iced::Size,
    /// The window is hidden in the tray.
    pub window_hidden: bool,
    /// The compact assistant is taking over the window.
    pub assistant_only: bool,
    /// The window size to restore when the pop-up goes away.
    pub restore_size: Option<iced::Size>,
    /// When the compact pop-up was opened, so a focus flicker at launch is
    /// not mistaken for the user clicking away.
    popup_opened_at: Option<Instant>,
    /// The assistant replaced a visible main window, so closing it should
    /// restore that window rather than hide it to the tray.
    popup_from_main: bool,
    /// The user asked to leave; do not intercept the close request.
    pub quitting: bool,
    /// Whether the window currently has native decorations. The compact
    /// assistant is frameless, so this is toggled around it.
    decorations_on: bool,

    /// The tray icon, when a StatusNotifier host is present.
    pub tray: Option<Tray>,
    /// Why the tray is unavailable, when it is.
    pub tray_error: Option<String>,

    /// The in-process browser bridge.
    pub bridge: Option<RunningBridge>,
    /// Why the bridge is not running, when it is not.
    pub bridge_error: Option<String>,

    /// Transient messages.
    pub toasts: Vec<Toast>,
    /// When to wipe the clipboard.
    pub clipboard_clear_at: Option<Instant>,
    /// When the vault first went dirty, so autosave can wait a beat.
    pub dirty_since: Option<Instant>,
    /// A pending confirmation.
    pub confirm: Option<Confirm>,
    /// A browser waiting for the user to approve it.
    pub pairing: Option<aurapass_bridge::PairPrompt>,
    /// Whether this session can hide its window (i.e. it is running on X11).
    pub hide_supported: bool,
    /// Fingerprint of the current desktop login session, for PIN unlock.
    pub pin_session: String,

    /// Seconds since the epoch, refreshed on every tick; TOTP codes hang off it.
    pub now_unix: u64,
    /// Local time, refreshed on every tick.
    pub now_local: chrono::DateTime<Local>,
    /// What the desktop wants, used when the theme is set to `system`.
    pub system_mode: iced::theme::Mode,

    /// Development aid: capture the window to this PPM path and exit.
    shot: Option<String>,
    /// Whether the capture has been requested.
    shot_done: bool,
    /// Whether the later "does the artwork drift?" capture has been taken.
    shot2_done: bool,
    /// Whether the dev capture has already arranged the screen it wants.
    shot_setup_done: bool,
    /// How many heartbeats have elapsed.
    ticks: u64,
}

impl AppState {
    // ------------------------------------------------------------- lifecycle

    /// Build the application.
    pub fn boot() -> (Self, Task<Message>) {
        let config = AppConfig::load();

        let mut tray_error = None;
        let tray = if config.tray_enabled {
            match Tray::start(config.tray_icon_dark) {
                Ok(tray) => Some(tray),
                Err(e) => {
                    eprintln!("aurapass: system tray unavailable ({e})");
                    tray_error = Some(e);
                    None
                }
            }
        } else {
            None
        };

        let unlock = UnlockState {
            path: config
                .pinned_vaults()
                .first()
                .map(|v| v.path.display().to_string())
                .unwrap_or_default(),
            ..UnlockState::default()
        };
        let pin_session = aurapass_core::pin::session_fingerprint();

        let window = iced::window::Id::unique();
        let size = shot_size()
            .unwrap_or_else(|| iced::Size::new(config.window.width, config.window.height));

        let mut state = Self {
            config,
            screen: Screen::Unlock,
            unlock,
            vault: None,
            browse: BrowseState::default(),
            editor: None,
            tools: ToolsState::default(),
            assistant: AssistantState::default(),
            window,
            window_size: size,
            window_hidden: false,
            assistant_only: false,
            restore_size: None,
            popup_opened_at: None,
            popup_from_main: false,
            quitting: false,
            decorations_on: true,
            tray,
            tray_error,
            bridge: None,
            bridge_error: None,
            toasts: Vec::new(),
            clipboard_clear_at: None,
            dirty_since: None,
            confirm: None,
            pairing: None,
            hide_supported: std::env::var_os("DISPLAY").is_some(),
            pin_session,
            now_unix: 0,
            now_local: Local::now(),
            system_mode: iced::theme::Mode::default(),
            shot: std::env::var("AURAPASS_SHOT").ok(),
            shot_done: false,
            shot2_done: false,
            shot_setup_done: false,
            ticks: 0,
        };

        if let Some(e) = &state.tray_error {
            state.notify_error(format!(
                "No system tray on this desktop ({e}). Closing AuraPass will quit it."
            ));
        }

        // Offer the PIN immediately when this session already has one for the
        // remembered vault.
        state.refresh_pin_mode();

        // The bridge starts with the app, not with the vault: a browser can be
        // approved while the vault is still locked, and the extension gets a
        // clear "locked" answer instead of "AuraPass is not running".
        if state.config.bridge.enabled {
            state.start_bridge();
        }

        // Keep the per-user XDG autostart entry in sync with the preference.
        // Re-enabling also repairs the entry after the binary has moved, while
        // an entry created by an older build is reflected in the checkbox.
        if state.config.autostart {
            if let Err(e) = aurapass_core::autostart::enable() {
                state.notify_error(format!("could not update the startup entry: {e}"));
            }
        } else if aurapass_core::autostart::is_enabled() {
            state.config.autostart = true;
            state.save_config();
        }

        let resolved = iced::window::oldest().map(Message::Ready);
        let mode = iced::system::theme().map(Message::SystemTheme);
        (state, Task::batch([resolved, mode]))
    }

    /// The window title, so the taskbar entry names the vault.
    pub fn window_title(&self) -> String {
        match &self.vault {
            Some(v) => format!("{} — {}", v.name(), aurapass_core::APP_NAME),
            None => aurapass_core::APP_NAME.to_string(),
        }
    }

    /// The active theme. `system` follows the desktop's colour preference.
    pub fn theme(&self) -> Theme {
        match self.config.theme.as_str() {
            "light" => theme::light_theme(),
            "dark" => theme::dark_theme(),
            _ => {
                if self.system_mode == iced::theme::Mode::Dark {
                    theme::dark_theme()
                } else {
                    theme::light_theme()
                }
            }
        }
    }

    /// The window's own background.
    ///
    /// The main window is opaque. The quick assistant instead lets the desktop
    /// show through its rounded corners; its panel paints the actual surface.
    pub fn window_style(&self, theme: &Theme) -> iced::theme::Style {
        let mut style = iced::theme::default(theme);
        if self.assistant_only {
            style.background_color = iced::Color::TRANSPARENT;
        }
        style
    }

    /// Everything the runtime should keep an eye on.
    pub fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            iced::time::every(Duration::from_millis(500)).map(Message::Tick),
            iced::window::events().map(|(id, event)| Message::Window(id, event)),
            iced::system::theme_changes().map(Message::SystemTheme),
            iced::keyboard::listen().map(Message::Key),
        ])
    }

    // --------------------------------------------------------------- helpers

    /// Show a transient message.
    pub fn notify(&mut self, text: impl Into<String>) {
        self.toasts.push(Toast {
            text: text.into(),
            error: false,
            at: Instant::now(),
        });
    }

    /// Show a transient failure.
    pub fn notify_error(&mut self, text: impl Into<String>) {
        self.toasts.push(Toast {
            text: text.into(),
            error: true,
            at: Instant::now(),
        });
    }

    /// Copy a value, arm the auto-clear timer and say so.
    pub fn copy(&mut self, label: &str, value: String) -> Task<Message> {
        if value.is_empty() {
            self.notify_error("Nothing to copy");
            return Task::none();
        }
        let after = self
            .vault
            .as_ref()
            .map(|v| v.settings().clipboard_clear_secs)
            .unwrap_or(30);
        self.clipboard_clear_at = if after > 0 {
            Some(Instant::now() + Duration::from_secs(after))
        } else {
            None
        };
        self.notify(format!(
            "{label} copied{}",
            if after > 0 {
                format!(" — clears in {after}s")
            } else {
                String::new()
            }
        ));
        iced::clipboard::write(value)
    }

    /// Open a URL with the desktop's default handler.
    pub fn open_url(&mut self, url: &str) {
        let url = if url.contains("://") {
            url.to_string()
        } else {
            format!("https://{url}")
        };
        let _ = std::process::Command::new("xdg-open")
            .arg(&url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }

    /// Persist preferences.
    pub fn save_config(&mut self) {
        if let Err(e) = self.config.save() {
            self.notify_error(format!("could not save preferences: {e}"));
        }
    }

    /// Where a file dialog should start: the last directory the user used.
    pub fn last_directory(&self) -> Option<std::path::PathBuf> {
        self.config.last_directory.clone()
    }

    /// Remember the directory a chosen file came from, for the next dialog.
    pub fn remember_directory(&mut self, path: &std::path::Path) {
        if let Some(parent) = path.parent() {
            self.config.last_directory = Some(parent.to_path_buf());
            self.save_config();
        }
    }

    // ------------------------------------------------------------ vault I/O

    /// Unlock the vault named on the unlock screen.
    pub fn do_unlock(&mut self) {
        let path = PathBuf::from(crate::unlock::expand(&self.unlock.path));

        if self.unlock.use_pin {
            self.unlock_with_pin(&path);
            return;
        }

        let key = if self.unlock.key_file.trim().is_empty() {
            None
        } else {
            match std::fs::read(crate::unlock::expand(&self.unlock.key_file)) {
                Ok(bytes) => Some(bytes),
                Err(e) => {
                    self.unlock.error = Some(format!("key file: {e}"));
                    return;
                }
            }
        };
        let file = match VaultFile::load(&path) {
            Ok(file) => file,
            Err(e) => {
                self.unlock.error = Some(e.to_string());
                return;
            }
        };
        match file.unlock(&self.unlock.password, key.as_deref()) {
            Ok(vault) => {
                self.unlock.password.clear();
                self.unlock.pin.clear();
                self.unlock.error = None;
                // The master password is allowed to renew the PIN for this
                // desktop session (that is what makes it "once per login").
                self.renew_pin_session(&path);
                self.after_unlock(vault, &path);
            }
            Err(e) => self.unlock.error = Some(e.to_string()),
        }
    }

    /// The PIN entry for the selected vault, if it is live in this session.
    pub fn pin_entry_for_selected(&self) -> Option<&aurapass_core::pin::PinUnlock> {
        let path = PathBuf::from(crate::unlock::expand(&self.unlock.path));
        self.config
            .pin_for(&path)
            .filter(|pin| pin.is_live(&self.pin_session))
    }

    /// Whether the "Unlock with your PIN" affordance should be offered.
    pub fn pin_available_for_selected(&self) -> bool {
        self.pin_entry_for_selected().is_some()
    }

    /// Point the unlock screen at a PIN or at the master password.
    pub fn refresh_pin_mode(&mut self) {
        self.unlock.use_pin = self.pin_available_for_selected();
        self.unlock.pin.clear();
        if self.unlock.use_pin {
            self.unlock.password.clear();
        }
    }

    /// Re-bind a stored PIN to the current desktop session after a master
    /// unlock, so it keeps working until the user logs out.
    fn renew_pin_session(&mut self, path: &std::path::Path) {
        let session = self.pin_session.clone();
        if let Some(pin) = self.config.pin_unlocks.iter_mut().find(|p| p.vault == path) {
            pin.refresh_session(&session);
        }
    }

    /// Unlock using the session PIN.
    fn unlock_with_pin(&mut self, path: &std::path::Path) {
        let Some(entry) = self.config.pin_for(path).cloned() else {
            self.unlock.use_pin = false;
            self.unlock.error = Some("No PIN is stored for this vault. Enter the master password.".into());
            return;
        };
        if !entry.is_live(&self.pin_session) {
            self.unlock.use_pin = false;
            self.unlock.pin.clear();
            self.unlock.error =
                Some("This PIN expired. Enter the master password to set it up again.".into());
            return;
        }
        if self.unlock.pin.is_empty() {
            self.unlock.error = Some("Enter your PIN.".into());
            return;
        }
        let key = match entry.unwrap_key(&self.unlock.pin) {
            Ok(key) => key,
            Err(_) => {
                let mut exhausted = false;
                let mut left = 0;
                if let Some(stored) = self.config.pin_unlocks.iter_mut().find(|p| p.vault == path) {
                    exhausted = stored.record_failure();
                    left = MAX_PIN_ATTEMPTS.saturating_sub(stored.failures);
                }
                self.save_config();
                self.unlock.pin.clear();
                if exhausted {
                    self.unlock.use_pin = false;
                    self.unlock.error =
                        Some("Too many wrong PINs. Enter the master password to continue.".into());
                } else {
                    self.unlock.error = Some(format!(
                        "That PIN is not right. {left} attempt{} left.",
                        if left == 1 { "" } else { "s" }
                    ));
                }
                return;
            }
        };

        let file = match VaultFile::load(path) {
            Ok(file) => file,
            Err(e) => {
                self.unlock.error = Some(e.to_string());
                return;
            }
        };
        if file.info().vault_id.to_string() != entry.vault_id {
            self.unlock.error = Some("This PIN belongs to a different vault file.".into());
            return;
        }
        match file.unlock_with_key(key) {
            Ok(vault) => {
                self.unlock.pin.clear();
                self.unlock.error = None;
                self.renew_pin_session(path);
                self.after_unlock(vault, path);
            }
            Err(e) => self.unlock.error = Some(e.to_string()),
        }
    }

    /// Create a vault from the unlock screen's form.
    pub fn do_create(&mut self) {
        let path = PathBuf::from(crate::unlock::expand(&self.unlock.new_path));
        let name = if self.unlock.new_name.trim().is_empty() {
            path.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| aurapass_core::APP_NAME.to_string())
        } else {
            self.unlock.new_name.trim().to_string()
        };
        if self.unlock.new_password != self.unlock.new_confirm {
            self.unlock.error = Some("the two passwords do not match".into());
            return;
        }
        let pin = self.unlock.new_pin.trim().to_string();
        if pin != self.unlock.new_pin_confirm {
            self.unlock.error = Some("the two PINs do not match".into());
            return;
        }
        if let Err(e) = aurapass_core::pin::validate_pin(&pin) {
            self.unlock.error = Some(e.to_string());
            return;
        }
        let preset = match self.unlock.kdf.as_str() {
            "moderate" => aurapass_core::crypto::KdfPreset::Moderate,
            "paranoid" => aurapass_core::crypto::KdfPreset::Paranoid,
            _ => aurapass_core::crypto::KdfPreset::Interactive,
        };
        match VaultFile::create(&path, &self.unlock.new_password, &name, preset, None) {
            Ok(vault) => {
                match vault.pin_envelope(&pin, &self.pin_session) {
                    Ok(entry) => self.config.set_pin(entry),
                    Err(e) => self.notify_error(format!("the unlock PIN could not be set: {e}")),
                }
                self.unlock.creating = false;
                self.unlock.new_password.clear();
                self.unlock.new_confirm.clear();
                self.unlock.new_pin.clear();
                self.unlock.new_pin_confirm.clear();
                self.unlock.error = None;
                self.notify(format!("Created vault “{name}”"));
                self.after_unlock(vault, &path);
            }
            Err(e) => self.unlock.error = Some(e.to_string()),
        }
    }

    /// Bookkeeping once a vault becomes available.
    fn after_unlock(&mut self, vault: UnlockedVault, path: &std::path::Path) {
        let settings = vault.settings().clone();
        self.browse = BrowseState {
            sort: SortOrder::from_setting(&settings.sort_order),
            reveal: !settings.hide_secrets_default,
            ..BrowseState::default()
        };
        self.tools.reset_for_vault();
        self.assistant.use_policy(&settings.password_policy);
        self.editor = None;
        // Keep the unlock screen pointed at the vault that is open, so a later
        // lock can offer its PIN without a detour through the vault list.
        self.unlock.path = path.display().to_string();
        self.unlock.key_file.clear();
        self.config.remember_vault(path, vault.name().to_string());
        self.save_config();
        if self.config.bridge.enabled {
            self.start_bridge();
        }
        self.sync_bridge_vault();
        if let Some(tray) = &self.tray {
            tray.set_status(vault.name().to_string(), true);
        }
        self.vault = Some(vault);
        self.screen = Screen::Main;
        // Land on something: an empty detail pane is a poor first impression.
        self.browse.selected = self
            .vault
            .as_ref()
            .and_then(|v| v.query(&self.browse.query()).first().copied());
    }

    /// Development aid: put the window into a named state before a capture.
    ///
    /// Only ever runs when `AURAPASS_SHOT_MODAL` is set, which the shipped
    /// package never does; it exists so every dialog can be screenshotted
    /// without a human clicking through them.
    fn apply_shot_setup(&mut self) -> Task<Message> {
        let Ok(name) = std::env::var("AURAPASS_SHOT_MODAL") else {
            return Task::none();
        };
        match name.as_str() {
            "editor" => {
                if let Some(id) = self
                    .vault
                    .as_ref()
                    .and_then(|v| v.data().items.first().map(|i| i.id))
                {
                    self.start_edit(id);
                }
            }
            "assistant" => return self.enter_popup(false),
            "newitem" => self.tools.open = Some(tools::Modal::NewItem),
            "generator" => self.tools.open = Some(tools::Modal::Generator),
            "health" => {
                self.tools.open = Some(tools::Modal::Health);
                let _ = crate::tools::update(self, tools::Message::RunAudit);
            }
            "settings" => {
                self.tools.open = Some(tools::Modal::Settings);
                self.tools.settings = self.vault.as_ref().map(|v| v.settings().clone());
            }
            "activity" => self.tools.open = Some(tools::Modal::Activity),
            "import" => self.tools.open = Some(tools::Modal::Import),
            "export" => self.tools.open = Some(tools::Modal::Export),
            "password" => self.tools.open = Some(tools::Modal::ChangePassword),
            "bridge" => self.tools.open = Some(tools::Modal::Bridge),
            "about" => self.tools.open = Some(tools::Modal::About),
            "categories" => self.tools.open = Some(tools::Modal::Categories),
            _ => {}
        }
        Task::none()
    }

    /// Write the vault out if it has unsaved changes.
    ///
    /// Called by the autosave heartbeat, before locking, and on the way out;
    /// it stays quiet so a background save never interrupts with a toast.
    pub fn save_vault(&mut self) {
        let Some(vault) = self.vault.as_mut() else {
            return;
        };
        if vault.is_dirty()
            && let Err(e) = vault.save()
        {
            self.notify_error(format!("could not save: {e}"));
        }
        // The extension serves its own copy of the vault; keep it current.
        self.sync_bridge_vault();
    }

    /// Give the bridge the window's copy of the vault, so the extension sees
    /// exactly what is on screen.
    fn sync_bridge_vault(&self) {
        if let Some(running) = &self.bridge {
            running.bridge().set_vault(self.vault.clone());
        }
    }

    /// Lock the vault, saving first when needed.
    pub fn lock_vault(&mut self) {
        if let Some(vault) = self.vault.as_mut()
            && vault.is_dirty()
            && let Err(e) = vault.save()
        {
            self.notify_error(format!("could not save before locking: {e}"));
        }
        // Keep the bridge listening: it answers "locked" and can still ask the
        // user to approve a new browser, but it can no longer read anything.
        if let Some(running) = &self.bridge {
            running.bridge().set_vault(None);
        }
        if let Some(vault) = self.vault.take()
            && let Err(e) = vault.lock()
        {
            self.notify_error(e.to_string());
        }
        self.editor = None;
        self.confirm = None;
        self.browse.selected = None;
        self.screen = Screen::Unlock;
        self.unlock.password.clear();
        self.refresh_pin_mode();
        self.clipboard_clear_at = None;
        if let Some(tray) = &self.tray {
            tray.set_status(String::new(), false);
        }
    }

    // ------------------------------------------------------------ tray & window

    /// Bring the main window to the front.
    pub fn show_window(&mut self) -> Task<Message> {
        self.window_hidden = false;
        Task::batch([
            iced::window::set_mode(self.window, iced::window::Mode::Windowed),
            iced::window::minimize(self.window, false),
            iced::window::gain_focus(self.window),
        ])
    }

    /// Hide the main window into the tray.
    pub fn hide_window(&mut self) -> Task<Message> {
        // Without an X server there is no way to unmap the window, so hiding
        // would look like a dead button. Quit instead of lying to the user.
        if self.tray.is_none() || !self.hide_supported {
            return self.request_quit();
        }
        let restore = self.leave_popup();
        self.popup_from_main = false;
        self.window_hidden = true;
        Task::batch([
            restore,
            iced::window::set_mode(self.window, iced::window::Mode::Hidden),
        ])
    }

    /// Show the window if hidden, hide it if shown.
    pub fn toggle_window(&mut self) -> Task<Message> {
        if self.window_hidden {
            self.show_window()
        } else {
            self.hide_window()
        }
    }

    /// Undo the compact pop-up: drop always-on-top, restore the native frame
    /// and the previous size.
    fn leave_popup(&mut self) -> Task<Message> {
        if !self.assistant_only {
            return Task::none();
        }
        self.assistant_only = false;
        let mut tasks = vec![
            iced::window::set_level(self.window, iced::window::Level::Normal),
            iced::window::set_min_size(self.window, Some(MAIN_MIN_SIZE)),
            iced::window::set_resizable(self.window, true),
        ];
        if !self.decorations_on {
            self.decorations_on = true;
            tasks.push(iced::window::toggle_decorations(self.window));
        }
        if let Some(size) = self.restore_size.take() {
            tasks.push(iced::window::resize(self.window, size));
        }
        Task::batch(tasks)
    }

    /// Open the quick assistant, as the tray icon's entry does.
    ///
    /// The assistant is always the same compact, frameless panel. Clicking the
    /// tray entry never brings the full three-pane window forward, and the
    /// panel lands in the middle of the current monitor.
    pub fn open_assistant(&mut self) -> Task<Message> {
        self.open_assistant_at(None)
    }

    /// Open the compact assistant.
    ///
    /// `anchor` is accepted for protocol compatibility but intentionally not
    /// used: the panel is centred on screen for both the extension and the
    /// tray, so it is always in the same predictable place.
    pub fn open_assistant_at(&mut self, _anchor: Option<(f32, f32)>) -> Task<Message> {
        let from_main = !self.assistant_only && !self.window_hidden;
        self.enter_popup(from_main)
    }

    /// Take over the window with the frameless, centred assistant panel.
    fn enter_popup(&mut self, from_main: bool) -> Task<Message> {
        if !self.assistant_only {
            self.restore_size = Some(self.window_size);
            self.popup_from_main = from_main;
        }
        self.popup_opened_at = Some(Instant::now());
        self.window_hidden = false;
        self.assistant_only = true;
        let id = self.window;

        let mut tasks = vec![
            iced::window::set_mode(id, iced::window::Mode::Windowed),
            iced::window::set_level(id, iced::window::Level::AlwaysOnTop),
        ];
        // Drop the native frame before changing geometry. The window manager
        // accounts for the title bar while it is still present, which otherwise
        // leaves the pop-up a title bar taller than the requested 450 px.
        if self.decorations_on {
            self.decorations_on = false;
            tasks.push(iced::window::toggle_decorations(id));
        }
        tasks.extend([
            // Lock the panel *before* resizing it. winit's X11 `set_resizable`
            // writes the window's current size into the min/max size hints, so
            // calling it after `resize` would pin the assistant at the old
            // full-window dimensions. Once non-resizable, `resize` itself
            // updates those hints to the requested compact size.
            iced::window::set_resizable(id, false),
            // The pop-up is smaller than the main window; the window manager
            // would otherwise clamp it to the full window's minimum. The outer
            // window also has a margin for the shadow around the 400x450 panel.
            iced::window::set_min_size(id, Some(POPUP_WINDOW_SIZE)),
            iced::window::resize(id, POPUP_WINDOW_SIZE),
        ]);
        tasks.push(center_on_monitor(id));
        tasks.push(iced::window::gain_focus(id));
        Task::batch(tasks)
    }

    /// Answer the browser that is waiting for approval.
    fn answer_pairing(&mut self, allow: bool) -> Task<Message> {
        let Some(prompt) = self.pairing.take() else {
            return Task::none();
        };
        let Some(running) = &self.bridge else {
            return Task::none();
        };
        match running.bridge().resolve_pair(&prompt.id, allow) {
            Some(issued) => {
                self.config.bridge.paired.retain(|b| b.id != issued.id);
                self.config.bridge.paired.push(issued.clone());
                self.save_config();
                self.notify(format!("{} connected", issued.name));
            }
            None if !allow => self.notify("Connection request declined"),
            None => {}
        }
        Task::none()
    }

    /// Put the quick assistant away, back into the tray.
    ///
    /// The pop-up is a transient panel: as soon as the user clicks anywhere
    /// else it should fold away rather than linger on top of their work.
    fn dismiss_popup(&mut self) -> Task<Message> {
        let settled = self
            .popup_opened_at
            .is_some_and(|at| at.elapsed() > Duration::from_millis(600));
        if !self.assistant_only || !settled {
            return Task::none();
        }
        self.close_assistant(false)
    }

    /// Put the assistant away.
    ///
    /// When it replaced a visible main window, the main window comes back at
    /// its old size; otherwise the app returns to the tray. `focus` decides
    /// whether the restored window may take keyboard focus — it must not when
    /// the user merely clicked somewhere else.
    fn close_assistant(&mut self, focus: bool) -> Task<Message> {
        let from_main = std::mem::take(&mut self.popup_from_main);
        self.popup_opened_at = None;
        let restore = self.leave_popup();
        if from_main {
            self.window_hidden = false;
            let show = if focus {
                self.show_window()
            } else {
                Task::batch([
                    iced::window::set_mode(self.window, iced::window::Mode::Windowed),
                    iced::window::minimize(self.window, false),
                ])
            };
            return Task::batch([restore, show]);
        }
        let hide = if self.tray.is_some() {
            self.window_hidden = true;
            iced::window::set_mode(self.window, iced::window::Mode::Hidden)
        } else {
            Task::none()
        };
        Task::batch([restore, hide])
    }

    /// Leave the assistant and show the full window.
    pub fn focus_main(&mut self) -> Task<Message> {
        self.popup_opened_at = None;
        self.popup_from_main = false;
        let restore = self.leave_popup();
        Task::batch([restore, self.show_window()])
    }

    /// Ask to quit, routing through a confirmation when there is no tray.
    pub fn request_quit(&mut self) -> Task<Message> {
        self.quitting = true;
        if let Some(vault) = self.vault.as_mut()
            && vault.is_dirty()
            && let Err(e) = vault.save()
        {
            eprintln!("aurapass: could not save before quitting: {e}");
        }
        self.save_config();
        iced::exit()
    }

    // ----------------------------------------------------------------- bridge

    /// Start the in-process browser bridge.
    pub fn start_bridge(&mut self) {
        if self.bridge.is_some() {
            return;
        }
        let bridge = std::sync::Arc::new(aurapass_bridge::Bridge::new(self.config.bridge.clone()));
        bridge.set_vault_path(self.vault.as_ref().and_then(|v| v.path().map(|p| p.to_path_buf())));
        bridge.set_vault(self.vault.clone());
        match aurapass_bridge::start(bridge, self.config.bridge.port) {
            Ok(running) => {
                self.bridge_error = None;
                self.bridge = Some(running);
            }
            Err(e) => self.bridge_error = Some(e.to_string()),
        }
    }

    /// Stop the browser bridge.
    pub fn stop_bridge(&mut self) {
        if let Some(bridge) = self.bridge.take() {
            bridge.stop();
            self.notify("Browser bridge stopped");
        }
    }

    // --------------------------------------------------------------- filters

    /// The items matching the current filters, in order.
    pub fn filtered(&self) -> Vec<Uuid> {
        let Some(vault) = &self.vault else {
            return Vec::new();
        };
        vault.query(&self.browse.query())
    }

    // ----------------------------------------------------------------- update

    /// Handle one message.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Ready(id) => {
                if let Some(id) = id {
                    self.window = id;
                }
                Task::none()
            }

            Message::Window(id, event) => {
                self.window = id;
                self.on_window(id, event)
            }

            Message::SystemTheme(mode) => {
                self.system_mode = mode;
                Task::none()
            }

            Message::Key(event) => self.on_key(event),

            Message::Tick(at) => self.on_tick(at),

            Message::Lock => {
                self.lock_vault();
                Task::none()
            }

            Message::Ask(action) => {
                self.confirm = Some(confirm_for(&action));
                Task::none()
            }

            Message::Confirm => {
                let Some(confirm) = self.confirm.take() else {
                    return Task::none();
                };
                self.run_confirm(confirm.action)
            }

            Message::Dismiss => {
                self.confirm = None;
                Task::none()
            }

            Message::PairAllow => self.answer_pairing(true),
            Message::PairDeny => self.answer_pairing(false),

            Message::CycleTheme => {
                self.config.theme = match self.config.theme.as_str() {
                    "system" => "light".into(),
                    "light" => "dark".into(),
                    _ => "system".into(),
                };
                self.save_config();
                Task::none()
            }

            Message::Unlock(m) => {
                let task = crate::unlock::update(self, m);
                self.touch();
                task
            }
            Message::Browse(m) => {
                let task = crate::browse::update(self, m);
                self.touch();
                task
            }
            Message::Editor(m) => {
                let task = crate::editor::update(self, m);
                self.touch();
                task
            }
            Message::Tools(m) => {
                let task = crate::tools::update(self, m);
                self.touch();
                task
            }
            Message::Assistant(m) => {
                let task = crate::assistant::update(self, m);
                self.touch();
                task
            }
        }
    }

    /// Note that the user did something, so the auto-lock timer restarts.
    fn touch(&mut self) {
        if let Some(vault) = self.vault.as_mut() {
            vault.touch();
        }
    }

    /// Run a confirmed action.
    fn run_confirm(&mut self, action: ConfirmAction) -> Task<Message> {
        match action {
            ConfirmAction::Trash(id) => {
                if let Some(vault) = self.vault.as_mut() {
                    match vault.trash_item(id) {
                        Ok(()) => {
                            self.notify("Moved to the bin");
                            if self.browse.selected == Some(id) {
                                self.browse.selected = None;
                            }
                        }
                        Err(e) => self.notify_error(e.to_string()),
                    }
                }
                Task::none()
            }
            ConfirmAction::DeleteCategory(id) => {
                if let Some(vault) = self.vault.as_mut() {
                    if let Some(pos) = vault.data().categories.iter().position(|c| c.id == id) {
                        let name = vault.data().categories[pos].name.clone();
                        for item in vault.data_mut().items.iter_mut() {
                            if item.category == Some(id) {
                                item.category = None;
                            }
                        }
                        vault.data_mut().categories.remove(pos);
                        vault.mark_dirty();
                        self.notify(format!("Deleted category “{name}”"));
                    }
                    if self.browse.category == Some(id) {
                        self.browse.category = None;
                    }
                }
                Task::none()
            }
            ConfirmAction::EmptyBin => {
                if let Some(vault) = self.vault.as_mut() {
                    let n = vault.empty_bin();
                    self.notify(format!("Permanently deleted {n} item(s)"));
                }
                self.browse.selected = None;
                Task::none()
            }
        }
    }

    /// The heartbeat: tray, auto-lock, clipboard, toasts, TOTP.
    fn on_tick(&mut self, at: Instant) -> Task<Message> {
        self.ticks += 1;
        self.now_unix = chrono::Utc::now().timestamp().max(0) as u64;
        self.now_local = Local::now();

        // A second launch asked us to come forward instead of starting a
        // second copy. Leave the compact assistant for the full window.
        if !self.quitting && crate::instance::take_show_request() {
            if self.assistant_only {
                return self.focus_main();
            }
            return self.show_window();
        }

        // Tray commands.
        let mut commands = Vec::new();
        if let Some(tray) = &self.tray {
            while let Some(command) = tray.poll() {
                commands.push(command);
            }
        }
        for command in commands {            match command {
                TrayCommand::Toggle => return self.toggle_window(),
                TrayCommand::Show => return self.show_window(),
                TrayCommand::QuickAssistant => return self.open_assistant(),
                TrayCommand::Lock => {
                    if self.vault.is_some() {
                        self.lock_vault();
                    }
                }
                TrayCommand::Quit => return self.request_quit(),
            }
        }

        // Browser bridge: pairing requests and commands from the extension.
        let mut bridge_tasks: Vec<Task<Message>> = Vec::new();
        let mut prompt = None;
        if let Some(running) = &self.bridge {
            let bridge = running.bridge();
            if self.pairing.is_none() {
                prompt = bridge.pending_pairs().into_iter().next();
            }
            for command in bridge.take_commands() {
                match command {
                    aurapass_bridge::UiCommand::ShowAssistant { x, y } => {
                        bridge_tasks.push(self.open_assistant_at(x.zip(y)));
                    }
                }
            }
        }
        if let Some(prompt) = prompt {
            self.pairing = Some(prompt);
            // Make sure the user can actually see the request. The compact
            // assistant hides the normal modal layer, so leave it first.
            if self.assistant_only {
                bridge_tasks.push(self.focus_main());
            } else {
                bridge_tasks.push(self.show_window());
            }
        }
        if !bridge_tasks.is_empty() {
            return Task::batch(bridge_tasks);
        }

        // A browser request may have saved a login; take the fresh copy.
        let changed = self
            .bridge
            .as_ref()
            .and_then(|running| running.bridge().take_changed_vault());
        if let Some(vault) = changed
            && self.vault.is_some()
        {
            self.vault = Some(vault);
        }

        // Auto-lock.
        if let Some(vault) = &self.vault
            && vault.should_auto_lock()
        {
            self.lock_vault();
            self.notify("Vault locked after a period of inactivity");
        }

        // Autosave: write the vault out a moment after the last change, so the
        // in-place edits (renaming a category, ticking favourites) survive a
        // crash without a write on every keystroke.
        match self.vault.as_ref() {
            Some(vault) if vault.is_dirty() => match self.dirty_since {
                None => self.dirty_since = Some(at),
                Some(since) if at.duration_since(since) >= Duration::from_secs(2) => {
                    self.dirty_since = None;
                    self.save_vault();
                }
                Some(_) => {}
            },
            _ => self.dirty_since = None,
        }

        // Clipboard.
        if let Some(at) = self.clipboard_clear_at
            && Instant::now() >= at
        {
            self.clipboard_clear_at = None;
            self.notify("Clipboard cleared");
            return iced::clipboard::write(String::new());
        }

        // Expire toasts.
        self.toasts
            .retain(|t| at.duration_since(t.at) < Duration::from_secs(6));

        // Development: a second capture, many frames later, to catch artwork
        // that drifts as frames accumulate.
        if let Ok(path) = std::env::var("AURAPASS_SHOT2")
            && !self.shot2_done
            && self.ticks >= 44
        {
            self.shot2_done = true;
            return iced::window::screenshot(self.window).then(move |shot| {
                if let Err(e) = write_ppm(&path, &shot) {
                    eprintln!("aurapass: could not write {path}: {e}");
                }
                Task::none()
            });
        }

        // Development: capture the window and leave.
        if let Some(path) = self.shot.clone()
            && !self.shot_done
            && self.ticks >= 4
        {
            if let (Ok(vault), Ok(password), true) = (
                std::env::var("AURAPASS_SHOT_VAULT"),
                std::env::var("AURAPASS_SHOT_PASSWORD"),
                self.vault.is_none(),
            ) {
                self.unlock.path = vault;
                self.unlock.password = password;
                self.do_unlock();
                return Task::none();
            }
            // Let the dialog settle for a frame or two before the capture.
            if self.ticks >= 6 && !self.shot_setup_done {
                self.shot_setup_done = true;
                return self.apply_shot_setup();
            }
            if self.ticks < 8 {
                return Task::none();
            }
            self.shot_done = true;
            let hold = std::env::var("AURAPASS_SHOT_HOLD").is_ok()
                || std::env::var("AURAPASS_SHOT2").is_ok();
            return iced::window::screenshot(self.window).then(move |shot| {
                if let Err(e) = write_ppm(&path, &shot) {
                    eprintln!("aurapass: could not write {path}: {e}");
                }
                // A capture normally leaves immediately; `AURAPASS_SHOT_HOLD`
                // keeps the window up so its memory can be sampled.
                if hold { Task::none() } else { iced::exit() }
            });
        }

        Task::none()
    }

    /// Handle a window event.
    /// Handle a keystroke nothing else wanted.
    ///
    /// Escape is the universal "get me out of here": dismiss a confirmation,
    /// close a dialog, leave the quick assistant. It only ever unwinds one step,
    /// so it can never throw away a vault or a half-written item.
    fn on_key(&mut self, event: iced::keyboard::Event) -> Task<Message> {
        let iced::keyboard::Event::KeyPressed {
            key, modifiers, ..
        } = event
        else {
            return Task::none();
        };

        // Tab moves between fields and controls, everywhere in the app, the
        // way every native toolkit behaves. Shift+Tab walks backwards.
        if key == iced::keyboard::Key::Named(iced::keyboard::key::Named::Tab) {
            return if modifiers.shift() {
                iced::widget::operation::focus_previous()
            } else {
                iced::widget::operation::focus_next()
            };
        }

        if key != iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape) {
            return Task::none();
        }

        if self.pairing.is_some() {
            return self.update(Message::PairDeny);
        }
        if self.confirm.is_some() {
            self.confirm = None;
            return Task::none();
        }
        if self.tools.open.is_some() {
            return self.update(Message::Tools(tools::Message::Close));
        }
        if self.assistant_only {
            return self.close_assistant(true);
        }
        Task::none()
    }

    fn on_window(&mut self, id: iced::window::Id, event: iced::window::Event) -> Task<Message> {
        if id != self.window {
            return Task::none();
        }
        match event {
            iced::window::Event::CloseRequested => {
                let hide_to_tray = self.hide_supported
                    && self.tray.is_some()
                    && self.config.close_to_tray
                    && !self.quitting;
                if hide_to_tray {
                    // The window is gone before anyone could read a toast, so
                    // there is nothing to announce: the tray icon is the cue.
                    return self.hide_window();
                }
                return self.request_quit();
            }
            iced::window::Event::Unfocused => self.dismiss_popup(),
            iced::window::Event::Resized(size) => {
                // The assistant pop-up is a temporary shape. Remembering its
                // size would make the main window open at 392x620 next time.
                if !self.assistant_only {
                    self.window_size = size;
                    self.config.window.width = size.width;
                    self.config.window.height = size.height;
                }
                Task::none()
            }
            _ => Task::none(),
        }
    }

    // ------------------------------------------------------------------- view

    /// Open the editor on an existing item.
    pub fn start_edit(&mut self, id: Uuid) {
        let Some(item) = self.vault.as_ref().and_then(|v| v.item(id)) else {
            return;
        };
        self.editor = Some(crate::editor::EditorState::from_item(item));
    }

    /// Draw the application.
    pub fn view(&self) -> Element<'_, Message> {
        // The compact assistant takes the window over entirely. Its visible
        // surface is a 400x450 rounded panel; the transparent margin around it
        // holds the drop shadow.
        if self.assistant_only {
            let panel = container(crate::assistant::view(self).map(Message::Assistant))
                .width(Length::Fixed(POPUP_SIZE.width))
                .height(Length::Fixed(POPUP_SIZE.height))
                .style(|t: &Theme| {
                    let k = Tokens::of(t);
                    container::Style {
                        background: Some(k.canvas.into()),
                        border: iced::Border {
                            color: k.border,
                            width: 1.0,
                            radius: POPUP_RADIUS.into(),
                        },
                        shadow: iced::Shadow {
                            color: iced::Color {
                                a: if k.is_dark { 0.55 } else { 0.16 },
                                ..iced::Color::BLACK
                            },
                            offset: iced::Vector::new(0.0, 4.0),
                            blur_radius: 16.0,
                        },
                        ..container::Style::default()
                    }
                });
            return container(panel)
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into();
        }

        let body: Element<'_, Message> = match self.screen {
            Screen::Unlock => crate::unlock::view(self).map(Message::Unlock),
            Screen::Main => self.main_view(),
        };

        let mut layers: Vec<Element<'_, Message>> = vec![body];

        if let Some(modal) = self.active_modal() {
            // `opaque` stops the panel underneath from reacting to the mouse, so
            // hovering or clicking the scrim can never light up a row behind it.
            layers.push(iced::widget::opaque(w::scrim(modal)));
        }
        if !self.toasts.is_empty() {
            layers.push(self.toast_layer());
        }

        if layers.len() == 1 {
            return layers.pop().expect("one layer");
        }
        let mut stack = Stack::new();
        for layer in layers {
            stack = stack.push(layer);
        }
        stack.into()
    }

    /// The unlocked layout: bar, three columns, status line.
    fn main_view(&self) -> Element<'_, Message> {
        column![
            self.toolbar(),
            row![
                crate::browse::sidebar(self).map(Message::Browse),
                crate::browse::list(self).map(Message::Browse),
                crate::browse::detail(self).map(Message::Browse),
            ]
            .width(Length::Fill)
            .height(Length::Fill),
            self.status_bar(),
        ]
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    /// The top bar: brand, vault, and the main commands.
    fn toolbar(&self) -> Element<'_, Message> {
        let vault_label = match &self.vault {
            Some(v) => v.name().to_string(),
            None => "Locked".to_string(),
        };
        let theme_glyph = match self.config.theme.as_str() {
            "light" => Glyph::Sun,
            "dark" => Glyph::Moon,
            _ => Glyph::Monitor,
        };

        let left: Vec<Element<'_, Message>> = vec![
            w::brand_badge(26.0),
            w::gap(9.0),
            iced::widget::text(aurapass_core::APP_NAME)
                .size(15.5)
                .font(theme::SEMI)
                .style(|t: &Theme| iced::widget::text::Style {
                    color: Some(Tokens::of(t).text),
                })
                .into(),
            w::gap(13.0),
            w::vdivider(),
            w::gap(13.0),
            glyph::tinted(Glyph::ShieldCheck, 14.0, theme::accent).into(),
            w::gap(6.0),
            w::small(vault_label).into(),
        ];

        let right: Vec<Element<'_, Message>> = vec![
            w::icon_button(
                Glyph::Sparkle,
                17.0,
                Some(Message::Tools(tools::Message::Open(tools::Modal::Generator))),
            )
            .into(),
            w::icon_button(
                Glyph::Gauge,
                17.0,
                Some(Message::Tools(tools::Message::Open(tools::Modal::Health))),
            )
            .into(),
            w::icon_button(
                Glyph::History,
                17.0,
                Some(Message::Tools(tools::Message::Open(tools::Modal::Activity))),
            )
            .into(),
            w::gap(6.0),
            w::vdivider(),
            w::gap(6.0),
            w::icon_button(
                Glyph::Import,
                17.0,
                Some(Message::Tools(tools::Message::Open(tools::Modal::Import))),
            )
            .into(),
            w::icon_button(
                Glyph::Export,
                17.0,
                Some(Message::Tools(tools::Message::Open(tools::Modal::Export))),
            )
            .into(),
            w::icon_button(
                Glyph::Info,
                17.0,
                Some(Message::Tools(tools::Message::Open(tools::Modal::About))),
            )
            .into(),
            w::gap(6.0),
            w::vdivider(),
            w::gap(6.0),
            w::icon_button(theme_glyph, 17.0, Some(Message::CycleTheme)).into(),
            w::icon_button(
                Glyph::Gear,
                17.0,
                Some(Message::Tools(tools::Message::Open(tools::Modal::Settings))),
            )
            .into(),
            w::gap(4.0),
            w::secondary_icon_button(Glyph::Lock, "Lock", Message::Lock).into(),
        ];

        container(
            row![
                row(left).spacing(0).align_y(Alignment::Center),
                w::grow(),
                row(right).spacing(2).align_y(Alignment::Center),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .height(Length::Fixed(theme::TOOLBAR_H))
        .padding(iced::Padding {
            top: theme::TOOLBAR_PAD_TOP,
            right: 12.0,
            bottom: 0.0,
            left: 12.0,
        })
        .style(|t: &Theme| {
            let k = Tokens::of(t);
            container::Style {
                background: Some(k.canvas.into()),
                border: iced::Border {
                    color: k.border,
                    width: 0.0,
                    radius: 0.0.into(),
                },
                ..container::Style::default()
            }
        })
        .into()
    }

    /// The footer: counts on the left, bridge and build on the right.
    fn status_bar(&self) -> Element<'_, Message> {
        let left = match &self.vault {
            Some(v) => {
                let s = v.stats();
                format!(
                    "{} items · {} favourites · {} with 2FA · {} in the bin",
                    s.items, s.favorites, s.with_totp, s.trashed
                )
            }
            None => "Locked".to_string(),
        };
        // No address, no port, no token: the user never needs to see them.
        let bridge = match (&self.bridge, &self.bridge_error) {
            (Some(_), _) => (true, "extension · ready".to_string()),
            (None, Some(_)) => (false, "extension off".to_string()),
            (None, None) => (false, "extension off".to_string()),
        };
        let bridge_button = iced::widget::button(
            row![
                glyph::tinted(
                    if bridge.0 {
                        Glyph::CircleCheck
                    } else {
                        Glyph::ShieldAlert
                    },
                    13.0,
                    if bridge.0 { theme::ok } else { theme::muted },
                ),
                w::gap(5.0),
                w::small(bridge.1),
            ]
            .align_y(Alignment::Center),
        )
        .padding([3, 8])
        .style(theme::bare)
        .on_press(Message::Tools(tools::Message::Open(tools::Modal::Bridge)));

        container(
            row![
                w::small(left),
                w::grow(),
                bridge_button,
                w::gap(4.0),
                w::small(format!("v{}", env!("CARGO_PKG_VERSION"))),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .height(Length::Fixed(theme::STATUS_H))
        .padding([0, 14])
        .style(|t: &Theme| {
            let k = Tokens::of(t);
            container::Style {
                background: Some(k.panel.into()),
                border: iced::Border {
                    color: k.border,
                    width: 0.0,
                    radius: 0.0.into(),
                },
                ..container::Style::default()
            }
        })
        .into()
    }

    /// The one dialog that should be on top, if any.
    fn active_modal(&self) -> Option<Element<'_, Message>> {
        if let Some(prompt) = &self.pairing {
            return Some(self.pairing_view(prompt));
        }
        if let Some(confirm) = &self.confirm {
            return Some(self.confirm_view(confirm));
        }
        // The generator is drawn by the assistant module, which owns its state.
        if self.tools.open == Some(tools::Modal::Generator) {
            return Some(crate::assistant::generator_modal(self).map(Message::Assistant));
        }
        if let Some(modal) = crate::tools::view(self) {
            return Some(modal.map(Message::Tools));
        }
        // The editor sits under the tool dialogs so the generator can be used
        // to fill in the item that is open.
        if let Some(editor) = &self.editor {
            return Some(crate::editor::view(self, editor).map(Message::Editor));
        }
        None
    }

    /// The browser approval dialog: the only way a new browser gets access.
    fn pairing_view<'a>(
        &'a self,
        prompt: &'a aurapass_bridge::PairPrompt,
    ) -> Element<'a, Message> {
        let card = container(
            column![
                row![
                    glyph::tinted(Glyph::Globe, 19.0, theme::accent),
                    w::gap(9.0),
                    w::title(format!("{} wants to connect", prompt.name)),
                ]
                .align_y(Alignment::Center),
                w::vgap(9.0),
                w::body(
                    "AuraPass will let this browser list and fill logins from your vault. \
                     You can revoke access at any time in Settings → Browser.",
                ),
                w::vgap(7.0),
                w::small(prompt.client.clone()),
                w::vgap(18.0),
                row![
                    w::grow(),
                    w::secondary_button("Deny", Message::PairDeny),
                    w::gap(8.0),
                    w::primary_button("Allow", Message::PairAllow),
                ]
                .align_y(Alignment::Center),
            ]
            .width(Length::Fixed(440.0)),
        )
        .padding(20)
        .style(theme::card);

        card.into()
    }

    /// A yes/no dialog.
    fn confirm_view<'a>(&'a self, confirm: &'a Confirm) -> Element<'a, Message> {        let yes = if confirm.danger {
            w::danger_button(&confirm.yes, Message::Confirm)
        } else {
            w::primary_button(&confirm.yes, Message::Confirm)
        };

        let card = container(
            column![
                row![
                    glyph::tinted(
                        if confirm.danger {
                            Glyph::Warning
                        } else {
                            Glyph::Info
                        },
                        19.0,
                        if confirm.danger {
                            theme::danger
                        } else {
                            theme::accent
                        },
                    ),
                    w::gap(9.0),
                    w::title(confirm.title.clone()),
                ]
                .align_y(Alignment::Center),
                w::vgap(9.0),
                w::body(confirm.body.clone()),
                w::vgap(18.0),
                row![
                    w::grow(),
                    w::secondary_button("Cancel", Message::Dismiss),
                    w::gap(8.0),
                    yes,
                ]
                .align_y(Alignment::Center),
            ]
            .width(Length::Fixed(430.0)),
        )
        .padding(20)
        .style(theme::card);

        card.into()
    }

    /// The stack of toasts in the bottom-right corner.
    fn toast_layer(&self) -> Element<'_, Message> {
        let mut list: iced::widget::Column<'_, Message> = column![].spacing(8).align_x(Alignment::End);
        for toast in self.toasts.iter().rev() {
            let tone: fn(&Tokens) -> iced::Color = if toast.error {
                theme::danger
            } else {
                theme::ok
            };
            let glyph = if toast.error {
                Glyph::CircleAlert
            } else {
                Glyph::CircleCheck
            };
            list = list.push(
                container(
                    row![
                        glyph::tinted(glyph, 15.0, tone),
                        w::gap(9.0),
                        w::body(toast.text.clone()),
                    ]
                    .align_y(Alignment::Center),
                )
                .padding([9, 13])
                .max_width(430.0)
                .style(move |t: &Theme| {
                    let k = Tokens::of(t);
                    container::Style {
                        background: Some(k.canvas.into()),
                        border: iced::Border {
                            color: k.border,
                            width: 1.0,
                            radius: theme::R_MD.into(),
                        },
                        shadow: iced::Shadow {
                            color: iced::Color {
                                a: if k.is_dark { 0.5 } else { 0.16 },
                                ..iced::Color::BLACK
                            },
                            offset: iced::Vector::new(0.0, 6.0),
                            blur_radius: 18.0,
                        },
                        ..container::Style::default()
                    }
                }),
            );
        }
        container(list)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(iced::alignment::Horizontal::Right)
            .align_y(iced::alignment::Vertical::Bottom)
            .padding(18)
            .into()
    }
}

/// The window size the capture harness asked for, if any.
///
/// `AURAPASS_SHOT_SIZE=392x560` lets the pop-up panel be photographed at the
/// size it really appears in; the shipped package never sets it.
fn shot_size() -> Option<iced::Size> {
    let raw = std::env::var("AURAPASS_SHOT_SIZE").ok()?;
    let (width, height) = raw.split_once(['x', 'X'])?;
    Some(iced::Size::new(
        width.trim().parse().ok()?,
        height.trim().parse().ok()?,
    ))
}

/// Describe a confirmation.
fn confirm_for(action: &ConfirmAction) -> Confirm {
    match action {
        ConfirmAction::Trash(_) => Confirm {
            title: "Move to the bin?".into(),
            body: "The item stays in the vault and can be restored until you empty the bin."
                .into(),
            yes: "Move to bin".into(),
            danger: false,
            action: action.clone(),
        },
        ConfirmAction::EmptyBin => Confirm {
            title: "Empty the bin?".into(),
            body: "Every item in the bin is deleted for good. This cannot be undone.".into(),
            yes: "Delete for good".into(),
            danger: true,
            action: action.clone(),
        },
        ConfirmAction::DeleteCategory(_) => Confirm {
            title: "Delete this category?".into(),
            body: "Items in the category are kept; they simply become uncategorised.".into(),
            yes: "Delete".into(),
            danger: true,
            action: action.clone(),
        },
    }
}

/// Write a screenshot as a binary PPM. Only used by the capture harness.
fn write_ppm(path: &str, shot: &iced::window::Screenshot) -> std::io::Result<()> {
    let width = shot.size.width as usize;
    let height = shot.size.height as usize;
    let mut out = Vec::with_capacity(width * height * 3 + 32);
    out.extend_from_slice(format!("P6\n{width} {height}\n255\n").as_bytes());
    for pixel in shot.rgba.chunks_exact(4) {
        out.extend_from_slice(&pixel[..3]);
    }
    std::fs::write(path, out)
}
