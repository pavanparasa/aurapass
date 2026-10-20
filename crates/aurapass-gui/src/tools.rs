//! The auxiliary dialogs: health, settings, activity, import/export, changing
//! the master password, the browser bridge, the category manager and About.
//!
//! iced has no multi-window story that fits a single-vault app, so each of
//! these is a centred modal over the browser rather than a floating window.
//! Only one can be open at a time, which is also easier to reason about.

use std::collections::HashMap;

use aurapass_core::audit::{AuditOptions, AuditReport, Finding, Severity};
use aurapass_core::crypto::KdfPreset;
use aurapass_core::importers::{self, ImportFormat, ImportPreview};
use aurapass_core::model::{ActivityKind, ItemKind, VaultSettings};
use iced::widget::{column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Task, Theme};
use uuid::Uuid;

use crate::app::{AppState, ConfirmAction, Message as AppMessage};
use crate::glyph::{self, Glyph};
use crate::theme::{self, Tokens};
use crate::widgets as w;

/// Which dialog is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modal {
    /// The password generator. Rendered from the quick assistant's state.
    Generator,
    /// Vault health and the audit report.
    Health,
    /// Preferences.
    Settings,
    /// Recent vault activity.
    Activity,
    /// Import from another password manager.
    Import,
    /// Export a backup or a plain file.
    Export,
    /// Change the master password.
    ChangePassword,
    /// Set, change or remove the unlock PIN.
    UnlockPin,
    /// The browser bridge.
    Bridge,
    /// Version and licences.
    About,
    /// Add, rename and delete categories.
    Categories,
    /// Pick what kind of item to create.
    NewItem,
}

/// What an export produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    /// An encrypted copy of the vault.
    Backup,
    /// A plaintext CSV.
    Csv,
    /// A plaintext JSON file.
    Json,
}

impl ExportKind {
    /// Display label.
    fn label(self) -> &'static str {
        match self {
            ExportKind::Backup => "Encrypted backup",
            ExportKind::Csv => "Plain CSV",
            ExportKind::Json => "Plain JSON",
        }
    }
}

/// The import form.
#[derive(Debug, Clone)]
pub struct ImportState {
    /// File to read.
    pub path: String,
    /// Which parser to use.
    pub format: ImportFormat,
    /// Replace items that look like duplicates.
    pub overwrite: bool,
    /// Optional category to file everything under.
    pub category: String,
    /// The parsed preview, once the file has been read.
    pub preview: Option<ImportPreview>,
    /// The last error.
    pub error: Option<String>,
    /// The outcome of the last import.
    pub applied: Option<String>,
}

impl Default for ImportState {
    fn default() -> Self {
        Self {
            path: String::new(),
            format: ImportFormat::Auto,
            overwrite: false,
            category: String::new(),
            preview: None,
            error: None,
            applied: None,
        }
    }
}

/// The export form.
#[derive(Debug, Clone)]
pub struct ExportState {
    /// Destination file.
    pub path: String,
    /// What to write.
    pub kind: ExportKind,
    /// The outcome message.
    pub message: Option<String>,
}

impl Default for ExportState {
    fn default() -> Self {
        Self {
            path: String::new(),
            kind: ExportKind::Backup,
            message: None,
        }
    }
}

/// The change-master-password form.
#[derive(Debug, Clone, Default)]
pub struct ChangeState {
    /// The current password.
    pub current: String,
    /// The new password.
    pub new: String,
    /// The new password again.
    pub confirm: String,
    /// Optional replacement key file.
    pub key_file: String,
    /// Show the passwords in the clear.
    pub reveal: bool,
    /// Which KDF preset to move to.
    pub kdf: Option<KdfPreset>,
    /// The last error.
    pub error: Option<String>,
}

/// The unlock-PIN form.
#[derive(Debug, Clone, Default)]
pub struct PinState {
    /// The new PIN.
    pub pin: String,
    /// The new PIN again.
    pub confirm: String,
    /// Show the digits.
    pub reveal: bool,
    /// The last error.
    pub error: Option<String>,
}

/// Everything the dialogs need to remember.
#[derive(Debug, Clone, Default)]
pub struct ToolsState {
    /// The open dialog, if any.
    pub open: Option<Modal>,
    /// The last audit report.
    pub audit: Option<AuditReport>,
    /// A note about the breach check.
    pub breach_note: Option<String>,
    /// The settings being edited, until they are saved or reverted.
    pub settings: Option<VaultSettings>,
    /// The import form.
    pub import: ImportState,
    /// The export form.
    pub export: ExportState,
    /// The change-password form.
    pub change: ChangeState,
    /// The unlock-PIN form.
    pub pin: PinState,
    /// The category-manager's new-category field.
    pub new_category: String,
}

impl ToolsState {
    /// Drop anything that belonged to the previous vault.
    pub fn reset_for_vault(&mut self) {
        self.open = None;
        self.audit = None;
        self.breach_note = None;
        self.settings = None;
        self.import = ImportState::default();
        self.export = ExportState::default();
        self.change = ChangeState::default();
        self.pin = PinState::default();
        self.new_category.clear();
    }
}

/// A dropdown option for the import format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatChoice(pub ImportFormat);

impl std::fmt::Display for FormatChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.label())
    }
}

impl FormatChoice {
    /// Every option, in menu order.
    pub fn all() -> Vec<FormatChoice> {
        let mut all = vec![FormatChoice(ImportFormat::Auto)];
        all.extend(ImportFormat::ALL.into_iter().map(FormatChoice));
        all
    }
}

/// Messages from the dialogs.
#[derive(Debug, Clone)]
pub enum Message {
    /// Open a dialog.
    Open(Modal),
    /// Close the current dialog.
    Close,

    // ---- health
    /// Run an offline audit.
    RunAudit,
    /// Run an audit that also checks Have I Been Pwned.
    RunOnlineAudit,

    // ---- settings
    /// Switch theme: `system`, `light` or `dark`.
    Theme(String),
    /// Auto-lock timeout, in seconds (0 disables).
    AutoLock(u64),
    /// Clipboard auto-clear, in seconds (0 disables).
    ClipboardClear(u64),
    /// Start with secrets masked.
    HideSecrets(bool),
    /// Allow online breach checks.
    BreachChecks(bool),
    /// Show the item list as a compact table.
    CompactList(bool),
    /// Show a tray icon (takes effect on restart).
    TrayEnabled(bool),
    /// Closing the window hides it to the tray.
    CloseToTray(bool),
    /// Use a dark tray glyph.
    TrayDark(bool),
    /// Open AuraPass automatically when the user logs in.
    Autostart(bool),
    /// Default password length.
    PolicyLength(usize),
    /// Default policy: lowercase letters.
    PolicyLower(bool),
    /// Default policy: uppercase letters.
    PolicyUpper(bool),
    /// Default policy: digits.
    PolicyDigits(bool),
    /// Default policy: symbols.
    PolicySymbols(bool),
    /// Default policy: avoid look-alike characters.
    PolicyAmbiguous(bool),
    /// Write the settings and preferences to disk.
    SaveSettings,
    /// Throw away the edits.
    RevertSettings,

    // ---- import
    /// The import path changed.
    ImportPath(String),
    /// Browse for the file to import.
    BrowseImport,
    /// The import file chooser answered.
    ImportPicked(Option<std::path::PathBuf>),
    /// The import format changed.
    ImportFormat(ImportFormat),
    /// Overwrite look-alike items.
    ImportOverwrite(bool),
    /// The category to file imported items under.
    ImportCategory(String),
    /// Read and parse the file.
    ImportPreview,
    /// Apply the preview.
    ImportApply,

    // ---- export
    /// The export path changed.
    ExportPath(String),
    /// Browse for where to write the export.
    BrowseExport,
    /// The export file chooser answered.
    ExportPicked(Option<std::path::PathBuf>),
    /// What to write.
    ExportKind(ExportKind),
    /// Write the file.
    ExportRun,

    // ---- change password
    /// The current master password changed.
    ChangeCurrent(String),
    /// The new master password changed.
    ChangeNew(String),
    /// The new master password, again.
    ChangeConfirm(String),
    /// The key file changed.
    ChangeKeyFile(String),
    /// Show the passwords.
    ChangeReveal,
    /// Which KDF preset to adopt.
    ChangeKdf(KdfPreset),
    /// Perform the change.
    ChangeRun,

    // ---- unlock PIN
    /// The PIN changed.
    PinNew(String),
    /// The PIN confirmation changed.
    PinConfirm(String),
    /// Show or hide the PIN.
    PinReveal,
    /// Store the PIN for this desktop session.
    PinSave,
    /// Forget the stored PIN.
    PinRemove,

    // ---- bridge
    /// Let the extension unlock the vault remotely.
    BridgeAllowRemote(bool),
    /// Start the bridge.
    BridgeStart,
    /// Stop the bridge.
    BridgeStop,
    /// Revoke a browser's access.
    BridgeRevoke(String),

    // ---- categories
    /// The new-category name changed.
    NewCategory(String),
    /// Create the category.
    AddCategory,
    /// Rename a category.
    RenameCategory(Uuid, String),
    /// Delete a category.
    DeleteCategory(Uuid),

    // ---- new item
    /// Create an item of the given kind.
    NewItem(ItemKind),
}

/// Handle a message from the dialogs.
pub fn update(state: &mut AppState, message: Message) -> Task<AppMessage> {
    match message {
        Message::Open(modal) => {
            if modal == Modal::Settings {
                state.tools.settings = state.vault.as_ref().map(|v| v.settings().clone());
            }
            if modal == Modal::UnlockPin {
                state.tools.pin = PinState::default();
            }
            state.tools.open = Some(modal);
        }
        Message::Close => state.tools.open = None,

        Message::RunAudit => run_audit(state, false),
        Message::RunOnlineAudit => run_audit(state, true),

        Message::Theme(value) => {
            state.config.theme = value;
            state.save_config();
        }
        Message::AutoLock(secs) => with_settings(state, |s| s.auto_lock_secs = secs),
        Message::ClipboardClear(secs) => with_settings(state, |s| s.clipboard_clear_secs = secs),
        Message::HideSecrets(on) => with_settings(state, |s| s.hide_secrets_default = on),
        Message::BreachChecks(on) => with_settings(state, |s| s.breach_check_enabled = on),
        Message::CompactList(on) => with_settings(state, |s| s.compact_list = on),
        Message::PolicyLength(n) => with_settings(state, |s| s.password_policy.length = n),
        Message::PolicyLower(on) => with_settings(state, |s| s.password_policy.lowercase = on),
        Message::PolicyUpper(on) => with_settings(state, |s| s.password_policy.uppercase = on),
        Message::PolicyDigits(on) => with_settings(state, |s| s.password_policy.digits = on),
        Message::PolicySymbols(on) => with_settings(state, |s| s.password_policy.symbols = on),
        Message::PolicyAmbiguous(on) => {
            with_settings(state, |s| s.password_policy.exclude_ambiguous = on)
        }
        Message::TrayEnabled(on) => {
            state.config.tray_enabled = on;
            state.save_config();
            state.notify("Restart AuraPass to apply the tray change");
        }
        Message::CloseToTray(on) => {
            state.config.close_to_tray = on;
            state.save_config();
        }
        Message::TrayDark(on) => {
            state.config.tray_icon_dark = on;
            state.save_config();
            state.notify("Restart AuraPass to apply the tray change");
        }
        Message::Autostart(on) => {
            let result = if on {
                aurapass_core::autostart::enable().map(|_| ())
            } else {
                aurapass_core::autostart::disable()
            };
            match result {
                Ok(()) => {
                    state.config.autostart = on;
                    state.save_config();
                    state.notify(if on {
                        "AuraPass will open when you log in"
                    } else {
                        "AuraPass will no longer start automatically"
                    });
                }
                Err(e) => state.notify_error(format!("could not update the startup entry: {e}")),
            }
        }
        Message::SaveSettings => {
            let Some(draft) = state.tools.settings.clone() else {
                return Task::none();
            };
            let outcome = match state.vault.as_mut() {
                Some(vault) => {
                    *vault.settings_mut() = draft.clone();
                    vault.mark_dirty();
                    vault.save().map_err(|e| e.to_string())
                }
                None => Ok(()),
            };
            match outcome {
                Ok(()) => {
                    if let Some(policy) = state.vault.as_ref().map(|v| v.settings().password_policy.clone())
                    {
                        state.assistant.use_policy(&policy);
                    }
                    state.notify("Settings saved");
                }
                Err(e) => state.notify_error(format!("could not save: {e}")),
            }
        }
        Message::RevertSettings => {
            state.tools.settings = state.vault.as_ref().map(|v| v.settings().clone());
            state.notify("Settings reverted");
        }

        Message::ImportPath(v) => {
            state.tools.import.path = v;
            state.tools.import.preview = None;
        }
        Message::BrowseImport => {
            let start = state.last_directory();
            return crate::filedialog::open_file(
                "Choose a file to import",
                start.as_deref(),
                Some(crate::filedialog::Filter {
                    label: "Password exports",
                    globs: "*.json *.csv *.txt",
                }),
            )
            .map(Message::ImportPicked)
            .map(AppMessage::Tools);
        }
        Message::ImportPicked(chosen) => {
            if let Some(path) = chosen {
                state.tools.import.path = path.display().to_string();
                state.tools.import.preview = None;
                state.remember_directory(&path);
            }
        }
        Message::ImportFormat(format) => {
            state.tools.import.format = format;
            state.tools.import.preview = None;
        }
        Message::ImportOverwrite(on) => state.tools.import.overwrite = on,
        Message::ImportCategory(v) => state.tools.import.category = v,
        Message::ImportPreview => preview_import(state),
        Message::ImportApply => apply_import(state),

        Message::ExportPath(v) => {
            state.tools.export.path = v;
            state.tools.export.message = None;
        }
        Message::BrowseExport => {
            let start = state.last_directory();
            let name = match state.tools.export.kind {
                ExportKind::Backup => "aurapass-backup.aurapass",
                ExportKind::Csv => "aurapass-export.csv",
                ExportKind::Json => "aurapass-export.json",
            };
            return crate::filedialog::save_file(
                "Where should the export go?",
                start.as_deref(),
                name,
                None,
            )
            .map(Message::ExportPicked)
            .map(AppMessage::Tools);
        }
        Message::ExportPicked(chosen) => {
            if let Some(path) = chosen {
                state.tools.export.path = path.display().to_string();
                state.tools.export.message = None;
                state.remember_directory(&path);
            }
        }
        Message::ExportKind(kind) => state.tools.export.kind = kind,
        Message::ExportRun => run_export(state),

        Message::ChangeCurrent(v) => state.tools.change.current = v,
        Message::ChangeNew(v) => state.tools.change.new = v,
        Message::ChangeConfirm(v) => state.tools.change.confirm = v,
        Message::ChangeKeyFile(v) => state.tools.change.key_file = v,
        Message::ChangeReveal => state.tools.change.reveal = !state.tools.change.reveal,
        Message::ChangeKdf(preset) => state.tools.change.kdf = Some(preset),
        Message::ChangeRun => change_password(state),

        Message::PinNew(v) => {
            if v.len() <= aurapass_core::pin::PIN_MAX_LEN && v.chars().all(|c| c.is_ascii_digit()) {
                state.tools.pin.pin = v;
            }
        }
        Message::PinConfirm(v) => {
            if v.len() <= aurapass_core::pin::PIN_MAX_LEN && v.chars().all(|c| c.is_ascii_digit()) {
                state.tools.pin.confirm = v;
            }
        }
        Message::PinReveal => state.tools.pin.reveal = !state.tools.pin.reveal,
        Message::PinSave => save_pin(state),
        Message::PinRemove => remove_pin(state),

        Message::BridgeAllowRemote(allow) => {
            state.config.bridge.require_gui = !allow;
            state.save_config();
            let restart = state.bridge.is_some();
            if restart {
                state.stop_bridge();
                state.start_bridge();
            }
        }
        Message::BridgeStart => state.start_bridge(),
        Message::BridgeStop => state.stop_bridge(),
        Message::BridgeRevoke(id) => {
            state.config.bridge.paired.retain(|b| b.id != id);
            state.save_config();
            if let Some(running) = &state.bridge {
                running.bridge().forget_browser(&id);
            }
            state.notify("Browser access revoked");
        }

        Message::NewCategory(v) => state.tools.new_category = v,
        Message::AddCategory => {
            let name = state.tools.new_category.trim().to_string();
            if name.is_empty() {
                state.notify_error("Give the category a name");
            } else if let Some(vault) = state.vault.as_mut() {
                vault.data_mut().category_by_name_or_create(&name);
                vault.mark_dirty();
                state.tools.new_category.clear();
                state.notify(format!("Added category “{name}”"));
            }
        }
        Message::RenameCategory(id, name) => {
            if let Some(vault) = state.vault.as_mut()
                && let Some(category) = vault
                    .data_mut()
                    .categories
                    .iter_mut()
                    .find(|c| c.id == id)
            {
                category.name = name;
                vault.mark_dirty();
            }
        }
        Message::DeleteCategory(id) => {
            return Task::done(AppMessage::Ask(ConfirmAction::DeleteCategory(id)));
        }

        Message::NewItem(kind) => {
            state.tools.open = None;
            state.editor = Some(crate::editor::EditorState::new(kind));
        }
    }
    Task::none()
}

/// Edit the settings draft in place.
fn with_settings(state: &mut AppState, edit: impl FnOnce(&mut VaultSettings)) {
    if let Some(draft) = state.tools.settings.as_mut() {
        edit(draft);
    }
}

/// Produce an audit report, optionally checking Have I Been Pwned.
fn run_audit(state: &mut AppState, online: bool) {
    state.tools.breach_note = None;
    let mut breaches: HashMap<Uuid, u32> = HashMap::new();

    if online {
        match state.vault.as_ref() {
            Some(vault) => {
                let mut client = aurapass_core::breach::BreachClient::new();
                let outcome = aurapass_core::breach::check_items(
                    &mut client,
                    vault.passwords_for_breach_check(),
                );
                match outcome {
                    Ok(found) => {
                        // A hit on a shared password counts for every item using it.
                        for (password, ids) in vault.items_sharing_passwords() {
                            if let Some(count) = found
                                .iter()
                                .find(|(id, _)| ids.contains(id))
                                .map(|(_, count)| *count)
                            {
                                let _ = password;
                                for id in ids {
                                    breaches.insert(id, count);
                                }
                            }
                        }
                        for (id, count) in found {
                            breaches.entry(id).or_insert(count);
                        }
                        state.tools.breach_note = Some(format!("{} checked online", client.requests()));
                    }
                    Err(e) => {
                        state.tools.breach_note = Some(format!("breach check skipped: {e}"));
                    }
                }
            }
            None => state.tools.breach_note = Some("no vault open".into()),
        }
    }

    let report = state
        .vault
        .as_ref()
        .map(|vault| vault.audit(&breaches, &AuditOptions::default()));
    let Some(report) = report else {
        return;
    };
    if online
        && let Some(vault) = state.vault.as_mut()
    {
        vault.data_mut().push_activity(
            ActivityKind::BreachChecked,
            "Breach check ran",
            Some(format!("{} passwords", report.breaches_checked)),
        );
    }
    state.tools.audit = Some(report);
}

/// Read and parse the import file.
fn preview_import(state: &mut AppState) {
    let path = crate::unlock::expand(&state.tools.import.path);
    match std::fs::read_to_string(&path) {
        Ok(content) => match importers::parse(&content, state.tools.import.format) {
            Ok(preview) => {
                state.tools.import.preview = Some(preview);
                state.tools.import.error = None;
                state.tools.import.applied = None;
            }
            Err(e) => state.tools.import.error = Some(e.to_string()),
        },
        Err(e) => state.tools.import.error = Some(e.to_string()),
    }
}

/// Move the previewed items into the vault.
fn apply_import(state: &mut AppState) {
    let Some(preview) = state.tools.import.preview.clone() else {
        return;
    };
    let category = {
        let trimmed = state.tools.import.category.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    };
    let overwrite = state.tools.import.overwrite;
    let Some(vault) = state.vault.as_mut() else {
        return;
    };
    let (added, updated, skipped) = vault.import_items(preview.items, category.as_deref(), overwrite);
    let outcome = vault.save().map_err(|e| e.to_string());
    let message = format!("Imported: {added} added, {updated} updated, {skipped} skipped.");
    match outcome {
        Ok(()) => {
            state.tools.import.applied = Some(message.clone());
            state.notify(message);
        }
        Err(e) => state.tools.import.error = Some(e),
    }
}

/// Write an export file.
fn run_export(state: &mut AppState) {
    let path = std::path::PathBuf::from(crate::unlock::expand(&state.tools.export.path));
    let kind = state.tools.export.kind;
    let Some(vault) = state.vault.as_mut() else {
        return;
    };
    let outcome = match kind {
        ExportKind::Backup => vault
            .export_backup(&path)
            .map(|()| "Encrypted backup written".to_string()),
        ExportKind::Csv => {
            let items: Vec<_> = vault.data().active().cloned().collect();
            let content = importers::export_csv(&items);
            importers::write_export(&path, &content)
                .map(|()| format!("Wrote {} entries (PLAINTEXT)", items.len()))
        }
        ExportKind::Json => {
            let items: Vec<_> = vault.data().active().cloned().collect();
            let name = vault.name().to_string();
            match importers::export_json(&items, &name) {
                Ok(content) => importers::write_export(&path, &content)
                    .map(|()| format!("Wrote {} entries (PLAINTEXT)", items.len())),
                Err(e) => Err(e),
            }
        }
    };
    let _ = vault.save();
    match outcome {
        Ok(message) => {
            state.tools.export.message = Some(message.clone());
            state.notify(message);
        }
        Err(e) => {
            state.tools.export.message = Some(format!("error: {e}"));
            state.notify_error(e.to_string());
        }
    }
}

/// Change the master password.
fn change_password(state: &mut AppState) {
    let current = state.tools.change.current.clone();
    let new = state.tools.change.new.clone();
    if new != state.tools.change.confirm {
        state.tools.change.error = Some("the two passwords do not match".into());
        return;
    }
    let key_file = if state.tools.change.key_file.trim().is_empty() {
        None
    } else {
        match std::fs::read(crate::unlock::expand(&state.tools.change.key_file)) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                state.tools.change.error = Some(format!("key file: {e}"));
                return;
            }
        }
    };
    let preset = state.tools.change.kdf.unwrap_or(KdfPreset::Interactive);
    let Some(vault) = state.vault.as_mut() else {
        return;
    };
    match vault.change_password(&current, &new, key_file.as_deref(), Some(preset)) {
        Ok(()) => match vault.save() {
            Ok(()) => {
                state.tools.change = ChangeState::default();
                state.tools.open = None;
                state.notify("Master password changed");
            }
            Err(e) => state.tools.change.error = Some(e.to_string()),
        },
        Err(e) => state.tools.change.error = Some(e.to_string()),
    }
}

/// Set (or replace) the unlock PIN for the open vault.
fn save_pin(state: &mut AppState) {
    let pin = state.tools.pin.pin.trim().to_string();
    if pin != state.tools.pin.confirm {
        state.tools.pin.error = Some("the two PINs do not match".into());
        return;
    }
    if let Err(e) = aurapass_core::pin::validate_pin(&pin) {
        state.tools.pin.error = Some(e.to_string());
        return;
    }
    let envelope = {
        let Some(vault) = state.vault.as_ref() else {
            state.tools.pin.error = Some("unlock a vault first".into());
            return;
        };
        vault.pin_envelope(&pin, &state.pin_session)
    };
    match envelope {
        Ok(entry) => {
            state.config.set_pin(entry);
            state.save_config();
            state.tools.pin = PinState::default();
            state.tools.open = None;
            state.refresh_pin_mode();
            state.notify("Unlock PIN set for this desktop session");
        }
        Err(e) => state.tools.pin.error = Some(e.to_string()),
    }
}

/// Forget the stored PIN.
fn remove_pin(state: &mut AppState) {
    let path = state.vault.as_ref().and_then(|v| v.path().map(|p| p.to_path_buf()));
    let Some(path) = path else {
        return;
    };
    state.config.remove_pin(&path);
    state.save_config();
    state.tools.pin = PinState::default();
    state.tools.open = None;
    state.refresh_pin_mode();
    state.notify("Unlock PIN removed; the master password is required again");
}

// --------------------------------------------------------------------- view

/// Draw the open dialog, if there is one.
pub fn view(state: &AppState) -> Option<Element<'_, Message>> {
    let modal = state.tools.open?;
    Some(match modal {
        // Handled by the assistant module, which owns the generator.
        Modal::Generator => return None,
        Modal::Health => health(state),
        Modal::Settings => settings(state),
        Modal::Activity => activity(state),
        Modal::Import => import(state),
        Modal::Export => export(state),
        Modal::ChangePassword => change(state),
        Modal::UnlockPin => pin(state),
        Modal::Bridge => bridge(state),
        Modal::About => about(),
        Modal::Categories => categories(state),
        Modal::NewItem => new_item(),
    })
}

/// The common modal chrome.
fn modal<'a>(
    glyph: Glyph,
    title: &str,
    subtitle: Option<String>,
    width: f32,
    body: Vec<Element<'a, Message>>,
    footer: Vec<Element<'a, Message>>,
    scroll_body: bool,
) -> Element<'a, Message> {
    let mut head: Vec<Element<'a, Message>> = vec![
        glyph::tinted(glyph, 18.0, theme::accent).into(),
        w::gap(10.0),
    ];
    let mut titles = column![w::title(title.to_string())];
    if let Some(subtitle) = subtitle {
        titles = titles.push(w::small(subtitle));
    }
    head.push(titles.width(Length::Fill).into());
    head.push(w::icon_button(Glyph::Close, 15.0, Some(Message::Close)).into());

    // A long body scrolls inside the card; the card itself never grows past
    // the window, because the modal sits in a padded overlay.
    w::dialog(
        width,
        row(head)
            .width(Length::Fill)
            .align_y(Alignment::Center)
            .into(),
        body,
        footer,
        scroll_body,
    )
}

/// A caption above a control.
fn field<'a>(label: &str, control: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    column![w::micro(label), w::vgap(5.0), control.into()]
        .width(Length::Fill)
        .into()
}

/// A single-line input bound to a `String` message.
fn input<'a>(
    placeholder: &str,
    value: &str,
    on_input: impl Fn(String) -> Message + 'a,
) -> Element<'a, Message> {
    text_input(placeholder, value)
        .on_input(on_input)
        .padding([9, 11])
        .size(theme::T_BODY)
        .font(theme::REG)
        .style(theme::input)
        .into()
}

/// A secret input with a reveal toggle.
fn secret<'a>(
    placeholder: &str,
    value: &str,
    reveal: bool,
    on_input: impl Fn(String) -> Message + 'a,
    toggle: Message,
) -> Element<'a, Message> {
    row![
        text_input(placeholder, value)
            .on_input(on_input)
            .secure(!reveal)
            .padding([9, 11])
            .size(theme::T_BODY)
            .font(theme::REG)
            .style(theme::input),
        w::icon_button(
            if reveal { Glyph::EyeOff } else { Glyph::Eye },
            16.0,
            Some(toggle)
        ),
    ]
    .spacing(6)
    .align_y(Alignment::Center)
    .into()
}

/// A minus / value / plus stepper.
fn stepper<'a>(
    value: u64,
    min: u64,
    max: u64,
    step: u64,
    unit: &str,
    message: fn(u64) -> Message,
) -> Element<'a, Message> {
    row![
        w::icon_button(
            Glyph::Minus,
            14.0,
            (value > min).then(|| message(value.saturating_sub(step).max(min)))
        ),
        container(w::strong(format!("{value} {unit}")))
            .width(Length::Fixed(96.0))
            .center_x(Length::Fixed(96.0)),
        w::icon_button(
            Glyph::Plus,
            14.0,
            (value < max).then(|| message((value + step).min(max)))
        ),
    ]
    .spacing(4)
    .align_y(Alignment::Center)
    .into()
}

/// A small tinted counter tile.
fn tile<'a>(label: &str, value: usize, tone: fn(&Tokens) -> iced::Color) -> Element<'a, Message> {
    container(
        column![
            text(value.to_string())
                .size(19.0)
                .font(theme::SEMI)
                .style(move |t: &Theme| text::Style {
                    color: Some(tone(&Tokens::of(t))),
                }),
            w::small(label.to_string()),
        ]
        .align_x(Alignment::Center),
    )
    .width(Length::Fixed(96.0))
    .padding([8, 6])
    .style(move |t: &Theme| {
        let k = Tokens::of(t);
        container::Style {
            background: Some(k.wash(tone(&k)).into()),
            border: iced::Border {
                color: iced::Color {
                    a: 0.28,
                    ..tone(&k)
                },
                width: 1.0,
                radius: theme::R_MD.into(),
            },
            ..container::Style::default()
        }
    })
    .into()
}

/// The colour for an audit severity.
fn severity_tone(severity: Severity) -> fn(&Tokens) -> iced::Color {
    match severity {
        Severity::Critical | Severity::High => theme::danger,
        Severity::Medium => theme::warn,
        Severity::Low => theme::accent,
        Severity::Info => theme::muted,
    }
}

// ------------------------------------------------------------------- health

/// The vault health dialog.
fn health(state: &AppState) -> Element<'_, Message> {
    let mut body: Vec<Element<'_, Message>> = Vec::new();

    let mut actions: Vec<Element<'_, Message>> = vec![
        w::secondary_icon_button(Glyph::ShieldCheck, "Run audit", Message::RunAudit).into(),
    ];
    if state
        .vault
        .as_ref()
        .is_some_and(|v| v.settings().breach_check_enabled)
    {
        actions.push(
            w::secondary_icon_button(Glyph::Globe, "Check breaches online", Message::RunOnlineAudit)
                .into(),
        );
    }
    body.push(row(actions).spacing(8).into());
    if let Some(note) = &state.tools.breach_note {
        body.push(w::small(note.clone()));
    }
    body.push(w::vgap(4.0));

    match &state.tools.audit {
        None => body.push(w::empty_state(
            Glyph::Gauge,
            "No audit yet",
            "Run one to score your vault's health and find weak, reused or breached passwords.",
        )),
        Some(report) => {
            body.push(
                row![
                    text(report.score.to_string())
                        .size(40.0)
                        .font(theme::BOLD)
                        .style(move |_t: &Theme| text::Style {
                            color: Some(theme::score_color(report.score)),
                        }),
                    w::gap(14.0),
                    column![
                        w::title(report.verdict().to_string()),
                        w::small(format!(
                            "{} items · {} passwords · {} checked against breaches",
                            report.counts.items,
                            report.counts.passwords,
                            report.breaches_checked
                        )),
                    ]
                    .width(Length::Fill),
                ]
                .align_y(Alignment::Center)
                .into(),
            );
            body.push(w::vgap(2.0));
            body.push(
                row![
                    tile("Weak", report.counts.weak, theme::danger),
                    tile("Reused", report.counts.reused, theme::warn),
                    tile("Breached", report.counts.breached, theme::danger),
                    tile("Old", report.counts.stale, theme::warn),
                    tile("No 2FA", report.counts.missing_totp, theme::accent),
                    tile("Expired", report.counts.expired, theme::danger),
                ]
                .spacing(7)
                .wrap()
                .into(),
            );

            if report.findings.is_empty() {
                body.push(
                    container(
                        row![
                            glyph::tinted(Glyph::Check, 16.0, theme::ok),
                            w::gap(8.0),
                            w::body("No problems found. Your vault is in good shape."),
                        ]
                        .align_y(Alignment::Center),
                    )
                    .width(Length::Fill)
                    .padding([10, 12])
                    .style(theme::well)
                    .into(),
                );
            } else {
                for finding in &report.findings {
                    body.push(finding_card(finding));
                }
            }
        }
    }

    modal(
        Glyph::Gauge,
        "Vault health",
        Some("Every check runs locally, except the breach lookup you start yourself.".into()),
        660.0,
        body,
        vec![w::secondary_button("Close", Message::Close).into()],
        true,
    )
}

/// One audit finding.
fn finding_card(finding: &Finding) -> Element<'_, Message> {
    let tone = severity_tone(finding.severity);
    container(
        column![
            row![
                w::chip(finding.severity.label(), tone),
                w::gap(7.0),
                w::strong(finding.item_title.clone()),
            ]
            .align_y(Alignment::Center),
            w::vgap(4.0),
            w::small(finding.detail.clone()),
            w::vgap(3.0),
            row![
                glyph::tinted(Glyph::ChevronRight, 13.0, theme::accent),
                w::gap(5.0),
                w::small(finding.remediation.clone()),
            ]
            .align_y(Alignment::Center),
        ]
        .width(Length::Fill),
    )
    .width(Length::Fill)
    .padding([10, 12])
    .style(move |t: &Theme| {
        let k = Tokens::of(t);
        container::Style {
            background: Some(k.canvas.into()),
            border: iced::Border {
                color: iced::Color {
                    a: 0.35,
                    ..tone(&k)
                },
                width: 1.0,
                radius: theme::R_MD.into(),
            },
            ..container::Style::default()
        }
    })
    .into()
}

// ----------------------------------------------------------------- settings

/// The preferences dialog.
fn settings(state: &AppState) -> Element<'_, Message> {
    let mut body: Vec<Element<'_, Message>> = Vec::new();

    // ---- appearance
    let current = state.config.theme.as_str();
    body.push(w::card(
        "Appearance",
        vec![
            field(
                "Theme",
                row![
                    w::segment("Follow the system", current == "system", Message::Theme("system".into())),
                    w::segment("Light", current == "light", Message::Theme("light".into())),
                    w::segment("Dark", current == "dark", Message::Theme("dark".into())),
                ]
                .spacing(6),
            ),
            w::check(
                "Compact item list",
                state
                    .tools
                    .settings
                    .as_ref()
                    .is_some_and(|s| s.compact_list),
                Message::CompactList,
            ),
        ],
    ));

    // ---- security
    let mut security: Vec<Element<'_, Message>> = Vec::new();
    if let Some(draft) = &state.tools.settings {
        security.push(
            row![
                field(
                    "Auto-lock after (0 disables)",
                    stepper(draft.auto_lock_secs, 0, 3600, 60, "s", Message::AutoLock),
                ),
                field(
                    "Clear the clipboard after (0 disables)",
                    stepper(
                        draft.clipboard_clear_secs,
                        0,
                        600,
                        15,
                        "s",
                        Message::ClipboardClear,
                    ),
                ),
            ]
            .spacing(18)
            .width(Length::Fill)
            .into(),
        );
        security.push(
            row![
                w::check(
                    "Hide secrets by default",
                    draft.hide_secrets_default,
                    Message::HideSecrets,
                ),
                w::check(
                    "Allow online breach checks",
                    draft.breach_check_enabled,
                    Message::BreachChecks,
                ),
            ]
            .spacing(18)
            .width(Length::Fill)
            .into(),
        );
        security.push(w::vgap(1.0));
        security.push(
            w::secondary_icon_button(
                Glyph::Key,
                "Change the master password…",
                Message::Open(Modal::ChangePassword),
            )
            .into(),
        );
        let has_pin = state
            .vault
            .as_ref()
            .and_then(|v| v.path())
            .is_some_and(|path| state.config.pin_for(path).is_some());
        security.push(
            w::secondary_icon_button(
                Glyph::Grid,
                if has_pin {
                    "Change or remove the unlock PIN…"
                } else {
                    "Set an unlock PIN…"
                },
                Message::Open(Modal::UnlockPin),
            )
            .into(),
        );
        security.push(w::small(if has_pin {
            "The PIN unlocks this vault after you log in to the computer; the master password \n            is still accepted, and is required again after a logout or reboot."
        } else {
            "Skip the master password for the rest of this desktop login."
        }));
    } else {
        security.push(w::small("Unlock a vault to change its settings."));
    }
    body.push(w::card("Security", security));

    // ---- tray
    let mut tray: Vec<Element<'_, Message>> = vec![
        w::check(
            "Show a tray icon (restart to apply)",
            state.config.tray_enabled,
            Message::TrayEnabled,
        ),
        w::check(
            "Closing the window hides it to the tray",
            state.config.close_to_tray,
            Message::CloseToTray,
        ),
        w::check(
            "Dark tray glyph, for light panels (restart to apply)",
            state.config.tray_icon_dark,
            Message::TrayDark,
        ),
    ];
    if state.tray.is_none() {
        tray.push(w::small(
            "No tray is available on this desktop right now, so closing the window quits AuraPass.",
        ));
    }
    body.push(w::card("System tray", tray));

    // ---- startup
    body.push(w::card(
        "Startup",
        vec![
            w::check(
                "Open automatically at startup",
                state.config.autostart,
                Message::Autostart,
            ),
            w::small("Uses your desktop's autostart folder; the vault still starts locked."),
        ],
    ));

    // ---- default policy
    let mut policy_rows: Vec<Element<'_, Message>> = Vec::new();
    if let Some(draft) = &state.tools.settings {
        let policy = &draft.password_policy;
        policy_rows.push(field(
            "Length",
            stepper(
                policy.length as u64,
                6,
                128,
                1,
                "characters",
                |n| Message::PolicyLength(n as usize),
            ),
        ));
        policy_rows.push(
            row![
                w::check("a–z", policy.lowercase, Message::PolicyLower),
                w::gap(10.0),
                w::check("A–Z", policy.uppercase, Message::PolicyUpper),
                w::gap(10.0),
                w::check("0–9", policy.digits, Message::PolicyDigits),
                w::gap(10.0),
                w::check("!@#$", policy.symbols, Message::PolicySymbols),
            ]
            .width(Length::Fill)
            .align_y(Alignment::Center)
            .into(),
        );
        policy_rows.push(
            row![
                w::check(
                    "Avoid look-alike characters",
                    policy.exclude_ambiguous,
                    Message::PolicyAmbiguous,
                ),
                w::grow(),
                w::small(format!(
                    "About {:.0} bits of entropy",
                    policy.entropy_bits()
                )),
            ]
            .width(Length::Fill)
            .align_y(Alignment::Center)
            .into(),
        );
    } else {
        policy_rows.push(w::small("Unlock a vault to see its password policy."));
    }
    body.push(w::card("Default password policy", policy_rows));

    modal(
        Glyph::Gear,
        "Preferences",
        Some("These live in your config file, not the vault.".into()),
        600.0,
        body,
        vec![
            w::secondary_button("Revert", Message::RevertSettings).into(),
            w::primary_button("Save", Message::SaveSettings).into(),
        ],
        true,
    )
}

// ----------------------------------------------------------------- activity

/// The recent-activity dialog.
fn activity(state: &AppState) -> Element<'_, Message> {
    let mut body: Vec<Element<'_, Message>> = Vec::new();

    let entries: Vec<(String, &'static str, String, Option<String>)> = state
        .vault
        .as_ref()
        .map(|vault| {
            vault
                .data()
                .activity
                .iter()
                .rev()
                .take(500)
                .map(|entry| {
                    (
                        entry.at.format("%d %b %Y · %H:%M").to_string(),
                        entry.kind.label(),
                        entry.subject.clone(),
                        entry.detail.clone(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    if entries.is_empty() {
        body.push(w::empty_state(
            Glyph::History,
            "Nothing yet",
            "Unlocking, editing, importing and autofilling are all recorded here.",
        ));
    } else {
        for (at, kind, subject, detail) in entries {
            let mut lines = column![
                row![
                    w::chip(kind, theme::accent),
                    w::gap(7.0),
                    w::strong(subject),
                    w::grow(),
                    w::small(at),
                ]
                .align_y(Alignment::Center),
            ];
            if let Some(detail) = detail {
                lines = lines.push(w::vgap(3.0)).push(w::small(detail));
            }
            body.push(
                container(lines.width(Length::Fill))
                    .width(Length::Fill)
                    .padding([8, 10])
                    .style(theme::well)
                    .into(),
            );
        }
    }

    modal(
        Glyph::History,
        "Activity",
        Some("Kept inside the vault, newest first.".into()),
        620.0,
        body,
        vec![w::secondary_button("Close", Message::Close).into()],
        true,
    )
}

// ------------------------------------------------------------------- import

/// The import dialog.
fn import(state: &AppState) -> Element<'_, Message> {
    let form = &state.tools.import;
    let mut body: Vec<Element<'_, Message>> = Vec::new();

    body.push(field(
        "File to import",
        row![
            container(input(
                "~/Downloads/enpass-export.json",
                &form.path,
                Message::ImportPath,
            ))
            .width(Length::Fill),
            w::gap(6.0),
            w::secondary_icon_button(Glyph::Folder, "Choose…", Message::BrowseImport),
        ]
        .align_y(Alignment::Center),
    ));
    body.push(field(
        "Format",
        iced::widget::pick_list(
            FormatChoice::all(),
            Some(FormatChoice(form.format)),
            |choice| Message::ImportFormat(choice.0),
        )
        .text_size(theme::T_BODY)
        .font(theme::REG)
        .padding([7, 10])
        .style(theme::pick_list)
        .menu_style(theme::menu),
    ));
    body.push(field(
        "File everything under this category (optional)",
        input("Imported", &form.category, Message::ImportCategory),
    ));
    body.push(w::check(
        "Overwrite items that look like duplicates",
        form.overwrite,
        Message::ImportOverwrite,
    ));

    if let Some(error) = &form.error {
        body.push(banner(error.clone(), true));
    }
    if let Some(message) = &form.applied {
        body.push(banner(message.clone(), false));
    }

    if let Some(preview) = &form.preview {
        body.push(w::vgap(4.0));
        body.push(w::strong(preview.summary()));
        for warning in &preview.warnings {
            body.push(
                row![
                    glyph::tinted(Glyph::Warning, 13.0, theme::warn),
                    w::gap(6.0),
                    w::small(warning.clone()),
                ]
                .align_y(Alignment::Center)
                .into(),
            );
        }
        let rows: Vec<Element<'_, Message>> = preview
            .items
            .iter()
            .take(200)
            .map(|item| {
                row![
                    glyph::tinted(Glyph::of_kind(item.kind), 14.0, theme::muted),
                    w::gap(8.0),
                    w::body(item.title.clone()),
                    w::grow(),
                    w::small(
                        item.username
                            .clone()
                            .unwrap_or_default(),
                    ),
                ]
                .align_y(Alignment::Center)
                .padding([4, 8])
                .into()
            })
            .collect();
        if !rows.is_empty() {
            body.push(
                container(w::scroller(column(rows).spacing(1)).height(Length::Fixed(170.0)))
                    .width(Length::Fill)
                    .padding(4)
                    .style(theme::well)
                    .into(),
            );
        }
    }

    let mut footer: Vec<Element<'_, Message>> = Vec::new();
    if form.preview.is_some() {
        footer.push(w::primary_icon_button(Glyph::Import, "Import", Message::ImportApply).into());
    }
    footer.push(w::secondary_icon_button(Glyph::Search, "Preview", Message::ImportPreview).into());
    footer.push(w::secondary_button("Close", Message::Close).into());

    modal(
        Glyph::Import,
        "Import",
        Some("Enpass, Bitwarden, LastPass, Chrome, 1Password, KeePass and generic CSV.".into()),
        620.0,
        body,
        footer,
        false,
    )
}

// ------------------------------------------------------------------- export

/// The export dialog.
fn export(state: &AppState) -> Element<'_, Message> {
    let form = &state.tools.export;
    let mut body: Vec<Element<'_, Message>> = Vec::new();

    body.push(field(
        "Destination file",
        row![
            container(input(
                "~/Documents/aurapass-backup.aurapass",
                &form.path,
                Message::ExportPath
            ))
            .width(Length::Fill),
            w::gap(6.0),
            w::secondary_icon_button(Glyph::Folder, "Choose…", Message::BrowseExport),
        ]
        .align_y(Alignment::Center),
    ));
    body.push(w::micro("What to write"));
    body.push(
        row![
            w::segment(
                ExportKind::Backup.label(),
                form.kind == ExportKind::Backup,
                Message::ExportKind(ExportKind::Backup)
            ),
            w::segment(
                ExportKind::Csv.label(),
                form.kind == ExportKind::Csv,
                Message::ExportKind(ExportKind::Csv)
            ),
            w::segment(
                ExportKind::Json.label(),
                form.kind == ExportKind::Json,
                Message::ExportKind(ExportKind::Json)
            ),
        ]
        .spacing(6)
        .into(),
    );
    if form.kind != ExportKind::Backup {
        body.push(banner(
            "CSV and JSON exports are not encrypted. Delete the file when you are done.".into(),
            true,
        ));
    }
    if let Some(message) = &form.message {
        body.push(banner(message.clone(), message.starts_with("error")));
    }

    modal(
        Glyph::Download,
        "Export",
        Some("Take a copy of the vault, encrypted or plain.".into()),
        540.0,
        body,
        vec![
            w::primary_icon_button(Glyph::Download, "Export", Message::ExportRun).into(),
            w::secondary_button("Close", Message::Close).into(),
        ],
        false,
    )
}

// ----------------------------------------------------------- change password

/// The change-master-password dialog.
fn change(state: &AppState) -> Element<'_, Message> {
    let form = &state.tools.change;
    let mut body: Vec<Element<'_, Message>> = Vec::new();

    body.push(field(
        "Current master password",
        secret(
            "Your current password",
            &form.current,
            form.reveal,
            Message::ChangeCurrent,
            Message::ChangeReveal,
        ),
    ));
    body.push(field(
        "New master password",
        secret(
            "A new password",
            &form.new,
            form.reveal,
            Message::ChangeNew,
            Message::ChangeReveal,
        ),
    ));
    body.push(field(
        "Repeat the new password",
        secret(
            "Type it again",
            &form.confirm,
            form.reveal,
            Message::ChangeConfirm,
            Message::ChangeReveal,
        ),
    ));
    body.push(field(
        "Key file (leave blank to keep the current one)",
        input("~/keys/vault.key", &form.key_file, Message::ChangeKeyFile),
    ));
    body.push(w::micro("Key derivation"));
    let current = form.kdf.unwrap_or(KdfPreset::Interactive);
    let mut segments: Vec<Element<'_, Message>> = Vec::new();
    for preset in KdfPreset::ALL {
        segments.push(
            w::segment(preset.label(), current == preset, Message::ChangeKdf(preset)).into(),
        );
    }
    body.push(row(segments).spacing(6).into());
    body.push(w::small(current.description()));

    if let Some(error) = &form.error {
        body.push(banner(error.clone(), true));
    }

    modal(
        Glyph::Key,
        "Change master password",
        Some("The vault is re-keyed and written out immediately.".into()),
        560.0,
        body,
        vec![
            w::secondary_button("Cancel", Message::Close).into(),
            w::primary_button("Change password", Message::ChangeRun).into(),
        ],
        false,
    )
}

// ------------------------------------------------------------------ PIN

/// The unlock-PIN dialog.
fn pin(state: &AppState) -> Element<'_, Message> {
    let form = &state.tools.pin;
    let has_pin = state
        .vault
        .as_ref()
        .and_then(|v| v.path())
        .is_some_and(|path| state.config.pin_for(path).is_some());
    let mut body: Vec<Element<'_, Message>> = vec![
        w::body(
            "A PIN is quicker than the master password and only works until you log out of \
             this computer. It is protected with Argon2id and disabled after too many wrong \
             guesses.",
        ),
        w::vgap(12.0),
    ];
    body.push(field(
        "New PIN (4–12 digits)",
        secret(
            "Choose a PIN",
            &form.pin,
            form.reveal,
            Message::PinNew,
            Message::PinReveal,
        ),
    ));
    body.push(field(
        "Repeat the PIN",
        secret(
            "Type it again",
            &form.confirm,
            form.reveal,
            Message::PinConfirm,
            Message::PinReveal,
        ),
    ));
    if let Some(error) = &form.error {
        body.push(banner(error.clone(), true));
    }
    let mut footer = vec![
        w::secondary_button("Cancel", Message::Close).into(),
        w::primary_button(if has_pin { "Replace PIN" } else { "Set PIN" }, Message::PinSave)
            .into(),
    ];
    if has_pin {
        footer.insert(0, w::secondary_button("Remove PIN", Message::PinRemove).into());
    }
    modal(
        Glyph::Grid,
        if has_pin { "Change the unlock PIN" } else { "Set an unlock PIN" },
        Some("One PIN per vault, remembered for this desktop session.".into()),
        470.0,
        body,
        footer,
        false,
    )
}

// ------------------------------------------------------------------- bridge

/// The browser-bridge dialog.
fn bridge(state: &AppState) -> Element<'_, Message> {
    let running = state.bridge.is_some();
    let mut body: Vec<Element<'_, Message>> = Vec::new();

    body.push(w::body(
        "The bridge lets the AuraPass browser extension fill logins. It only ever talks over \
         the loopback interface, and a browser cannot read anything until you approve it here.",
    ));
    body.push(w::vgap(6.0));
    body.push(
        row![
            w::micro("Status"),
            w::gap(8.0),
            w::chip(
                if running { "ready" } else { "stopped" },
                if running { theme::ok } else { theme::muted }
            ),
        ]
        .align_y(Alignment::Center)
        .into(),
    );

    if let Some(error) = &state.bridge_error {
        body.push(w::vgap(6.0));
        body.push(banner(error.clone(), true));
    }

    // Which browsers may talk to this vault.
    body.push(w::vgap(14.0));
    body.push(w::micro("Connected browsers"));
    body.push(w::vgap(6.0));

    let paired = &state.config.bridge.paired;
    if paired.is_empty() {
        body.push(
            container(w::small(
                "None yet. Open the AuraPass extension in your browser and it will ask \
                 to connect; approve it with the dialog that appears here.",
            ))
            .width(Length::Fill)
            .padding([10, 12])
            .style(theme::well)
            .into(),
        );
    } else {
        let mut list = column![].spacing(6);
        for browser in paired {
            let id = browser.id.clone();
            let name = if browser.name.trim().is_empty() {
                "Browser".to_string()
            } else {
                browser.name.clone()
            };
            let since = browser
                .paired_at
                .get(..10)
                .map(str::to_string)
                .unwrap_or_default();
            list = list.push(
                container(
                    row![
                        glyph::tinted(Glyph::Globe, 15.0, theme::accent),
                        w::gap(9.0),
                        column![w::strong(name), w::small(format!("connected {since}"))]
                            .width(Length::Fill),
                        w::secondary_icon_button(Glyph::Trash, "Revoke", Message::BridgeRevoke(id)),
                    ]
                    .align_y(Alignment::Center),
                )
                .width(Length::Fill)
                .padding([8, 10])
                .style(theme::well),
            );
        }
        body.push(list.into());
    }

    body.push(w::vgap(14.0));
    body.push(w::check(
        "Let the extension unlock the vault remotely",
        !state.config.bridge.require_gui,
        Message::BridgeAllowRemote,
    ));
    body.push(w::small(
        "With this off — the recommended setting — the extension can only use a vault the \
         desktop app has already unlocked.",
    ));

    body.push(w::vgap(12.0));
    body.push(w::hline());
    body.push(w::vgap(10.0));
    body.push(w::micro("How pairing works"));
    body.push(w::small(
        "1. Install the AuraPass extension in your browser.\n\
         2. Click its toolbar button. AuraPass asks whether to allow the browser.\n\
         3. Approve once. The extension and the app share a secret from then on; \
         nothing is typed or copied, and the local address stays hidden.",
    ));

    let mut footer: Vec<Element<'_, Message>> = Vec::new();
    if running {
        footer.push(w::secondary_icon_button(Glyph::Close, "Stop", Message::BridgeStop).into());
    } else {
        footer.push(w::primary_icon_button(Glyph::Sparkle, "Start", Message::BridgeStart).into());
    }
    footer.push(w::secondary_button("Close", Message::Close).into());

    modal(
        Glyph::Globe,
        "Browser extension",
        Some("Approve a browser once; it stays connected until you revoke it.".into()),
        620.0,
        body,
        footer,
        true,
    )
}

// -------------------------------------------------------------------- about

/// The About dialog.
fn about<'a>() -> Element<'a, Message> {
    let mut body: Vec<Element<'a, Message>> = Vec::new();

    body.push(
        column![
            container(w::brand_badge(52.0)).width(Length::Fill).center_x(Length::Fill),
            w::vgap(10.0),
            text(aurapass_core::APP_NAME)
                .size(23.0)
                .font(theme::BOLD)
                .style(|t: &Theme| text::Style {
                    color: Some(Tokens::of(t).text),
                }),
            w::vgap(3.0),
            w::small(format!("version {} · by pa1", aurapass_core::VERSION)),
        ]
        .align_x(Alignment::Center)
        .width(Length::Fill)
        .into(),
    );

    modal(
        Glyph::Info,
        "About AuraPass",
        None,
        520.0,
        body,
        vec![w::secondary_button("Close", Message::Close).into()],
        false,
    )
}

// -------------------------------------------------------------- categories

/// The category manager.
fn categories(state: &AppState) -> Element<'_, Message> {
    let mut body: Vec<Element<'_, Message>> = Vec::new();

    let categories = state
        .vault
        .as_ref()
        .map(|v| v.data().categories.clone())
        .unwrap_or_default();

    body.push(field(
        "New category",
        row![
            input("Work, Family, …", &state.tools.new_category, Message::NewCategory),
            w::primary_icon_button(Glyph::Plus, "Add", Message::AddCategory),
        ]
        .spacing(6)
        .width(Length::Fill)
        .align_y(Alignment::Center),
    ));

    if categories.is_empty() {
        body.push(w::vgap(6.0));
        body.push(w::empty_state(
            Glyph::Folder,
            "No categories yet",
            "Categories are a second axis of filing, alongside item types and tags.",
        ));
    } else {
        for category in categories {
            let id = category.id;
            let count = state
                .vault
                .as_ref()
                .map(|v| {
                    v.data()
                        .items
                        .iter()
                        .filter(|i| !i.trashed && i.category == Some(id))
                        .count()
                })
                .unwrap_or(0);
            body.push(
                row![
                    glyph::tinted(Glyph::Folder, 16.0, theme::accent),
                    w::gap(8.0),
                    input("Category name", &category.name, move |name| {
                        Message::RenameCategory(id, name)
                    }),
                    w::small(format!("{count} item{}", if count == 1 { "" } else { "s" })),
                    w::icon_button(Glyph::Trash, 15.0, Some(Message::DeleteCategory(id))),
                ]
                .spacing(6)
                .width(Length::Fill)
                .align_y(Alignment::Center)
                .into(),
            );
        }
    }

    modal(
        Glyph::Folder,
        "Categories",
        Some("Renaming saves as you type.".into()),
        560.0,
        body,
        vec![w::secondary_button("Close", Message::Close).into()],
        false,
    )
}

// ----------------------------------------------------------------- new item

/// The kind picker shown by the New item button.
fn new_item<'a>() -> Element<'a, Message> {
    let mut tiles: Vec<Element<'a, Message>> = Vec::new();
    for kind in ItemKind::ALL {
        tiles.push(
            iced::widget::button(
                column![
                    glyph::tinted(Glyph::of_kind(kind), 20.0, theme::accent),
                    w::vgap(7.0),
                    w::small(kind.label()),
                ]
                .align_x(Alignment::Center)
                .width(Length::Fill),
            )
            .width(Length::Fixed(104.0))
            .padding([12, 8])
            .style(theme::row_plain)
            .on_press(Message::NewItem(kind))
            .into(),
        );
    }

    modal(
        Glyph::Plus,
        "What would you like to add?",
        None,
        600.0,
        vec![row(tiles).spacing(7).wrap().into()],
        vec![w::secondary_button("Cancel", Message::Close).into()],
        false,
    )
}

// ------------------------------------------------------------------ helpers

/// A coloured message strip.
fn banner<'a>(text: String, bad: bool) -> Element<'a, Message> {
    let tone: fn(&Tokens) -> iced::Color = if bad { theme::danger } else { theme::ok };
    container(
        row![
            glyph::tinted(
                if bad {
                    Glyph::CircleAlert
                } else {
                    Glyph::CircleCheck
                },
                15.0,
                tone
            ),
            w::gap(8.0),
            w::body(text),
        ]
        .align_y(Alignment::Center),
    )
    .width(Length::Fill)
    .padding([8, 10])
    .style(move |t: &Theme| {
        let k = Tokens::of(t);
        container::Style {
            background: Some(k.wash(tone(&k)).into()),
            border: iced::Border {
                color: iced::Color {
                    a: 0.3,
                    ..tone(&k)
                },
                width: 1.0,
                radius: theme::R_SM.into(),
            },
            ..container::Style::default()
        }
    })
    .into()
}
