//! System-tray integration.
//!
//! AuraPass registers a freedesktop `StatusNotifierItem` (the modern Linux
//! tray protocol, used by Ubuntu/GNOME, KDE and friends) through the pure-Rust
//! `ksni` crate. The tray owns its own D-Bus thread; all it does is push small
//! commands down an `mpsc` channel that the GUI polls once a frame. Nothing
//! here blocks the UI except a brief, bounded property refresh.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::{MenuItem, StandardItem};
use ksni::{Icon, Tray as KsniTray};

use crate::icon;

/// A request coming from the tray icon or its menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayCommand {
    /// Left click: show the window if hidden, hide it if shown.
    Toggle,
    /// Show and focus the main window.
    Show,
    /// Open the quick-assistant popup.
    QuickAssistant,
    /// Lock the vault immediately.
    Lock,
    /// Quit the application for real.
    Quit,
}

/// The bits of application state the tray shows.
#[derive(Default)]
pub struct TrayStatus {
    /// Vault display name, empty while locked.
    pub title: String,
    /// Whether a vault is currently open.
    pub unlocked: bool,
}

/// The `StatusNotifierItem` implementation.
struct TrayIcon {
    tx: Sender<TrayCommand>,
    status: Arc<Mutex<TrayStatus>>,
    /// `true` for a dark glyph (light panels), `false` for a light glyph.
    dark: bool,
}

/// Pixel sizes we hand to the panel; it picks the best fit.
const ICON_SIZES: [usize; 4] = [22, 24, 32, 48];

impl TrayIcon {
    fn item(label: &str, icon_name: &str, cmd: TrayCommand) -> MenuItem<Self> {
        StandardItem {
            label: label.to_string(),
            icon_name: icon_name.to_string(),
            activate: Box::new(move |this: &mut Self| {
                let _ = this.tx.send(cmd);
            }),
            ..Default::default()
        }
        .into()
    }
}

impl KsniTray for TrayIcon {
    fn id(&self) -> String {
        "aurapass".to_string()
    }

    fn title(&self) -> String {
        let status = self.status.lock().expect("tray status lock poisoned");
        match (status.unlocked, status.title.is_empty()) {
            (true, false) => format!("AuraPass — {}", status.title),
            (true, true) => "AuraPass — unlocked".to_string(),
            _ => "AuraPass — locked".to_string(),
        }
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        // A near-black glyph reads on a light panel; a near-white glyph reads
        // on the dark panel Ubuntu ships by default.
        let rgb = if self.dark {
            [0x1b, 0x18, 0x26]
        } else {
            [0xf4, 0xf4, 0xf9]
        };
        ICON_SIZES
            .iter()
            .map(|&size| Icon {
                width: size as i32,
                height: size as i32,
                data: icon::to_argb32(&icon::keyhole_rgba(size, rgb)),
            })
            .collect()
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            Self::item("Open AuraPass", "window-new", TrayCommand::Show),
            Self::item(
                "Quick assistant",
                "dialog-password",
                TrayCommand::QuickAssistant,
            ),
            MenuItem::Separator,
            Self::item("Lock vault", "changes-prevent", TrayCommand::Lock),
            MenuItem::Separator,
            Self::item("Quit AuraPass", "application-exit", TrayCommand::Quit),
        ]
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send(TrayCommand::Toggle);
    }

    fn secondary_activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send(TrayCommand::QuickAssistant);
    }
}

/// A live tray icon.
pub struct Tray {
    handle: Handle<TrayIcon>,
    rx: Receiver<TrayCommand>,
}

impl Tray {
    /// Register the tray icon. `dark_glyph` selects the glyph variant.
    pub fn start(dark_glyph: bool) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel();
        let status = Arc::new(Mutex::new(TrayStatus::default()));
        let icon = TrayIcon {
            tx,
            status: status.clone(),
            dark: dark_glyph,
        };
        // Fail fast when no `StatusNotifierWatcher` is on the session bus. The
        // alternative — claiming the name anyway and hoping a host turns up —
        // would leave the window hidden with nothing to bring it back, so we
        // prefer to report that the tray is unavailable and let the app keep
        // closing normally.
        let handle = icon
            .assume_sni_available(false)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(Self { handle, rx })
    }

    /// Non-blocking read of the next tray command.
    pub fn poll(&self) -> Option<TrayCommand> {
        self.rx.try_recv().ok()
    }

    /// Push the current vault name / lock state to the tray.
    pub fn set_status(&self, title: impl Into<String>, unlocked: bool) {
        let title = title.into();
        let _ = self.handle.update(|tray| {
            if let Ok(mut status) = tray.status.lock() {
                status.title = title;
                status.unlocked = unlocked;
            }
        });
    }
}
