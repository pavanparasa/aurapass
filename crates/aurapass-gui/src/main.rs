//! `aurapass-desktop` — the AuraPass desktop application.
//!
//! A thin iced front-end over `aurapass-core`. It also hosts the browser bridge
//! in-process, so the extension talks to the same vault the window shows.
//!
//! The renderer is iced's software rasteriser (tiny-skia) rather than a GPU
//! backend: AuraPass draws a handful of flat panels, and doing it on the CPU
//! keeps the app at a fraction of the resident memory a GL/Vulkan stack would
//! cost (no Mesa driver, no shader compiler, no GPU allocation).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod assistant;
mod browse;
mod editor;
mod filedialog;
mod glyph;
mod icon;
mod instance;
mod theme;
mod tools;
mod tray;
mod unlock;
mod widgets;

fn main() -> iced::Result {
    // AuraPass needs window control that the Wayland protocol does not offer:
    // winit's Wayland backend cannot hide a window (`set_visible` is a no-op),
    // so "close to tray" would silently do nothing, and a Wayland client cannot
    // choose where its window appears, so the quick assistant could not open
    // under the browser's toolbar button. Every modern Ubuntu session ships
    // XWayland, so route through it when an X server is reachable. The desktop
    // itself keeps running Wayland; only this app talks X11.
    let has_x11 = std::env::var_os("DISPLAY").is_some();
    if has_x11 {
        // SAFETY: this runs before iced starts any thread or reads the
        // environment, so there is no concurrent access.
        unsafe {
            std::env::remove_var("WAYLAND_DISPLAY");
        }
    }

    // One window per user profile. A second launch wakes the existing window
    // and exits instead of starting a second bridge/tray/auto-lock timer.
    let Some(_instance) = instance::acquire() else {
        return Ok(());
    };

    let config = aurapass_core::config::AppConfig::load();
    let size = iced::Size::new(
        config.window.width.max(app::MAIN_MIN_SIZE.width),
        config.window.height.max(app::MAIN_MIN_SIZE.height),
    );

    iced::application(
        app::AppState::boot,
        app::AppState::update,
        app::AppState::view,
    )
    .title(app::AppState::window_title)
    .theme(app::AppState::theme)
    .style(app::AppState::window_style)
    .subscription(app::AppState::subscription)
    .font(theme::INTER)
    .font(glyph::LUCIDE_FONT_BYTES)
    .default_font(theme::REG)
    .window(iced::window::Settings {
        size,
        min_size: Some(app::MAIN_MIN_SIZE),
        // Native decorations: the window manager draws the title bar, controls
        // and taskbar entry, so AuraPass behaves like every other app on the
        // desktop and can be switched between with Alt+Tab / the dock.
        decorations: true,
        resizable: true,
        // Lets the compact assistant show the desktop through its rounded
        // corners. The main window paints an opaque background over it.
        transparent: true,
        // We close (or hide to the tray) ourselves, in `update`.
        exit_on_close_request: false,
        icon: icon::window_icon(128),
        platform_specific: iced::window::settings::PlatformSpecific {
            // Matches `aurapass.desktop`, so the shell shows the right name and
            // icon in the dock and the window list.
            application_id: aurapass_core::APP_ID.to_string(),
            override_redirect: false,
        },
        ..iced::window::Settings::default()
    })
    .centered()
    .run()
}
