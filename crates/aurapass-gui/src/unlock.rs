//! The unlock / create-vault screen.

use iced::widget::{column, container, row, scrollable, text_input};
use iced::{Alignment, Element, Length, Task, Theme};

use aurapass_core::crypto::KdfPreset;
use aurapass_core::pin::{PIN_MAX_LEN, PIN_MIN_LEN};

use crate::app::{AppState, Message as AppMessage};
use crate::glyph::{self, Glyph};
use crate::theme::{self, Tokens};
use crate::widgets as w;

/// PIN fields accept digits only, up to the format limit.
fn digits_only(value: &str) -> bool {
    value.len() <= PIN_MAX_LEN && value.chars().all(|c| c.is_ascii_digit())
}

/// Expand a leading `~` to the user's home directory.
pub fn expand(path: &str) -> String {
    let trimmed = path.trim();
    if let Some(rest) = trimmed.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return format!("{}/{}", home.to_string_lossy(), rest);
    }
    trimmed.to_string()
}

/// The unlock-screen form.
#[derive(Debug, Clone, Default)]
pub struct UnlockState {
    /// Path to the vault file.
    pub path: String,
    /// The master password.
    pub password: String,
    /// The session PIN, when the user is unlocking with one.
    pub pin: String,
    /// Show the PIN field instead of the master password.
    pub use_pin: bool,
    /// Optional key file.
    pub key_file: String,
    /// Whether the password is shown in the clear.
    pub reveal: bool,
    /// The last error, if any.
    pub error: Option<String>,
    /// Whether the "create a vault" form is showing.
    pub creating: bool,
    /// New-vault display name.
    pub new_name: String,
    /// New-vault path.
    pub new_path: String,
    /// New-vault master password.
    pub new_password: String,
    /// New-vault password confirmation.
    pub new_confirm: String,
    /// PIN chosen at creation.
    pub new_pin: String,
    /// PIN confirmation.
    pub new_pin_confirm: String,
    /// KDF preset: `interactive`, `moderate` or `paranoid`.
    pub kdf: String,
}

/// Messages from the unlock screen.
#[derive(Debug, Clone)]
pub enum Message {
    /// The vault path changed.
    Path(String),
    /// The password changed.
    Password(String),
    /// The unlock PIN changed.
    Pin(String),
    /// Switch to entering the master password.
    UsePassword,
    /// Switch back to the PIN.
    UsePin,
    /// The key file changed.
    KeyFile(String),
    /// Show or hide the password.
    Reveal,
    /// Attempt the unlock.
    Submit,
    /// Switch to the create form.
    ShowCreate,
    /// Switch back to the unlock form.
    ShowUnlock,
    /// The new vault's name changed.
    NewName(String),
    /// The new vault's path changed.
    NewPath(String),
    /// The new vault's password changed.
    NewPassword(String),
    /// The new vault's confirmation changed.
    NewConfirm(String),
    /// The new vault's PIN changed.
    NewPin(String),
    /// The new vault's PIN confirmation changed.
    NewPinConfirm(String),
    /// The KDF preset changed.
    Kdf(String),
    /// Create the vault.
    Create,
    /// Select a remembered vault.
    Pick(String),
    /// Forget a remembered vault.
    Forget(usize),
    /// Browse for an existing vault file.
    BrowseVault,
    /// Browse for where to save a new vault.
    BrowseNewVault,
    /// The file chooser answered.
    Picked(Option<std::path::PathBuf>),
    /// The file chooser answered for the new vault.
    PickedNew(Option<std::path::PathBuf>),
}

/// Handle a message from the unlock screen.
pub fn update(state: &mut AppState, message: Message) -> Task<AppMessage> {
    match message {
        Message::Path(v) => state.unlock.path = v,
        Message::Password(v) => state.unlock.password = v,
        Message::Pin(v) => {
            if digits_only(&v) {
                state.unlock.pin = v;
            }
        }
        Message::UsePassword => {
            state.unlock.use_pin = false;
            state.unlock.pin.clear();
            state.unlock.error = None;
        }
        Message::UsePin => {
            if state.pin_available_for_selected() {
                state.unlock.use_pin = true;
                state.unlock.password.clear();
                state.unlock.error = None;
            }
        }
        Message::KeyFile(v) => state.unlock.key_file = v,
        Message::Reveal => state.unlock.reveal = !state.unlock.reveal,
        Message::Submit => state.do_unlock(),
        Message::ShowCreate => {
            state.unlock.creating = true;
            state.unlock.error = None;
            state.unlock.use_pin = false;
            if state.unlock.new_path.trim().is_empty() {
                state.unlock.new_path = aurapass_core::config::AppConfig::suggested_vault_path(
                    "AuraPass Vault",
                )
                .display()
                .to_string();
            }
        }
        Message::ShowUnlock => {
            state.unlock.creating = false;
            state.unlock.error = None;
            state.refresh_pin_mode();
        }
        Message::NewName(v) => state.unlock.new_name = v,
        Message::NewPath(v) => state.unlock.new_path = v,
        Message::NewPassword(v) => state.unlock.new_password = v,
        Message::NewConfirm(v) => state.unlock.new_confirm = v,
        Message::NewPin(v) => {
            if digits_only(&v) {
                state.unlock.new_pin = v;
            }
        }
        Message::NewPinConfirm(v) => {
            if digits_only(&v) {
                state.unlock.new_pin_confirm = v;
            }
        }
        Message::Kdf(v) => state.unlock.kdf = v,
        Message::Create => state.do_create(),
        Message::Pick(path) => {
            state.unlock.path = path;
            state.unlock.error = None;
            state.unlock.password.clear();
            state.refresh_pin_mode();
        }
        Message::Forget(index) => {
            let removed = state.config.vaults.get(index).map(|v| v.path.clone());
            if let Some(path) = removed {
                state.config.forget_vault(&path);
                state.save_config();
                state.notify("Vault forgotten");
            }
        }
        Message::BrowseVault => {
            let start = state.last_directory();
            return crate::filedialog::open_file(
                "Open a vault",
                start.as_deref(),
                Some(crate::filedialog::Filter {
                    label: "AuraPass vaults",
                    globs: "*.aurapass",
                }),
            )
            .map(Message::Picked).map(AppMessage::Unlock);
        }
        Message::Picked(chosen) => {
            if let Some(path) = chosen {
                let name = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "Vault".to_string());
                state
                    .config
                    .remember_vault(path.clone(), name);
                state.save_config();
                state.unlock.path = path.display().to_string();
                state.unlock.error = None;
                state.unlock.password.clear();
                state.refresh_pin_mode();
            }
        }
        Message::BrowseNewVault => {
            let start = state.last_directory();
            return crate::filedialog::save_file(
                "Choose where to keep the vault",
                start.as_deref(),
                "Vault.aurapass",
                Some(crate::filedialog::Filter {
                    label: "AuraPass vaults",
                    globs: "*.aurapass",
                }),
            )
            .map(Message::PickedNew).map(AppMessage::Unlock);
        }
        Message::PickedNew(chosen) => {
            if let Some(path) = chosen {
                let mut path = path;
                if path.extension().is_none() {
                    path.set_extension("aurapass");
                }
                state.unlock.new_path = path.display().to_string();
                if state.unlock.new_name.trim().is_empty() {
                    state.unlock.new_name = path
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                }
            }
        }
    }
    Task::none()
}

/// Draw the screen.
pub fn view(state: &AppState) -> Element<'_, Message> {
    let background = |t: &Theme| container::Style {
        background: Some(Tokens::of(t).panel.into()),
        ..container::Style::default()
    };
    if state.unlock.creating {
        // The create form is taller than a small window; let it scroll rather
        // than clip the PIN fields off the bottom.
        return container(
            scrollable(
                container(create_form(state))
                    .width(Length::Fill)
                    .center_x(Length::Fill)
                    .padding([22, 0]),
            )
            .height(Length::Fill)
            .style(theme::scrollbar),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .style(background)
        .into();
    }

    container(unlock_form(state))
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(background)
        .into()
}

/// The brand header shared by both forms.
fn header(subtitle: &str) -> Element<'static, Message> {
    column![
        container(w::brand_badge(56.0)).width(Length::Fill).center_x(Length::Fill),
        w::vgap(14.0),
        iced::widget::text(aurapass_core::APP_NAME)
            .size(27.0)
            .font(theme::BOLD)
            .style(|t: &Theme| iced::widget::text::Style {
                color: Some(Tokens::of(t).text),
            }),
        w::vgap(4.0),
        w::body(subtitle.to_string()),
    ]
    .align_x(Alignment::Center)
    .width(Length::Fill)
    .into()
}

/// A shadowed card.
fn card<'a>(body: Element<'a, Message>) -> Element<'a, Message> {
    container(body)
        .width(Length::Fixed(430.0))
        .padding(26)
        .style(theme::card)
        .into()
}

/// The password input, with a reveal toggle built in.
fn password_input<'a>(
    placeholder: &str,
    value: &str,
    reveal: bool,
    on_input: fn(String) -> Message,
    on_submit: Message,
) -> Element<'a, Message> {
    let field = text_input(placeholder, value)
        .on_input(on_input)
        .on_submit(on_submit)
        .secure(!reveal)
        .padding([9, 11])
        .size(theme::T_BODY)
        .font(theme::REG)
        .style(theme::input);

    row![
        field,
        w::icon_button(
            if reveal { Glyph::EyeOff } else { Glyph::Eye },
            16.0,
            Some(Message::Reveal)
        ),
    ]
    .spacing(6)
    .align_y(Alignment::Center)
    .into()
}

/// A plain text field.
fn input<'a>(
    placeholder: &str,
    value: &str,
    on_input: fn(String) -> Message,
    on_submit: Message,
) -> Element<'a, Message> {
    text_input(placeholder, value)
        .on_input(on_input)
        .on_submit(on_submit)
        .padding([9, 11])
        .size(theme::T_BODY)
        .font(theme::REG)
        .style(theme::input)
        .into()
}

/// The error banner, when something went wrong.
fn error_banner<'a>(error: Option<&String>) -> Option<Element<'a, Message>> {
    let error = error?;
    Some(
        container(
            row![
                glyph::tinted(Glyph::CircleAlert, 15.0, theme::danger),
                w::gap(8.0),
                w::body(error.clone()),
            ]
            .align_y(Alignment::Center),
        )
        .width(Length::Fill)
        .padding([8, 10])
        .style(|t: &Theme| {
            let k = Tokens::of(t);
            container::Style {
                background: Some(k.wash(k.danger).into()),
                border: iced::Border {
                    color: iced::Color { a: 0.3, ..k.danger },
                    width: 1.0,
                    radius: theme::R_SM.into(),
                },
                ..container::Style::default()
            }
        })
        .into(),
    )
}

/// The unlock form.
fn unlock_form(state: &AppState) -> Element<'_, Message> {
    let mut body: Vec<Element<'_, Message>> = vec![
        header("Offline-first password manager"),
        w::vgap(22.0),
    ];

    let vaults = state.config.pinned_vaults();
    if !vaults.is_empty() {
        body.push(w::micro("Vault"));
        body.push(w::vgap(6.0));
        let mut list = column![].spacing(6);
        for (index, vault) in vaults.iter().enumerate() {
            let path = vault.path.display().to_string();
            let name = vault.name.clone();
            let selected = state.unlock.path == path;
            list = list.push(
                row![
                    iced::widget::button(
                        row![
                            glyph::tinted(
                                Glyph::HardDrive,
                                15.0,
                                if selected { theme::accent } else { theme::muted }
                            ),
                            w::gap(9.0),
                            column![w::strong(name), w::small(path.clone())]
                                .width(Length::Fill),
                        ]
                        .align_y(Alignment::Center),
                    )
                    .width(Length::Fill)
                    .padding([6, 8])
                    .style(move |t: &Theme, s| {
                        let k = Tokens::of(t);
                        let hovered = matches!(
                            s,
                            iced::widget::button::Status::Hovered
                                | iced::widget::button::Status::Pressed
                        );
                        iced::widget::button::Style {
                            background: Some(
                                (if selected {
                                    k.accent_soft
                                } else if hovered {
                                    k.hover
                                } else {
                                    iced::Color::TRANSPARENT
                                })
                                .into(),
                            ),
                            text_color: k.text,
                            border: iced::Border {
                                color: if selected { k.accent } else { k.border },
                                width: 1.0,
                                radius: theme::R_SM.into(),
                            },
                            shadow: iced::Shadow::default(),
                            snap: true,
                        }
                    })
                    .on_press(Message::Pick(path)),
                    w::icon_button(Glyph::Close, 13.0, Some(Message::Forget(index))),
                ]
                .spacing(4)
                .align_y(Alignment::Center),
            );
        }
        body.push(list.into());
        body.push(w::vgap(8.0));
        body.push(
            container(
                iced::widget::button(
                    row![
                        glyph::icon(Glyph::Folder, 14.0),
                        w::gap(6.0),
                        w::small("Open another vault…"),
                    ]
                    .align_y(Alignment::Center),
                )
                .padding([5, 8])
                .style(theme::bare)
                .on_press(Message::BrowseVault),
            )
            .width(Length::Fill)
            .center_x(Length::Fill)
            .into(),
        );
        body.push(w::vgap(14.0));
    } else {
        body.push(w::micro("Vault file"));
        body.push(w::vgap(6.0));
        body.push(input(
            "~/AuraPass/Vault.aurapass",
            &state.unlock.path,
            Message::Path,
            Message::Submit,
        ));
        body.push(w::vgap(14.0));
    }

    if state.unlock.use_pin {
        body.push(w::micro("Unlock PIN"));
        body.push(w::vgap(6.0));
        body.push(password_input(
            "Your PIN",
            &state.unlock.pin,
            state.unlock.reveal,
            Message::Pin,
            Message::Submit,
        ));
        body.push(w::vgap(6.0));
        body.push(w::small(
            "Your PIN works until you log out of this computer. The master password is always accepted.",
        ));
    } else {
        body.push(w::micro("Master password"));
        body.push(w::vgap(6.0));
        body.push(password_input(
            "Your master password",
            &state.unlock.password,
            state.unlock.reveal,
            Message::Password,
            Message::Submit,
        ));

        body.push(w::vgap(14.0));
        body.push(w::micro("Key file (optional)"));
        body.push(w::vgap(6.0));
        body.push(input(
            "Leave empty unless the vault needs one",
            &state.unlock.key_file,
            Message::KeyFile,
            Message::Submit,
        ));
    }

    if let Some(banner) = error_banner(state.unlock.error.as_ref()) {
        body.push(w::vgap(12.0));
        body.push(banner);
    }

    body.push(w::vgap(20.0));
    body.push(
        container(w::primary_button("Unlock", Message::Submit).width(Length::Fill))
            .width(Length::Fill)
            .into(),
    );
    if state.unlock.use_pin {
        body.push(w::vgap(8.0));
        body.push(
            container(
                iced::widget::button(
                    row![
                        glyph::icon(Glyph::Key, 14.0),
                        w::gap(6.0),
                        w::body("Use the master password instead"),
                    ]
                    .align_y(Alignment::Center),
                )
                .padding([5, 8])
                .style(theme::bare)
                .on_press(Message::UsePassword),
            )
            .width(Length::Fill)
            .center_x(Length::Fill)
            .into(),
        );
    } else if state.pin_available_for_selected() {
        body.push(w::vgap(8.0));
        body.push(
            container(
                iced::widget::button(
                    row![
                        glyph::icon(Glyph::Grid, 14.0),
                        w::gap(6.0),
                        w::body("Unlock with your PIN"),
                    ]
                    .align_y(Alignment::Center),
                )
                .padding([5, 8])
                .style(theme::bare)
                .on_press(Message::UsePin),
            )
            .width(Length::Fill)
            .center_x(Length::Fill)
            .into(),
        );
    }

    body.push(w::vgap(10.0));
    body.push(
        container(
            iced::widget::button(
                row![
                    glyph::icon(Glyph::Plus, 14.0),
                    w::gap(6.0),
                    w::body("Create a new vault"),
                ]
                .align_y(Alignment::Center),
            )
            .padding([6, 10])
            .style(theme::bare)
            .on_press(Message::ShowCreate),
        )
        .width(Length::Fill)
        .center_x(Length::Fill)
        .into(),
    );

    card(column(body).into())
}

/// The create-vault form.
fn create_form(state: &AppState) -> Element<'_, Message> {
    let mut body: Vec<Element<'_, Message>> = vec![
        header("Set up a new vault"),
        w::vgap(22.0),
        w::micro("Vault name"),
        w::vgap(6.0),
        input("Personal", &state.unlock.new_name, Message::NewName, Message::Create),
        w::vgap(14.0),
        w::micro("Where to keep it"),
        w::vgap(6.0),
        row![
            container(input(
                "~/AuraPass/Vault.aurapass",
                &state.unlock.new_path,
                Message::NewPath,
                Message::Create,
            ))
            .width(Length::Fill),
            w::gap(6.0),
            w::secondary_icon_button(Glyph::Folder, "Choose…", Message::BrowseNewVault),
        ]
        .align_y(Alignment::Center)
        .into(),
        w::vgap(14.0),
        w::micro("Master password"),
        w::vgap(6.0),
        password_input(
            "At least 8 characters",
            &state.unlock.new_password,
            state.unlock.reveal,
            Message::NewPassword,
            Message::Create,
        ),
        w::vgap(14.0),
        w::micro("Repeat the master password"),
        w::vgap(6.0),
        password_input(
            "Type it again",
            &state.unlock.new_confirm,
            state.unlock.reveal,
            Message::NewConfirm,
            Message::Create,
        ),
        w::vgap(16.0),
        w::micro(format!("Unlock PIN ({PIN_MIN_LEN}–{PIN_MAX_LEN} digits)")),
        w::vgap(6.0),
        row![
            container(password_input(
                "Choose a PIN",
                &state.unlock.new_pin,
                state.unlock.reveal,
                Message::NewPin,
                Message::Create,
            ))
            .width(Length::Fill),
            w::gap(8.0),
            container(password_input(
                "Repeat the PIN",
                &state.unlock.new_pin_confirm,
                state.unlock.reveal,
                Message::NewPinConfirm,
                Message::Create,
            ))
            .width(Length::Fill),
        ]
        .align_y(Alignment::Center)
        .into(),
        w::vgap(6.0),
        w::small(
            "The master password is asked once per desktop login; the PIN unlocks after that. \
             Change or remove it later in Settings → Security.",
        ),
        w::vgap(16.0),
        w::micro("Key derivation"),
        w::vgap(6.0),
    ];

    let current = if state.unlock.kdf.is_empty() {
        "interactive"
    } else {
        state.unlock.kdf.as_str()
    };
    let mut segments: Vec<Element<'_, Message>> = Vec::new();
    for preset in KdfPreset::ALL {
        let key = match preset {
            KdfPreset::Interactive => "interactive",
            KdfPreset::Moderate => "moderate",
            KdfPreset::Paranoid => "paranoid",
        };
        segments.push(w::segment(preset.label(), current == key, Message::Kdf(key.into())).into());
    }
    body.push(row(segments).spacing(6).into());
    body.push(w::vgap(6.0));
    body.push(w::small(
        "A slower derivation is harder to brute-force. Interactive unlocks in a blink; \
         Paranoid is for patient, high-value vaults.",
    ));

    if let Some(banner) = error_banner(state.unlock.error.as_ref()) {
        body.push(w::vgap(12.0));
        body.push(banner);
    }

    body.push(w::vgap(20.0));
    body.push(
        container(w::primary_button("Create vault", Message::Create).width(Length::Fill))
            .width(Length::Fill)
            .into(),
    );
    body.push(w::vgap(10.0));
    body.push(
        container(
            iced::widget::button(
                row![
                    glyph::icon(Glyph::ChevronRight, 14.0),
                    w::gap(6.0),
                    w::body("I already have a vault"),
                ]
                .align_y(Alignment::Center),
            )
            .padding([6, 10])
            .style(theme::bare)
            .on_press(Message::ShowUnlock),
        )
        .width(Length::Fill)
        .center_x(Length::Fill)
        .into(),
    );

    card(column(body).into())
}
