//! The quick assistant: a small generator that pops up from the tray, much like
//! the Enpass assistant.
//!
//! It needs no vault, so it is usable while the vault is locked. When the main
//! window is hidden to the tray it takes the window over and shows just itself,
//! compact and always-on-top; when the main window is open it floats above it.
//!
//! History is deliberately **in memory only**: generated secrets are never
//! written to disk in the clear.

use std::collections::VecDeque;

use aurapass_core::generator::{self, PasswordPolicy};
use chrono::{DateTime, Local};
use iced::widget::{column, container, row};
use iced::{Alignment, Element, Length, Task, Theme};

use crate::app::{AppState, Message as AppMessage};
use crate::glyph::{self, Glyph};
use crate::theme::{self, Tokens};
use crate::widgets as w;

/// How many generations are remembered.
const HISTORY: usize = 12;

/// Which kind of secret the assistant is making.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A random password.
    Password,
    /// A diceware-style passphrase.
    Passphrase,
    /// A numeric PIN.
    Pin,
}

impl Mode {
    /// Display label.
    fn label(self) -> &'static str {
        match self {
            Mode::Password => "Password",
            Mode::Passphrase => "Passphrase",
            Mode::Pin => "PIN",
        }
    }
}

/// One remembered generation.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The generated secret.
    pub value: String,
    /// Entropy in bits.
    pub entropy: f64,
    /// `password`, `passphrase` or `pin`.
    pub kind: &'static str,
    /// When it was generated.
    pub at: DateTime<Local>,
}

/// Everything the assistant shows and edits.
#[derive(Debug, Clone)]
pub struct AssistantState {
    /// The generator policy, shared with the vault's preference.
    pub policy: PasswordPolicy,
    /// Which kind of secret.
    pub mode: Mode,
    /// The current generation.
    pub preview: String,
    /// Its entropy, in bits.
    pub entropy: f64,
    /// Passphrase word count.
    pub words: usize,
    /// Passphrase separator.
    pub separator: String,
    /// Append a digit to passphrases.
    pub append_number: bool,
    /// PIN length.
    pub pin_length: usize,
    /// Recent generations, newest first. Memory only.
    pub history: VecDeque<Entry>,
    /// Whether history values are shown in the clear.
    pub reveal: bool,
    /// What the user is looking for in the vault.
    pub search: String,
}

impl Default for AssistantState {
    fn default() -> Self {
        let mut state = Self {
            policy: PasswordPolicy::default(),
            mode: Mode::Password,
            preview: String::new(),
            entropy: 0.0,
            words: 4,
            separator: "-".into(),
            append_number: true,
            pin_length: 6,
            history: VecDeque::new(),
            reveal: false,
            search: String::new(),
        };
        state.regenerate();
        state
    }
}

impl AssistantState {
    /// Adopt the vault's stored generator policy.
    pub fn use_policy(&mut self, policy: &PasswordPolicy) {
        self.policy = policy.clone();
        self.regenerate();
    }

    /// Produce a new secret and remember it.
    pub fn regenerate(&mut self) {
        let (value, kind) = match self.mode {
            Mode::Password => (generator::generate_password(&self.policy), "password"),
            Mode::Passphrase => (
                generator::generate_passphrase(
                    self.words,
                    &self.separator,
                    true,
                    self.append_number,
                ),
                "passphrase",
            ),
            Mode::Pin => (generator::generate_pin(self.pin_length), "pin"),
        };

        let (value, entropy) = match value {
            Ok(value) => {
                let entropy = match self.mode {
                    Mode::Password => {
                        aurapass_core::strength::evaluate(&value, &[]).log10_guesses * 10f64.log2()
                    }
                    Mode::Passphrase => {
                        generator::passphrase_entropy_bits(self.words, self.append_number)
                    }
                    Mode::Pin => self.pin_length as f64 * 10f64.log2(),
                };
                (value, entropy)
            }
            Err(e) => (format!("({e})"), 0.0),
        };

        self.preview = value.clone();
        self.entropy = entropy;
        if self.preview.starts_with('(') {
            return;
        }
        self.history.push_front(Entry {
            value,
            entropy,
            kind,
            at: Local::now(),
        });
        while self.history.len() > HISTORY {
            self.history.pop_back();
        }
    }
}

/// Messages from the assistant.
#[derive(Debug, Clone)]
pub enum Message {
    /// Which kind of secret to make.
    Mode(Mode),
    /// Password length changed.
    Length(usize),
    /// Toggle lowercase letters.
    Lowercase(bool),
    /// Toggle uppercase letters.
    Uppercase(bool),
    /// Toggle digits.
    Digits(bool),
    /// Toggle symbols.
    Symbols(bool),
    /// Toggle dropping look-alike characters.
    ExcludeAmbiguous(bool),
    /// Passphrase word count changed.
    Words(usize),
    /// Passphrase separator changed.
    Separator(String),
    /// Toggle the trailing digit on passphrases.
    AppendNumber(bool),
    /// PIN length changed.
    PinLength(usize),
    /// Make a new secret.
    Regenerate,
    /// Copy the current secret.
    Copy,
    /// Copy a history entry.
    CopyEntry(usize),
    /// Show or hide the history.
    Reveal,
    /// Forget the history.
    Clear,
    /// Close the generator modal (without touching the assistant panel).
    CloseModal,
    /// Paste the preview into the item being edited.
    UseForItem,
    /// Open the full window.
    ShowMain,
    /// The search field changed.
    Search(String),
    /// Clear the search field.
    ClearSearch,
    /// Copy the password of a search result.
    CopyResult(uuid::Uuid),
}

/// Handle a message from the assistant.
pub fn update(state: &mut AppState, message: Message) -> Task<AppMessage> {
    let assistant = &mut state.assistant;
    match message {
        Message::Mode(mode) => {
            assistant.mode = mode;
            assistant.regenerate();
        }
        Message::Length(n) => {
            assistant.policy.length = n.clamp(6, 128);
            assistant.regenerate();
        }
        Message::Lowercase(v) => {
            assistant.policy.lowercase = v;
            assistant.regenerate();
        }
        Message::Uppercase(v) => {
            assistant.policy.uppercase = v;
            assistant.regenerate();
        }
        Message::Digits(v) => {
            assistant.policy.digits = v;
            assistant.regenerate();
        }
        Message::Symbols(v) => {
            assistant.policy.symbols = v;
            assistant.regenerate();
        }
        Message::ExcludeAmbiguous(v) => {
            assistant.policy.exclude_ambiguous = v;
            assistant.regenerate();
        }
        Message::Words(n) => {
            assistant.words = n.clamp(3, 12);
            assistant.regenerate();
        }
        Message::Separator(v) => {
            assistant.separator = if v.is_empty() { "-".into() } else { v };
            assistant.regenerate();
        }
        Message::AppendNumber(v) => {
            assistant.append_number = v;
            assistant.regenerate();
        }
        Message::PinLength(n) => {
            assistant.pin_length = n.clamp(4, 16);
            assistant.regenerate();
        }
        Message::Regenerate => assistant.regenerate(),
        Message::Copy => {
            let value = assistant.preview.clone();
            return state.copy("Password", value);
        }
        Message::CopyEntry(index) => {
            if let Some(entry) = assistant.history.iter().nth(index) {
                let value = entry.value.clone();
                return state.copy("Password", value);
            }
        }
        Message::Reveal => assistant.reveal = !assistant.reveal,
        Message::Clear => {
            assistant.history.clear();
            state.notify("Generation history cleared");
        }
        Message::CloseModal => state.tools.open = None,
        Message::UseForItem => {
            let value = state.assistant.preview.clone();
            match state.editor.as_mut() {
                Some(editor) => {
                    editor.draft.password = Some(value);
                    editor.reveal = true;
                    state.tools.open = None;
                    state.notify("Password inserted into the item");
                }
                None => state.notify_error("No item is open"),
            }
        }
        Message::ShowMain => return state.focus_main(),
        Message::Search(v) => assistant.search = v,
        Message::ClearSearch => assistant.search.clear(),
        Message::CopyResult(id) => {
            let password = state
                .vault
                .as_ref()
                .and_then(|v| v.item(id))
                .and_then(|i| i.password().map(str::to_string));
            match password {
                Some(password) => return state.copy("Password", password),
                None => return Task::none(),
            }
        }
    }
    Task::none()
}

/// Draw the assistant.
pub fn view(state: &AppState) -> Element<'_, Message> {
    let assistant = &state.assistant;
    let searching = !assistant.search.trim().is_empty();

    let body: Element<'_, Message> = if searching {
        search_results(state).into()
    } else {
        column![
            preview_card(assistant),
            w::vgap(8.0),
            options(assistant),
            w::vgap(8.0),
            row![
                w::primary_icon_button(Glyph::Copy, "Copy", Message::Copy),
                w::secondary_icon_button(Glyph::Sparkle, "New", Message::Regenerate),
                w::grow(),
                w::secondary_button("Open AuraPass", Message::ShowMain),
            ]
            .spacing(8)
            .width(Length::Fill)
            .align_y(Alignment::Center),
            w::vgap(7.0),
            w::hline(),
            w::vgap(6.0),
            history(assistant),
        ]
        .width(Length::Fill)
        .into()
    };

    container(
        column![
            search_field(assistant),
            w::vgap(8.0),
            body,
        ]
        .width(Length::Fill)
        .height(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .padding(14)
    .into()
}

/// The search box at the top of the panel.
fn search_field<'a>(assistant: &'a AssistantState) -> Element<'a, Message> {
    let mut row_items: Vec<Element<'a, Message>> = vec![
        iced::widget::text_input("Search logins and websites", &assistant.search)
            .on_input(Message::Search)
            .padding([8, 10])
            .size(theme::T_BODY)
            .font(theme::REG)
            .style(theme::input)
            .into(),
    ];
    if !assistant.search.is_empty() {
        row_items.push(w::icon_button(Glyph::Close, 13.0, Some(Message::ClearSearch)).into());
    }
    row(row_items)
        .spacing(4)
        .align_y(Alignment::Center)
        .width(Length::Fill)
        .into()
}

/// Matching logins, one click to copy the password.
fn search_results(state: &AppState) -> Element<'_, Message> {
    let Some(vault) = state.vault.as_ref() else {
        return w::empty_state(
            Glyph::Key,
            "No vault is open",
            "Unlock AuraPass on the desktop to search it.",
        );
    };
    let query = state.assistant.search.trim().to_string();
    let ids = vault.query(&aurapass_core::vault::VaultQuery {
        text: query,
        ..Default::default()
    });

    if ids.is_empty() {
        return w::empty_state(
            Glyph::Search,
            "Nothing matched",
            "Try a different word, or clear the search.",
        );
    }

    let mut list = column![].spacing(2);
    for id in ids.into_iter().take(8) {
        let Some(item) = vault.item(id) else {
            continue;
        };
        let title = if item.title.trim().is_empty() {
            "Untitled".to_string()
        } else {
            item.title.clone()
        };
        let subtitle = item
            .username
            .clone()
            .filter(|u| !u.trim().is_empty())
            .or_else(|| item.urls.first().cloned())
            .unwrap_or_else(|| item.kind.label().to_string());
        let tile = glyph::tinted(Glyph::of_kind(item.kind), 15.0, theme::muted);
        list = list.push(
            iced::widget::button(
                row![
                    tile,
                    w::gap(9.0),
                    column![
                        w::strong(title),
                        w::small(subtitle),
                    ]
                    .width(Length::Fill),
                    glyph::icon(Glyph::Copy, 13.0),
                ]
                .align_y(Alignment::Center)
                .width(Length::Fill),
            )
            .width(Length::Fill)
            .padding([7, 8])
            .style(|t: &Theme, s| theme::row(t, s, false))
            .on_press(Message::CopyResult(id)),
        );
    }

    w::scroller(list.width(Length::Fill)).height(Length::Fill).into()
}

/// The generator, as a modal over the browser window.
///
/// The assistant owns the generator's state, so this is the same generator
/// under a different hat — no second set of options to keep in sync.
pub fn generator_modal(state: &AppState) -> Element<'_, Message> {
    let assistant = &state.assistant;

    let mut footer: Vec<Element<'_, Message>> = vec![
        w::primary_icon_button(Glyph::Copy, "Copy", Message::Copy).into(),
        w::secondary_icon_button(Glyph::Sparkle, "Generate", Message::Regenerate).into(),
    ];
    if state.editor.is_some() {
        footer.push(
            w::secondary_icon_button(Glyph::ChevronRight, "Use for the open item", Message::UseForItem)
                .into(),
        );
    }
    footer.push(w::grow());
    footer.push(w::secondary_button("Close", Message::CloseModal).into());

    let head: Element<'_, Message> = row![
        glyph::tinted(Glyph::Sparkle, 18.0, theme::accent),
        w::gap(10.0),
        column![
            w::title("Password generator"),
            w::small("Values are generated here and kept in memory only"),
        ]
        .width(Length::Fill),
        w::icon_button(Glyph::Close, 15.0, Some(Message::CloseModal)),
    ]
    .align_y(Alignment::Center)
    .into();

    w::dialog(
        520.0,
        head,
        vec![preview_card(assistant), options(assistant)],
        footer,
        false,
    )
}

/// The big generated value.
fn preview_card<'a>(assistant: &AssistantState) -> Element<'a, Message> {
    let shown = if assistant.reveal {
        assistant.preview.clone()
    } else {
        theme::mask(&assistant.preview, false)
    };
    let bits = assistant.entropy;
    let verdict = if bits >= 128.0 {
        "excellent"
    } else if bits >= 80.0 {
        "strong"
    } else if bits >= 50.0 {
        "fair"
    } else {
        "weak"
    };

    container(
        column![
            iced::widget::text(shown)
                .size(16.0)
                .font(theme::MED)
                .style(|t: &Theme| iced::widget::text::Style {
                    color: Some(Tokens::of(t).text),
                }),
            w::vgap(5.0),
            row![
                w::small(format!("{bits:.0} bits of entropy")),
                w::gap(6.0),
                w::chip(verdict, theme::ok),
                w::grow(),
                w::icon_button(
                    if assistant.reveal {
                        Glyph::EyeOff
                    } else {
                        Glyph::Eye
                    },
                    14.0,
                    Some(Message::Reveal)
                ),
            ]
            .align_y(Alignment::Center),
        ]
        .width(Length::Fill),
    )
    .width(Length::Fill)
    .padding(10)
    .style(theme::well)
    .into()
}

/// The mode switch and per-mode knobs.
///
/// The assistant is a fixed 400x450 panel, so the character classes are
/// compact toggle chips instead of a five-line checkbox list.
fn options<'a>(assistant: &AssistantState) -> Element<'a, Message> {
    let mut body: Vec<Element<'a, Message>> = Vec::new();

    let mut modes: Vec<Element<'a, Message>> = Vec::new();
    for mode in [Mode::Password, Mode::Passphrase, Mode::Pin] {
        modes.push(w::segment(mode.label(), assistant.mode == mode, Message::Mode(mode)).into());
    }
    body.push(row(modes).spacing(6).into());
    body.push(w::vgap(8.0));

    match assistant.mode {
        Mode::Password => {
            body.push(
                row![
                    w::micro("Length"),
                    w::grow(),
                    stepper(assistant.policy.length, 6, 64, Message::Length),
                ]
                .width(Length::Fill)
                .align_y(Alignment::Center)
                .into(),
            );
            body.push(w::vgap(6.0));
            body.push(w::micro("Characters"));
            body.push(w::vgap(4.0));
            body.push(
                row![
                    w::segment(
                        "a–z",
                        assistant.policy.lowercase,
                        Message::Lowercase(!assistant.policy.lowercase),
                    ),
                    w::segment(
                        "A–Z",
                        assistant.policy.uppercase,
                        Message::Uppercase(!assistant.policy.uppercase),
                    ),
                    w::segment(
                        "0–9",
                        assistant.policy.digits,
                        Message::Digits(!assistant.policy.digits),
                    ),
                    w::segment(
                        "!@#",
                        assistant.policy.symbols,
                        Message::Symbols(!assistant.policy.symbols),
                    ),
                    w::segment(
                        "No 0/O",
                        assistant.policy.exclude_ambiguous,
                        Message::ExcludeAmbiguous(!assistant.policy.exclude_ambiguous),
                    ),
                ]
                .spacing(5)
                .width(Length::Fill)
                .into(),
            );
        }
        Mode::Passphrase => {
            body.push(
                row![
                    w::micro("Words"),
                    w::grow(),
                    stepper(assistant.words, 3, 12, Message::Words),
                ]
                .width(Length::Fill)
                .align_y(Alignment::Center)
                .into(),
            );
            body.push(w::vgap(6.0));
            body.push(
                row![
                    w::micro("Separator"),
                    w::grow(),
                    iced::widget::text_input("-", &assistant.separator)
                        .on_input(Message::Separator)
                        .padding([6, 10])
                        .size(theme::T_BODY)
                        .font(theme::REG)
                        .style(theme::input)
                        .width(Length::Fixed(80.0)),
                ]
                .width(Length::Fill)
                .align_y(Alignment::Center)
                .into(),
            );
            body.push(w::vgap(6.0));
            body.push(
                row![
                    w::segment(
                        "Append a digit",
                        assistant.append_number,
                        Message::AppendNumber(!assistant.append_number),
                    ),
                ]
                .width(Length::Fill)
                .into(),
            );
        }
        Mode::Pin => {
            body.push(
                row![
                    w::micro("Digits"),
                    w::grow(),
                    stepper(assistant.pin_length, 4, 16, Message::PinLength),
                ]
                .width(Length::Fill)
                .align_y(Alignment::Center)
                .into(),
            );
        }
    }

    column(body).width(Length::Fill).into()
}

/// A minus / value / plus stepper.
fn stepper<'a>(
    value: usize,
    min: usize,
    max: usize,
    message: fn(usize) -> Message,
) -> Element<'a, Message> {
    row![
        w::icon_button(
            Glyph::Minus,
            14.0,
            (value > min).then(|| message(value.saturating_sub(1)))
        ),
        container(w::strong(value.to_string()))
            .width(Length::Fixed(44.0))
            .center_x(Length::Fixed(44.0)),
        w::icon_button(
            Glyph::Plus,
            14.0,
            (value < max).then(|| message(value + 1))
        ),
    ]
    .spacing(4)
    .align_y(Alignment::Center)
    .into()
}

/// The in-memory history.
fn history<'a>(assistant: &AssistantState) -> Element<'a, Message> {
    let mut kids: Vec<Element<'a, Message>> = vec![
        w::micro("Recent generations"),
        w::grow(),
        w::icon_button(Glyph::Trash, 13.0, Some(Message::Clear)).into(),
    ];
    let heading = row(kids.drain(..).collect::<Vec<_>>())
        .align_y(Alignment::Center);

    if assistant.history.is_empty() {
        return column![heading, w::vgap(5.0), w::small("Nothing generated yet.")]
            .width(Length::Fill)
            .height(Length::Fill)
            .into();
    }

    let mut list: iced::widget::Column<'a, Message> = column![].spacing(3);
    for (index, entry) in assistant.history.iter().enumerate() {
        let shown = if assistant.reveal {
            entry.value.clone()
        } else {
            theme::mask(&entry.value, false)
        };
        list = list.push(
            row![
                container(
                    iced::widget::button(
                        row![
                            column![
                                iced::widget::text(shown)
                                    .size(theme::T_BODY)
                                    .font(theme::REG)
                                    .style(|t: &Theme| iced::widget::text::Style {
                                        color: Some(Tokens::of(t).text),
                                    }),
                                w::small(format!(
                                    "{} · {:.0} bits · {}",
                                    entry.kind,
                                    entry.entropy,
                                    entry.at.format("%H:%M")
                                )),
                            ]
                            .width(Length::Fill),
                        ]
                        .width(Length::Fill),
                    )
                    .width(Length::Fill)
                    .padding([6, 8])
                    .style(theme::row_plain)
                    .on_press(Message::CopyEntry(index)),
                )
                .width(Length::Fill),
            ]
            .align_y(Alignment::Center),
        );
    }

    column![
        heading,
        w::vgap(5.0),
        w::scroller(list)
            .width(Length::Fill)
            .height(Length::Fill),
    ]
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}
