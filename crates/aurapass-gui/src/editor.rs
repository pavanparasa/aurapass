//! The add / edit item dialog.

use aurapass_core::generator;
use aurapass_core::model::{Field, Item, ItemKind};
use aurapass_core::vault::PASSWORD_HISTORY_LIMIT;
use iced::widget::{column, container, row, text, text_editor, text_input};
use iced::{Alignment, Element, Length, Task, Theme};
use uuid::Uuid;

use crate::app::{AppState, Message as AppMessage};
use crate::glyph::{self, Glyph};
use crate::theme::{self, Tokens};
use crate::widgets as w;

/// The item being edited.
#[derive(Debug, Clone)]
pub struct EditorState {
    /// The item's id, when it already exists.
    pub id: Option<Uuid>,
    /// The working copy.
    pub draft: Item,
    /// Whether this is a brand-new item.
    pub is_new: bool,
    /// Whether the password is shown in the clear.
    pub reveal: bool,
    /// The websites field, comma separated.
    pub urls_text: String,
    /// The tags field, comma separated.
    pub tags_text: String,
    /// The notes, as an editable buffer.
    pub notes: text_editor::Content,
    /// The last error.
    pub error: Option<String>,
}

impl EditorState {
    /// Start a brand-new item of the given kind.
    pub fn new(kind: ItemKind) -> Self {
        Self {
            id: None,
            draft: Item::new(kind, ""),
            is_new: true,
            reveal: true,
            urls_text: String::new(),
            tags_text: String::new(),
            notes: text_editor::Content::new(),
            error: None,
        }
    }

    /// Start editing an existing item.
    pub fn from_item(item: &Item) -> Self {
        Self {
            id: Some(item.id),
            draft: item.clone(),
            is_new: false,
            reveal: false,
            urls_text: item.urls.join(", "),
            tags_text: item.tags.join(", "),
            notes: text_editor::Content::with_text(&item.notes),
            error: None,
        }
    }
}

/// Messages from the editor.
#[derive(Debug, Clone)]
pub enum Message {
    /// The title changed.
    Title(String),
    /// The username changed.
    Username(String),
    /// The password changed.
    Password(String),
    /// The one-time-code secret changed.
    Totp(String),
    /// The websites changed.
    Urls(String),
    /// The notes changed.
    Notes(text_editor::Action),
    /// The tags changed.
    Tags(String),
    /// The kind changed.
    Kind(ItemKind),
    /// The category changed.
    Category(Option<Uuid>),
    /// Show or hide the password.
    Reveal,
    /// Fill the password field from the generator.
    Generate,
    /// A custom field's label changed.
    FieldLabel(usize, String),
    /// A custom field's value changed.
    FieldValue(usize, String),
    /// A custom field's sensitivity changed.
    FieldSensitive(usize, bool),
    /// Add a custom field.
    AddField,
    /// Remove a custom field.
    RemoveField(usize),
    /// Toggle the favourite flag.
    Favorite,
    /// Save the item.
    Save,
    /// Discard the draft.
    Cancel,
}

/// Handle a message from the editor.
pub fn update(state: &mut AppState, message: Message) -> Task<AppMessage> {
    // Actions that need the vault come first.
    match message {
        Message::Save => {
            let Some(editor) = state.editor.take() else {
                return Task::none();
            };
            match save(state, &editor) {
                Ok(title) => {
                    state.notify(format!("Saved “{title}”"));
                }
                Err(e) => {
                    let mut editor = editor;
                    editor.error = Some(e);
                    state.editor = Some(editor);
                }
            }
            return Task::none();
        }
        Message::Cancel => {
            state.editor = None;
            return Task::none();
        }
        _ => {}
    }

    let Some(editor) = state.editor.as_mut() else {
        return Task::none();
    };
    let draft = &mut editor.draft;

    match message {
        Message::Title(v) => draft.title = v,
        Message::Username(v) => draft.username = non_empty(v),
        Message::Password(v) => draft.password = non_empty(v),
        Message::Totp(v) => draft.totp = non_empty(v),
        Message::Notes(action) => editor.notes.perform(action),
        Message::Urls(v) => {
            draft.urls = split_list(&v);
            editor.urls_text = v;
        }
        Message::Tags(v) => {
            draft.tags = split_list(&v);
            editor.tags_text = v;
        }
        Message::Kind(kind) => draft.kind = kind,
        Message::Category(category) => draft.category = category,
        Message::Reveal => editor.reveal = !editor.reveal,
        Message::Favorite => draft.favorite = !draft.favorite,
        Message::Generate => {
            let policy = state.assistant.policy.clone();
            match generator::generate_password(&policy) {
                Ok(password) => {
                    draft.password = Some(password);
                    editor.reveal = true;
                }
                Err(e) => editor.error = Some(e.to_string()),
            }
        }
        Message::FieldLabel(index, label) => {
            if let Some(field) = editor.draft.fields.get_mut(index) {
                field.label = label;
            }
        }
        Message::FieldValue(index, value) => {
            if let Some(field) = editor.draft.fields.get_mut(index) {
                field.value = value;
            }
        }
        Message::FieldSensitive(index, sensitive) => {
            if let Some(field) = editor.draft.fields.get_mut(index) {
                field.sensitive = sensitive;
            }
        }
        Message::AddField => editor.draft.fields.push(Field::new("", "")),
        Message::RemoveField(index) => {
            if index < editor.draft.fields.len() {
                editor.draft.fields.remove(index);
            }
        }
        Message::Save | Message::Cancel => unreachable!("handled above"),
    }
    Task::none()
}

/// Trim a string, treating blank as "no value".
fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Split a comma- or newline-separated list into trimmed entries.
fn split_list(value: &str) -> Vec<String> {
    value
        .split([',', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Copy the editable fields of a draft onto a stored item.
fn copy_fields(item: &mut Item, draft: &Item) {
    item.kind = draft.kind;
    item.title = draft.title.trim().to_string();
    item.subtitle = draft.subtitle.clone();
    item.username = draft.username.clone();
    item.totp = draft.totp.clone();
    item.urls = draft.urls.clone();
    item.notes = draft.notes.clone();
    item.category = draft.category;
    item.tags = draft.tags.clone();
    item.favorite = draft.favorite;
    item.expires_at = draft.expires_at;
    item.fields = draft.fields.clone();
}

/// Write the draft into the vault and save it.
fn save(state: &mut AppState, editor: &EditorState) -> Result<String, String> {
    let mut draft = editor.draft.clone();
    draft.notes = editor.notes.text();
    let draft = &draft;
    if draft.title.trim().is_empty() {
        return Err("Give the item a title first.".into());
    }
    let Some(vault) = state.vault.as_mut() else {
        return Err("The vault is locked.".into());
    };

    match editor.id {
        Some(id) => {
            let Some(item) = vault.item_mut(id) else {
                return Err("That item no longer exists.".into());
            };
            let password_changed = item.password != draft.password;
            copy_fields(item, draft);
            if password_changed {
                match draft.password.clone() {
                    Some(password) => item.set_password(password, PASSWORD_HISTORY_LIMIT),
                    None => item.password = None,
                }
            }
            item.touch();
        }
        None => {
            let id = vault.create_item(draft.kind, draft.title.trim());
            if let Some(item) = vault.item_mut(id) {
                copy_fields(item, draft);
                if let Some(password) = draft.password.clone() {
                    item.set_password(password, PASSWORD_HISTORY_LIMIT);
                }
                item.touch();
            }
        }
    }
    vault.mark_dirty();
    vault.save().map_err(|e| e.to_string())?;
    Ok(draft.title.trim().to_string())
}

// --------------------------------------------------------------------- view

/// Draw the editor.
pub fn view<'a>(state: &'a AppState, editor: &'a EditorState) -> Element<'a, Message> {
    let draft = &editor.draft;
    let mut body: Vec<Element<'_, Message>> = Vec::new();

    // ---- header
    let head: Element<'_, Message> = row![
        w::kind_tile(draft.kind, 40.0),
        w::gap(11.0),
        column![
            w::title(if editor.is_new {
                "New item".to_string()
            } else {
                "Edit item".to_string()
            }),
            w::small(draft.kind.label()),
        ]
        .width(Length::Fill),
        w::icon_button(Glyph::Close, 15.0, Some(Message::Cancel)),
    ]
    .width(Length::Fill)
    .align_y(Alignment::Center)
    .into();

    // ---- kind picker
    body.push(w::micro("Type"));
    body.push(w::vgap(6.0));
    let mut kinds: Vec<Element<'_, Message>> = Vec::new();
    for kind in ItemKind::ALL {
        let active = draft.kind == kind;
        kinds.push(
            iced::widget::button(
                row![
                    glyph::tinted(
                        Glyph::of_kind(kind),
                        14.0,
                        if active { theme::on_accent } else { theme::muted }
                    ),
                    w::gap(6.0),
                    // No explicit colour: the chip's own style decides, so the
                    // label turns white when the chip is the selected one.
                    text(kind.label())
                        .size(theme::T_SMALL)
                        .font(theme::REG),
                ]
                .align_y(Alignment::Center),
            )
            .padding([5, 9])
            .style(move |t: &Theme, s| theme::chip_button(t, s, active))
            .on_press(Message::Kind(kind))
            .into(),
        );
    }
    body.push(row(kinds).spacing(5).wrap().into());
    body.push(w::vgap(14.0));

    // ---- title / username / password
    body.push(w::micro("Title"));
    body.push(w::vgap(6.0));
    body.push(field("Name this item", &draft.title, Message::Title));

    body.push(w::vgap(12.0));
    body.push(w::micro("Username or e-mail"));
    body.push(w::vgap(6.0));
    body.push(field(
        "name@example.com",
        draft.username.as_deref().unwrap_or(""),
        Message::Username,
    ));

    body.push(w::vgap(12.0));
    body.push(w::micro("Password"));
    body.push(w::vgap(6.0));
    let password = draft.password.clone().unwrap_or_default();
    body.push(
        row![
            text_input("The secret", &password)
                .on_input(Message::Password)
                .secure(!editor.reveal)
                .padding([9, 11])
                .size(theme::T_BODY)
                .font(theme::REG)
                .style(theme::input),
            w::icon_button(
                if editor.reveal { Glyph::EyeOff } else { Glyph::Eye },
                16.0,
                Some(Message::Reveal)
            ),
            w::icon_button(Glyph::Sparkle, 16.0, Some(Message::Generate)),
        ]
        .spacing(6)
        .align_y(Alignment::Center)
        .into(),
    );
    if let Some(strength) = draft.strength() {
        body.push(w::vgap(6.0));
        body.push(
            row![
                w::strength_bar(strength.score, 120.0),
                w::gap(8.0),
                w::small(format!("{} · {}", strength.label, strength.crack_time)),
            ]
            .align_y(Alignment::Center)
            .into(),
        );
    }

    body.push(w::vgap(12.0));
    body.push(w::micro("One-time code (TOTP secret or otpauth:// link)"));
    body.push(w::vgap(6.0));
    body.push(field(
        "JBSWY3DPEHPK3PXP",
        draft.totp.as_deref().unwrap_or(""),
        Message::Totp,
    ));

    // ---- category
    if let Some(vault) = state.vault.as_ref() {
        let categories = vault.data().categories.clone();
        if !categories.is_empty() {
            body.push(w::vgap(12.0));
            body.push(w::micro("Category"));
            body.push(w::vgap(6.0));
            let mut chips: Vec<Element<'_, Message>> = Vec::new();
            let active = draft.category.is_none();
            let label = |name: &str| {
                text(name.to_string())
                    .size(theme::T_SMALL)
                    .font(theme::REG)
            };
            chips.push(
                iced::widget::button(label("None"))
                    .padding([5, 9])
                    .style(move |t: &Theme, s| theme::chip_button(t, s, active))
                    .on_press(Message::Category(None))
                    .into(),
            );
            for category in categories {
                let is_active = draft.category == Some(category.id);
                let name = category.name.clone();
                chips.push(
                    iced::widget::button(label(&name))
                        .padding([5, 9])
                        .style(move |t: &Theme, s| theme::chip_button(t, s, is_active))
                        .on_press(Message::Category(Some(category.id)))
                        .into(),
                );
            }
            body.push(row(chips).spacing(5).wrap().into());
        }
    }

    // ---- websites / tags
    body.push(w::vgap(12.0));
    body.push(w::micro("Websites (comma separated)"));
    body.push(w::vgap(6.0));
    body.push(field(
        "https://example.com, https://example.org",
        &editor.urls_text,
        Message::Urls,
    ));

    body.push(w::vgap(12.0));
    body.push(w::micro("Tags (comma separated)"));
    body.push(w::vgap(6.0));
    body.push(field("work, personal", &editor.tags_text, Message::Tags));

    // ---- notes
    body.push(w::vgap(12.0));
    body.push(w::micro("Notes"));
    body.push(w::vgap(6.0));
    body.push(
        container(
            text_editor(&editor.notes)
                .placeholder("Anything worth remembering")
                .on_action(Message::Notes)
                .padding(10)
                .size(theme::T_BODY)
                .font(theme::REG)
                .height(Length::Fixed(96.0)),
        )
        .width(Length::Fill)
        .style(theme::well)
        .into(),
    );

    // ---- custom fields
    body.push(w::vgap(12.0));
    let mut heading: Vec<Element<'_, Message>> = vec![w::micro("Fields"), w::grow()];
    heading.push(
        iced::widget::button(
            row![glyph::icon(Glyph::Plus, 13.0), w::gap(5.0), w::small("Add")].align_y(
                Alignment::Center,
            ),
        )
        .padding([4, 8])
        .style(theme::bare)
        .on_press(Message::AddField)
        .into(),
    );
    body.push(row(heading).align_y(Alignment::Center).into());
    for (index, field) in draft.fields.iter().enumerate() {
        body.push(w::vgap(6.0));
        body.push(
            row![
                text_input("Label", &field.label)
                    .on_input(move |v| Message::FieldLabel(index, v))
                    .padding([8, 10])
                    .size(theme::T_BODY)
                    .font(theme::REG)
                    .style(theme::input)
                    .width(Length::Fixed(150.0)),
                text_input("Value", &field.value)
                    .on_input(move |v| Message::FieldValue(index, v))
                    .secure(field.sensitive && !editor.reveal)
                    .padding([8, 10])
                    .size(theme::T_BODY)
                    .font(theme::REG)
                    .style(theme::input),
                iced::widget::checkbox(field.sensitive)
                    .on_toggle(move |v| Message::FieldSensitive(index, v))
                    .size(16.0)
                    .style(theme::checkbox),
                w::icon_button(Glyph::Trash, 14.0, Some(Message::RemoveField(index))),
            ]
            .spacing(6)
            .align_y(Alignment::Center)
            .into(),
        );
    }

    // ---- footer
    if let Some(error) = &editor.error {
        body.push(w::vgap(14.0));
        body.push(
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
        );
    }

    let mut footer: Vec<Element<'_, Message>> = Vec::new();
    footer.push(
        iced::widget::button(
            row![
                glyph::tinted(
                    if draft.favorite { Glyph::Star } else { Glyph::Star },
                    15.0,
                    if draft.favorite { theme::warn } else { theme::muted },
                ),
                w::gap(6.0),
                w::small(if draft.favorite {
                    "Favourite"
                } else {
                    "Mark as favourite"
                }),
            ]
            .align_y(Alignment::Center),
        )
        .padding([6, 10])
        .style(theme::bare)
        .on_press(Message::Favorite)
        .into(),
    );
    footer.push(w::grow());
    footer.push(w::secondary_button("Cancel", Message::Cancel).into());
    footer.push(w::primary_button("Save", Message::Save).into());

    // The header stays put; the fields scroll when the item is a long one.
    w::dialog(660.0, head, body, footer, true)
}

/// A single-line text field.
fn field<'a>(
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
