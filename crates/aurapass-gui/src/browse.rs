//! The unlocked browser: the navigation rail, the item list and the detail pane.

use aurapass_core::model::{Item, ItemKind};
use aurapass_core::totp::Totp;
use aurapass_core::vault::{SortOrder, VaultQuery};
use chrono::{DateTime, Local, Utc};
use iced::widget::{column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Task, Theme};
use uuid::Uuid;

use crate::app::{AppState, ConfirmAction, Message as AppMessage};
use crate::glyph::{self, Glyph};
use crate::theme::{self, Tokens};
use crate::widgets as w;

/// Fixed height of one list row. Virtualising the list keeps a 1,600-item
/// vault as responsive as a ten-item one: only the visible window is built.
const ROW_HEIGHT: f32 = 54.0;
/// Rows drawn above and below the viewport so fast scrolling does not flash.
const OVERSCAN: usize = 6;
/// Used until the scrollable reports its real viewport on the first layout.
const FALLBACK_VIEWPORT: f32 = 760.0;
/// Stable id for scrolling back to the top when a filter changes.
const LIST_ID: &str = "aurapass-item-list";

/// Browser state: which filters are on and which item is selected.
#[derive(Debug, Clone)]
pub struct BrowseState {
    /// Free-text search.
    pub query: String,
    /// Restrict to one kind.
    pub kind: Option<ItemKind>,
    /// Restrict to one category.
    pub category: Option<Uuid>,
    /// Restrict to one tag.
    pub tag: Option<String>,
    /// Only favourites.
    pub favorites_only: bool,
    /// Show the bin instead of the live vault.
    pub bin: bool,
    /// Sort order.
    pub sort: SortOrder,
    /// The selected item.
    pub selected: Option<Uuid>,
    /// Whether the detail pane shows the password in the clear.
    pub reveal: bool,
    /// Last scroll offset reported by the list, in logical pixels.
    pub scroll_y: f32,
    /// Height of the list viewport, reported by the scrollable.
    pub viewport_h: f32,
}

impl Default for BrowseState {
    fn default() -> Self {
        Self {
            query: String::new(),
            kind: None,
            category: None,
            tag: None,
            favorites_only: false,
            bin: false,
            sort: SortOrder::default(),
            selected: None,
            reveal: false,
            scroll_y: 0.0,
            viewport_h: 0.0,
        }
    }
}

impl BrowseState {
    /// Translate the UI filters into a core query.
    pub fn query(&self) -> VaultQuery {
        VaultQuery {
            text: self.query.clone(),
            kinds: self.kind.into_iter().collect(),
            category: self.category,
            tags: self.tag.iter().cloned().collect(),
            favorites_only: self.favorites_only,
            include_trashed: self.bin,
            sort: self.sort,
        }
    }

    /// The heading above the item list.
    pub fn title(&self) -> String {
        if self.bin {
            return "Bin".to_string();
        }
        if let Some(kind) = self.kind {
            return kind.label().to_string();
        }
        if self.favorites_only {
            return "Favourites".to_string();
        }
        "All items".to_string()
    }
}

/// A sort-order option that can be shown in a dropdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortChoice(pub SortOrder);

impl std::fmt::Display for SortChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.label())
    }
}

impl SortChoice {
    /// Every order, in menu order.
    pub const ALL: [SortChoice; 5] = [
        SortChoice(SortOrder::Title),
        SortChoice(SortOrder::Updated),
        SortChoice(SortOrder::Created),
        SortChoice(SortOrder::LastUsed),
        SortChoice(SortOrder::Kind),
    ];
}

/// Messages from the browser.
#[derive(Debug, Clone)]
pub enum Message {
    /// The search box changed.
    Search(String),
    /// Clear the search box.
    ClearSearch,
    /// The sort order changed.
    Sort(SortOrder),
    /// Show everything.
    All,
    /// Filter by kind, or clear the kind filter.
    Kind(Option<ItemKind>),
    /// Filter by category, or clear it.
    Category(Option<Uuid>),
    /// Filter by tag, or clear it.
    Tag(Option<String>),
    /// Show only favourites.
    Favorites,
    /// Show the bin.
    Bin,
    /// The list viewport scrolled.
    Scrolled {
        /// Absolute vertical offset.
        offset: f32,
        /// Height of the visible list.
        viewport: f32,
    },
    /// Select an item.
    Select(Uuid),
    /// Reveal or hide the selected item's password.
    Reveal,
    /// Copy the selected item's password.
    CopyPassword(Uuid),
    /// Copy the selected item's username.
    CopyUsername(Uuid),
    /// Copy the selected item's one-time code.
    CopyTotp(Uuid),
    /// Copy an arbitrary labelled value.
    Copy {
        /// What it is.
        label: String,
        /// The value.
        value: String,
    },
    /// Open a URL.
    OpenUrl(String),
    /// Edit an item.
    Edit(Uuid),
    /// Duplicate an item.
    Duplicate(Uuid),
    /// Move an item to the bin.
    Trash(Uuid),
    /// Restore an item from the bin.
    Restore(Uuid),
    /// Toggle an item's favourite flag.
    Favorite(Uuid),
    /// Open the "new item" picker.
    NewItem,
    /// Open the category manager.
    Categories,
    /// Permanently delete everything in the bin.
    EmptyBin,
}

/// A denormalised row, so the list can be drawn from a single pass.
struct Row {
    id: Uuid,
    title: String,
    subtitle: String,
    kind: ItemKind,
    favorite: bool,
    has_totp: bool,
    score: Option<u8>,
    updated: String,
}

/// Format a timestamp for a list row.
fn short_date(at: DateTime<Utc>) -> String {
    let local = at.with_timezone(&Local);
    let today = Local::now().date_naive();
    if local.date_naive() == today {
        local.format("%H:%M").to_string()
    } else {
        local.format("%e %b").to_string()
    }
}

/// Format a timestamp in full.
fn long_date(at: DateTime<Utc>) -> String {
    at.with_timezone(&Local).format("%e %b %Y, %H:%M").to_string()
}

/// Build one row. Only the visible rows are ever built.
fn row_for(item: &Item) -> Row {
    Row {
        id: item.id,
        title: if item.title.trim().is_empty() {
            "Untitled".to_string()
        } else {
            item.title.clone()
        },
        subtitle: item
            .username
            .clone()
            .filter(|u| !u.trim().is_empty())
            .or_else(|| item.primary_url().map(str::to_string))
            .unwrap_or_default(),
        kind: item.kind,
        favorite: item.favorite,
        has_totp: item.totp.is_some(),
        // A cheap length/class estimate keeps the warning badge without
        // running zxcvbn over every item on every frame. The detail pane still
        // shows the full zxcvbn score for the selected item.
        score: item.password().map(aurapass_core::strength::quick_score),
        updated: short_date(item.updated_at),
    }
}

/// Handle a message from the browser.
pub fn update(state: &mut AppState, message: Message) -> Task<AppMessage> {
    let reset_scroll = matches!(
        &message,
        Message::Search(_)
            | Message::ClearSearch
            | Message::Sort(_)
            | Message::All
            | Message::Kind(_)
            | Message::Category(_)
            | Message::Tag(_)
            | Message::Favorites
            | Message::Bin
    );
    match message {
        Message::Scrolled { offset, viewport } => {
            state.browse.scroll_y = offset;
            state.browse.viewport_h = viewport;
        }
        Message::Search(text) => state.browse.query = text,
        Message::ClearSearch => state.browse.query.clear(),
        Message::Sort(order) => state.browse.sort = order,
        Message::All => {
            state.browse.kind = None;
            state.browse.category = None;
            state.browse.tag = None;
            state.browse.favorites_only = false;
            state.browse.bin = false;
        }
        Message::Kind(kind) => {
            state.browse.kind = kind;
            state.browse.bin = false;
        }
        Message::Category(category) => {
            state.browse.category = category;
            state.browse.bin = false;
        }
        Message::Tag(tag) => {
            state.browse.tag = tag;
            state.browse.bin = false;
        }
        Message::Favorites => {
            state.browse.favorites_only = !state.browse.favorites_only;
            state.browse.bin = false;
        }
        Message::Bin => {
            state.browse.bin = !state.browse.bin;
            state.browse.selected = None;
        }
        Message::Select(id) => {
            state.browse.selected = Some(id);
            state.browse.reveal = false;
            if let Some(vault) = state.vault.as_mut() {
                vault.note_usage(id);
            }
        }
        Message::Reveal => state.browse.reveal = !state.browse.reveal,
        Message::CopyPassword(id) => {
            let value = state
                .vault
                .as_ref()
                .and_then(|v| v.item(id))
                .and_then(|i| i.password.clone());
            match value {
                Some(value) => {
                    if let Some(vault) = state.vault.as_mut() {
                        vault.note_usage(id);
                    }
                    return state.copy("Password", value);
                }
                None => state.notify_error("This item has no password"),
            }
        }
        Message::CopyUsername(id) => {
            let value = state
                .vault
                .as_ref()
                .and_then(|v| v.item(id))
                .and_then(|i| i.username.clone())
                .filter(|v| !v.trim().is_empty());
            match value {
                Some(value) => return state.copy("Username", value),
                None => state.notify_error("This item has no username"),
            }
        }
        Message::CopyTotp(id) => {
            let secret = state
                .vault
                .as_ref()
                .and_then(|v| v.item(id))
                .and_then(|i| i.totp.clone());
            match secret.and_then(|s| Totp::parse(&s).ok()).map(|t| t.now()) {
                Some(Ok(code)) => return state.copy("One-time code", code),
                Some(Err(e)) => state.notify_error(e.to_string()),
                None => state.notify_error("This item has no one-time code"),
            }
        }
        Message::Copy { label, value } => return state.copy(&label, value),
        Message::OpenUrl(url) => {
            state.open_url(&url);
        }
        Message::Edit(id) => {
            state.browse.selected = Some(id);
            state.start_edit(id);
        }
        Message::Duplicate(id) => {
            if let Some(vault) = state.vault.as_mut() {
                match vault.duplicate_item(id) {
                    Ok(new_id) => {
                        state.browse.selected = Some(new_id);
                        state.notify("Item duplicated");
                    }
                    Err(e) => state.notify_error(e.to_string()),
                }
            }
        }
        Message::Trash(id) => return Task::done(AppMessage::Ask(ConfirmAction::Trash(id))),
        Message::Restore(id) => {
            if let Some(vault) = state.vault.as_mut() {
                match vault.restore_item(id) {
                    Ok(()) => state.notify("Item restored"),
                    Err(e) => state.notify_error(e.to_string()),
                }
            }
        }
        Message::Favorite(id) => {
            if let Some(vault) = state.vault.as_mut()
                && let Some(item) = vault.item_mut(id)
            {
                item.favorite = !item.favorite;
                item.touch();
                vault.mark_dirty();
            }
        }
        Message::NewItem => {
            return Task::done(AppMessage::Tools(crate::tools::Message::Open(
                crate::tools::Modal::NewItem,
            )));
        }
        Message::Categories => {
            return Task::done(AppMessage::Tools(crate::tools::Message::Open(
                crate::tools::Modal::Categories,
            )));
        }
        Message::EmptyBin => return Task::done(AppMessage::Ask(ConfirmAction::EmptyBin)),
    }
    if reset_scroll {
        state.browse.scroll_y = 0.0;
        return iced::widget::operation::scroll_to(
            LIST_ID,
            iced::widget::scrollable::AbsoluteOffset { x: 0.0, y: 0.0 },
        )
        .map(AppMessage::Browse);
    }
    Task::none()
}

// ------------------------------------------------------------------ sidebar

/// The navigation rail.
pub fn sidebar(state: &AppState) -> Element<'_, Message> {
    let vault = state.vault.as_ref();
    let stats = vault.map(|v| v.stats());

    let mut items: Vec<Element<'_, Message>> = Vec::new();

    // Search.
    let search = text_input("Search the vault", &state.browse.query)
        .on_input(Message::Search)
        .padding([8, 10])
        .size(theme::T_BODY)
        .font(theme::REG)
        .style(theme::input_soft);
    let mut search_row: Vec<Element<'_, Message>> = vec![search.into()];
    if !state.browse.query.is_empty() {
        search_row.push(w::icon_button(Glyph::Close, 14.0, Some(Message::ClearSearch)).into());
    }
    items.push(
        container(row(search_row).spacing(4).align_y(Alignment::Center))
            .padding([10, 10])
            .into(),
    );

    let mut nav: Vec<Element<'_, Message>> = Vec::new();
    let all_active = state.browse.kind.is_none()
        && state.browse.category.is_none()
        && state.browse.tag.is_none()
        && !state.browse.favorites_only
        && !state.browse.bin;
    nav.push(
        w::nav_button(
            Glyph::Grid,
            "All items",
            stats.as_ref().map(|s| s.items),
            all_active,
            Message::All,
        )
        .into(),
    );
    nav.push(
        w::nav_button(
            Glyph::Star,
            "Favourites",
            stats.as_ref().map(|s| s.favorites),
            state.browse.favorites_only,
            Message::Favorites,
        )
        .into(),
    );
    nav.push(
        w::nav_button(
            Glyph::Trash,
            "Bin",
            stats.as_ref().map(|s| s.trashed),
            state.browse.bin,
            Message::Bin,
        )
        .into(),
    );
    items.push(container(column(nav).spacing(2)).padding([4, 8]).into());

    // Types.
    if let Some(vault) = vault {
        let mut kinds: Vec<Element<'_, Message>> = Vec::new();
        let mut heading: Vec<Element<'_, Message>> = vec![w::micro("Types"), w::grow()];
        heading.push(w::icon_button(
            Glyph::Sliders,
            13.0,
            Some(Message::Categories),
        ).into());
        kinds.push(
            container(row(heading).align_y(Alignment::Center))
                .padding(iced::Padding {
                    top: 10.0,
                    right: 10.0,
                    bottom: 2.0,
                    left: 10.0,
                })
                .into(),
        );
        for kind in ItemKind::ALL {
            let count = vault.data().count_by_kind(kind);
            if count == 0 {
                continue;
            }
            kinds.push(
                w::nav_button(
                    Glyph::of_kind(kind),
                    kind.label(),
                    Some(count),
                    state.browse.kind == Some(kind),
                    Message::Kind(Some(kind)),
                )
                .into(),
            );
        }
        items.push(container(column(kinds).spacing(2)).padding([0, 8]).into());

        // Categories.
        let categories = &vault.data().categories;
        if !categories.is_empty() {
            let mut cats: Vec<Element<'_, Message>> = Vec::new();
            let mut heading: Vec<Element<'_, Message>> = vec![w::micro("Categories"), w::grow()];
            heading.push(w::icon_button(Glyph::Plus, 13.0, Some(Message::Categories)).into());
            cats.push(
                container(row(heading).align_y(Alignment::Center))
                    .padding(iced::Padding {
                        top: 10.0,
                        right: 10.0,
                        bottom: 2.0,
                        left: 10.0,
                    })
                    .into(),
            );
            for category in categories {
                let count = vault
                    .data()
                    .items
                    .iter()
                    .filter(|i| !i.trashed && i.category == Some(category.id))
                    .count();
                cats.push(
                    w::nav_button(
                        Glyph::Folder,
                        category.name.clone(),
                        Some(count),
                        state.browse.category == Some(category.id),
                        Message::Category(Some(category.id)),
                    )
                    .into(),
                );
            }
            items.push(container(column(cats).spacing(2)).padding([0, 8]).into());
        }

        // Tags.
        let tags = vault.data().all_tags();
        if !tags.is_empty() {
            let mut wrap: Vec<Element<'_, Message>> = Vec::new();
            for tag in tags.into_iter().take(24) {
                let active = state.browse.tag.as_deref() == Some(tag.as_str());
                wrap.push(tag_chip(tag.clone(), active));
            }
            items.push(
                container(column![w::micro("Tags"), w::vgap(6.0), wrap_row(wrap)])
                    .padding([10, 10])
                    .into(),
            );
        }
    }

    items.push(w::vgap(16.0));

    let content = container(w::scroller(column(items).width(Length::Fill)).height(Length::Fill))
        .width(Length::Fixed(theme::SIDEBAR_W))
        .height(Length::Fill)
        .style(|t: &Theme| container::Style {
            background: Some(Tokens::of(t).panel.into()),
            ..container::Style::default()
        });

    row![content, w::vline()].height(Length::Fill).into()
}

/// A clickable tag chip.
fn tag_chip<'a>(tag: String, active: bool) -> Element<'a, Message> {
    let label = format!("#{tag}");
    iced::widget::button(w::small(label))
        .padding([3, 8])
        .style(move |t: &Theme, s| {
            let k = Tokens::of(t);
            let hovered = matches!(
                s,
                iced::widget::button::Status::Hovered | iced::widget::button::Status::Pressed
            );
            iced::widget::button::Style {
                background: Some(
                    (if active {
                        k.accent_soft
                    } else if hovered {
                        k.hover
                    } else {
                        iced::Color::TRANSPARENT
                    })
                    .into(),
                ),
                text_color: if active { k.accent } else { k.muted },
                border: iced::Border {
                    color: if active { k.accent } else { k.border },
                    width: 1.0,
                    radius: 99.0.into(),
                },
                shadow: iced::Shadow::default(),
                snap: true,
            }
        })
        .on_press(Message::Tag(if active { None } else { Some(tag) }))
        .into()
}

/// Lay elements out in a simple wrapping-ish grid: rows of three.
fn wrap_row<'a>(children: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    let mut grid: Vec<Element<'a, Message>> = Vec::new();
    let mut line: Vec<Element<'a, Message>> = Vec::new();
    for child in children {
        line.push(child);
        if line.len() == 2 {
            grid.push(row(std::mem::take(&mut line)).spacing(6).into());
            grid.push(w::vgap(6.0));
        }
    }
    if !line.is_empty() {
        grid.push(row(line).spacing(6).into());
    }
    column(grid).into()
}

// --------------------------------------------------------------- item list

/// The middle column: heading and rows.
pub fn list(state: &AppState) -> Element<'_, Message> {
    let ids = state.filtered();
    let count = ids.len();

    let mut header: Vec<Element<'_, Message>> = vec![
        column![
            w::title(state.browse.title()),
            w::small(format!(
                "{count} item{}",
                if count == 1 { "" } else { "s" }
            )),
        ]
        .width(Length::Fill)
        .into(),
    ];

    if state.browse.bin {
        header.push(
            w::secondary_icon_button(
                Glyph::Trash,
                "Empty the bin",
                Message::EmptyBin,
            )
            .into(),
        );
    } else {
        header.push(
            iced::widget::pick_list(
                &SortChoice::ALL[..],
                Some(SortChoice(state.browse.sort)),
                |choice| Message::Sort(choice.0),
            )
            .width(Length::Fixed(150.0))
            .text_size(theme::T_BODY)
            .font(theme::REG)
            .padding([7, 10])
            .style(theme::pick_list)
            .menu_style(theme::menu)
            .into(),
        );
        header.push(w::primary_icon_button(Glyph::Plus, "New item", Message::NewItem).into());
    }

    let heading = container(row(header).spacing(8).align_y(Alignment::Center))
        .width(Length::Fill)
        .padding([14, 16]);

    let body: Element<'_, Message> = if ids.is_empty() {
        let (glyph, headline, hint) = if state.browse.bin {
            (Glyph::Trash, "The bin is empty", "Items you delete land here first.")
        } else if !state.browse.query.is_empty() {
            (
                Glyph::Search,
                "Nothing matched",
                "Try a different word, or clear the search.",
            )
        } else {
            (
                Glyph::Key,
                "Your vault is ready",
                "Add your first login with the New item button.",
            )
        };
        w::empty_state(glyph, headline, hint)
    } else {
        // Virtual list: a fixed-height spacer stands in for the rows above and
        // below the window. The scrollbar sees the full content height, but
        // only ~25 widgets are built and laid out per frame.
        let total_height = count as f32 * ROW_HEIGHT;
        let viewport = if state.browse.viewport_h > 0.0 {
            state.browse.viewport_h
        } else {
            FALLBACK_VIEWPORT
        };
        let offset = state
            .browse
            .scroll_y
            .clamp(0.0, (total_height - viewport).max(0.0));
        let first = ((offset / ROW_HEIGHT).floor() as usize).saturating_sub(OVERSCAN);
        let visible = (viewport / ROW_HEIGHT).ceil() as usize + OVERSCAN * 2 + 2;
        let last = (first + visible).min(count);

        let mut column_rows = column![]; // no spacing: ROW_HEIGHT includes it
        if first > 0 {
            column_rows = column_rows.push(w::vgap(first as f32 * ROW_HEIGHT));
        }
        if let Some(vault) = state.vault.as_ref() {
            for id in &ids[first..last] {
                if let Some(item) = vault.item(*id) {
                    column_rows = column_rows.push(row_entry(state, row_for(item)));
                }
            }
        }
        let below = count.saturating_sub(last) as f32;
        if below > 0.0 {
            column_rows = column_rows.push(w::vgap(below * ROW_HEIGHT));
        }

        w::scroller(column_rows.width(Length::Fill))
            .id(LIST_ID)
            .on_scroll(|viewport| Message::Scrolled {
                offset: viewport.absolute_offset().y,
                viewport: viewport.bounds().height,
            })
            .height(Length::Fill)
            .into()
    };

    container(column![heading, w::hline(), body])
        .width(Length::Fill)
        .height(Length::Fill)
        .style(|t: &Theme| container::Style {
            background: Some(Tokens::of(t).canvas.into()),
            ..container::Style::default()
        })
        .into()
}

/// One row in the item list.
fn row_entry<'a>(state: &'a AppState, item: Row) -> Element<'a, Message> {
    let selected = state.browse.selected == Some(item.id);

    let mut meta: Vec<Element<'_, Message>> = Vec::new();
    if item.has_totp {
        meta.push(glyph::tinted(Glyph::QrCode, 13.0, theme::muted).into());
    }
    if let Some(score) = item.score
        && score <= 1
        && item.kind.has_auditable_password()
    {
        meta.push(glyph::colored(Glyph::Warning, 13.0, theme::score_color(score)).into());
    }
    if item.favorite {
        meta.push(glyph::tinted(Glyph::Star, 13.0, theme::warn).into());
    }
    meta.push(w::small(item.updated.clone()).into());

    let mut body: Vec<Element<'_, Message>> = vec![
        w::kind_tile(item.kind, 32.0),
        w::gap(11.0),
        container(column![
            w::strong_line(item.title.clone()),
            w::small_line(item.subtitle.clone()),
        ])
        .width(Length::Fill)
        .clip(true)
        .into(),
    ];
    if !meta.is_empty() {
        body.push(
            column![row(meta).spacing(6).align_y(Alignment::Center)]
                .align_x(Alignment::End)
                .into(),
        );
    }

    container(
        iced::widget::button(row(body).align_y(Alignment::Center))
            .width(Length::Fill)
            .padding([7, 9])
            .style(move |t: &Theme, s| theme::row(t, s, selected))
            .on_press(Message::Select(item.id)),
    )
    .padding([1, 8])
    .width(Length::Fill)
    .height(Length::Fixed(ROW_HEIGHT))
    .align_y(Alignment::Center)
    .into()
}

// ------------------------------------------------------------------ detail

/// The right-hand pane.
pub fn detail(state: &AppState) -> Element<'_, Message> {
    let body: Element<'_, Message> = match state
        .vault
        .as_ref()
        .zip(state.browse.selected)
        .and_then(|(vault, id)| vault.item(id).map(|item| (vault, item)))
    {
        Some((vault, item)) => detail_body(state, vault, item),
        None => w::empty_state(
            Glyph::Shield,
            "Nothing selected",
            "Pick an item on the left to see its details.",
        ),
    };

    let pane = container(body)
        .width(Length::Fixed(theme::DETAIL_W))
        .height(Length::Fill)
        .style(|t: &Theme| container::Style {
            background: Some(Tokens::of(t).panel.into()),
            ..container::Style::default()
        });

    row![w::vline(), pane].height(Length::Fill).into()
}

/// The contents of the detail pane for one item.
fn detail_body<'a>(
    state: &'a AppState,
    vault: &'a aurapass_core::vault::UnlockedVault,
    item: &'a Item,
) -> Element<'a, Message> {
    let id = item.id;
    let mut sections: Vec<Element<'_, Message>> = Vec::new();

    // ---- header
    let category = item
        .category
        .and_then(|c| vault.data().category_name(c))
        .map(str::to_string);
    let mut subtitle: Vec<String> = vec![item.kind.label().to_string()];
    if let Some(category) = category {
        subtitle.push(category);
    }
    sections.push(
        row![
            w::kind_tile(item.kind, 44.0),
            w::gap(12.0),
            column![
                w::h1(item.title.clone()),
                w::small(subtitle.join(" · ")),
            ]
            .width(Length::Fill),
        ]
        .align_y(Alignment::Center)
        .into(),
    );

    // ---- action bar
    let mut actions: Vec<Element<'_, Message>> = Vec::new();
    actions.push(action_button(Glyph::Copy, "Copy password", Some(Message::CopyPassword(id))));
    if item.username.as_deref().is_some_and(|u| !u.trim().is_empty()) {
        actions.push(action_button(Glyph::Users, "Copy username", Some(Message::CopyUsername(id))));
    }
    if let Some(url) = item.primary_url() {
        actions.push(action_button(
            Glyph::Globe,
            "Open website",
            Some(Message::OpenUrl(url.to_string())),
        ));
    }
    actions.push(action_button(Glyph::Edit, "Edit", Some(Message::Edit(id))));
    actions.push(action_button(Glyph::Duplicate, "Duplicate", Some(Message::Duplicate(id))));
    actions.push(action_button(
        if item.favorite { Glyph::Star } else { Glyph::Star },
        if item.favorite { "Unfavourite" } else { "Favourite" },
        Some(Message::Favorite(id)),
    ));
    if item.trashed {
        actions.push(action_button(Glyph::Restore, "Restore", Some(Message::Restore(id))));
    } else {
        actions.push(action_button(Glyph::Trash, "Move to bin", Some(Message::Trash(id))));
    }
    sections.push(
        container(row(actions).spacing(6).wrap())
            .padding(iced::Padding {
                top: 10.0,
                right: 0.0,
                bottom: 0.0,
                left: 0.0,
            })
            .into(),
    );

    // ---- credentials
    let mut credentials: Vec<Element<'_, Message>> = Vec::new();
    if let Some(username) = item.username.as_deref().filter(|u| !u.trim().is_empty()) {
        credentials.push(field_row(
            "Username",
            username.to_string(),
            false,
            vec![w::icon_button(
                Glyph::Copy,
                14.0,
                Some(Message::Copy {
                    label: "Username".into(),
                    value: username.to_string(),
                }),
            )
            .into()],
        ));
    }
    if let Some(password) = item.password.as_deref() {
        let score = item.strength().map(|s| s.score);
        let mut trailing: Vec<Element<'_, Message>> = vec![
            w::icon_button(
                if state.browse.reveal {
                    Glyph::EyeOff
                } else {
                    Glyph::Eye
                },
                14.0,
                Some(Message::Reveal),
            )
            .into(),
            w::icon_button(Glyph::Copy, 14.0, Some(Message::CopyPassword(id))).into(),
        ];
        if let Some(score) = score {
            trailing.insert(0, w::strength_bar(score, 54.0));
        }
        credentials.push(field_row(
            "Password",
            theme::mask(password, state.browse.reveal),
            true,
            trailing,
        ));
    }
    if let Some(secret) = item.totp.as_deref() {
        let parsed = Totp::parse(secret).ok();
        let (code, remaining) = match &parsed {
            Some(totp) => (
                totp.code_at(state.now_unix).unwrap_or_else(|_| "—— ——".into()),
                totp.seconds_remaining(state.now_unix),
            ),
            None => ("invalid secret".into(), 0),
        };
        let spaced = code
            .chars()
            .enumerate()
            .fold(String::new(), |mut acc, (i, c)| {
                if i > 0 && i % 3 == 0 {
                    acc.push(' ');
                }
                acc.push(c);
                acc
            });
        credentials.push(field_row_with_hint(
            "One-time code",
            spaced,
            &format!("{remaining}s"),
            true,
            vec![
                w::icon_button(Glyph::Copy, 14.0, Some(Message::CopyTotp(id))).into(),
            ],
        ));
    }
    if !credentials.is_empty() {
        sections.push(card("Credentials", credentials));
    }

    // ---- websites
    if !item.urls.is_empty() {
        let urls: Vec<Element<'_, Message>> = item
            .urls
            .iter()
            .map(|url| {
                field_row(
                    "Website",
                    url.clone(),
                    false,
                    vec![
                        w::icon_button(Glyph::External, 14.0, Some(Message::OpenUrl(url.clone())))
                            .into(),
                        w::icon_button(
                            Glyph::Copy,
                            14.0,
                            Some(Message::Copy {
                                label: "Website".into(),
                                value: url.clone(),
                            }),
                        )
                        .into(),
                    ],
                )
            })
            .collect();
        sections.push(card("Websites", urls));
    }

    // ---- extra fields
    if !item.fields.is_empty() {
        let fields: Vec<Element<'_, Message>> = item
            .fields
            .iter()
            .map(|field| {
                let shown = if field.sensitive && !state.browse.reveal {
                    theme::mask(&field.value, false)
                } else {
                    field.value.clone()
                };
                field_row(
                    &field.label,
                    shown,
                    false,
                    vec![
                        w::icon_button(
                            Glyph::Copy,
                            14.0,
                            Some(Message::Copy {
                                label: field.label.clone(),
                                value: field.value.clone(),
                            }),
                        )
                        .into(),
                    ],
                )
            })
            .collect();
        sections.push(card("Fields", fields));
    }

    // ---- notes
    if !item.notes.trim().is_empty() {
        sections.push(card(
            "Notes",
            vec![
                container(
                    text(item.notes.clone())
                        .size(theme::T_BODY)
                        .font(theme::REG)
                        .style(|t: &Theme| text::Style {
                            color: Some(Tokens::of(t).text),
                        }),
                )
                .width(Length::Fill)
                .padding([10, 11])
                .style(theme::well)
                .into(),
            ],
        ));
    }

    // ---- attachments
    if !item.attachments.is_empty() {
        let files: Vec<Element<'_, Message>> = item
            .attachments
            .iter()
            .map(|file| {
                field_row(
                    &file.name,
                    format!("{} KB · {}", file.size / 1024, file.mime),
                    false,
                    Vec::new(),
                )
            })
            .collect();
        sections.push(card("Attachments", files));
    }

    // ---- history
    if !item.password_history.is_empty() {
        let history: Vec<Element<'_, Message>> = item
            .password_history
            .iter()
            .take(5)
            .map(|old| {
                field_row(
                    &long_date(old.changed_at),
                    theme::mask(&old.password, false),
                    true,
                    vec![
                        w::icon_button(
                            Glyph::Copy,
                            14.0,
                            Some(Message::Copy {
                                label: "Old password".into(),
                                value: old.password.clone(),
                            }),
                        )
                        .into(),
                    ],
                )
            })
            .collect();
        sections.push(card("Password history", history));
    }

    // ---- metadata
    let mut meta: Vec<Element<'_, Message>> = vec![
        field_row("Created", long_date(item.created_at), false, Vec::new()),
        field_row("Modified", long_date(item.updated_at), false, Vec::new()),
    ];
    if let Some(used) = item.last_used_at {
        meta.push(field_row("Last used", long_date(used), false, Vec::new()));
    }
    if let Some(changed) = item.password_changed_at {
        meta.push(field_row(
            "Password changed",
            long_date(changed),
            false,
            Vec::new(),
        ));
    }
    if !item.tags.is_empty() {
        let chips: Vec<Element<'_, Message>> = item
            .tags
            .iter()
            .map(|tag| w::chip(format!("#{tag}"), theme::accent))
            .collect();
        meta.push(
            container(column![
                w::micro("Tags"),
                w::vgap(5.0),
                row(chips).spacing(5).wrap(),
            ])
            .padding([6, 0])
            .into(),
        );
    }
    sections.push(card("Details", meta));

    // ---- bin actions
    if item.trashed {
        sections.push(
            container(
                row![w::secondary_icon_button(
                    Glyph::Restore,
                    "Restore",
                    Message::Restore(id)
                )]
                .spacing(8),
            )
            .padding([4, 0])
            .into(),
        );
    }

    w::scroller(
        column![column(sections).spacing(14)]
            .width(Length::Fill)
            .padding(18),
    )
    .height(Length::Fill)
    .into()
}

/// A small labelled action button.
fn action_button<'a>(glyph: Glyph, label: &str, message: Option<Message>) -> Element<'a, Message> {
    let button = iced::widget::button(
        row![glyph::icon(glyph, 14.0), w::gap(6.0), w::small(label)]
            .align_y(Alignment::Center),
    )
    .padding([6, 10])
    .style(theme::secondary);
    match message {
        Some(m) => button.on_press(m).into(),
        None => button.into(),
    }
}

/// A card with an uppercase heading.
fn card<'a>(heading: &str, rows: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    w::card(heading, rows)
}

/// A label above a read-only value, with trailing actions.
fn field_row<'a>(
    label: &str,
    value: String,
    monospace: bool,
    trailing: Vec<Element<'a, Message>>,
) -> Element<'a, Message> {
    let value_text = if monospace {
        text(value)
            .size(theme::T_BODY)
            .font(theme::REG)
            .style(|t: &Theme| text::Style {
                color: Some(Tokens::of(t).text),
            })
    } else {
        text(value)
            .size(theme::T_BODY)
            .font(theme::REG)
            .style(|t: &Theme| text::Style {
                color: Some(Tokens::of(t).text),
            })
    };

    let mut kids: Vec<Element<'a, Message>> = vec![value_text.width(Length::Fill).into()];
    kids.extend(trailing);

    column![
        w::micro(label),
        w::vgap(4.0),
        container(row(kids).spacing(6).align_y(Alignment::Center))
            .width(Length::Fill)
            .padding([7, 9])
            .style(theme::well),
    ]
    .width(Length::Fill)
    .into()
}

/// Like [`field_row`], with a muted hint after the value.
fn field_row_with_hint<'a>(
    label: &str,
    value: String,
    hint: &str,
    monospace: bool,
    trailing: Vec<Element<'a, Message>>,
) -> Element<'a, Message> {
    let mut kids: Vec<Element<'a, Message>> = vec![
        text(value)
            .size(theme::T_BODY)
            .font(if monospace { theme::SEMI } else { theme::REG })
            .style(|t: &Theme| text::Style {
                color: Some(Tokens::of(t).text),
            })
            .into(),
        w::small(hint.to_string()).into(),
        w::grow(),
    ];
    kids.extend(trailing);
    column![
        w::micro(label),
        w::vgap(4.0),
        container(row(kids).spacing(6).align_y(Alignment::Center))
            .width(Length::Fill)
            .padding([7, 9])
            .style(theme::well),
    ]
    .width(Length::Fill)
    .into()
}
