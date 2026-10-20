//! Reusable pieces of the AuraPass interface.
//!
//! Everything here is deliberately dumb: it knows about the design tokens and
//! nothing about the vault. Screens compose these into layouts.

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::widget::text::Wrapping;
use iced::{Alignment, Color, Element, Length, Renderer, Theme};

use crate::glyph::{self, Glyph};
use crate::theme::{self, Tokens};

/// Shorthand for the element type every screen returns.
pub type El<'a, M> = Element<'a, M, Theme, Renderer>;

// ----------------------------------------------------------------- text
//
// These helpers return a fully erased `El` rather than a `Text`. A `Text` works
// inside the `row!`/`column!` macros — they convert for you — but not when a
// screen builds its children into a `Vec` and pushes them one at a time, which
// is how every dialog here is assembled. Returning `El` makes both work.

/// An uppercase micro-label: field captions, section headers.
pub fn micro<'a, M: 'a>(s: impl Into<String>) -> El<'a, M> {
    text(s.into())
        .size(theme::T_MICRO)
        .font(theme::SEMI)
        .style(|t: &Theme| text::Style {
            color: Some(Tokens::of(t).faint),
        })
        .into()
}

/// Secondary metadata.
pub fn small<'a, M: 'a>(s: impl Into<String>) -> El<'a, M> {
    text(s.into())
        .size(theme::T_SMALL)
        .font(theme::REG)
        .style(|t: &Theme| text::Style {
            color: Some(Tokens::of(t).muted),
        })
        .into()
}

/// The workhorse body size.
pub fn body<'a, M: 'a>(s: impl Into<String>) -> El<'a, M> {
    text(s.into())
        .size(theme::T_BODY)
        .font(theme::REG)
        .style(|t: &Theme| text::Style {
            color: Some(Tokens::of(t).text),
        })
        .into()
}

/// Body text at the row size.
pub fn strong<'a, M: 'a>(s: impl Into<String>) -> El<'a, M> {
    text(s.into())
        .size(theme::T_ROW)
        .font(theme::MED)
        .style(|t: &Theme| text::Style {
            color: Some(Tokens::of(t).text),
        })
        .into()
}

/// A row title that never wraps; the list row has a fixed height.
pub fn strong_line<'a, M: 'a>(s: impl Into<String>) -> El<'a, M> {
    text(s.into())
        .size(theme::T_ROW)
        .font(theme::MED)
        .wrapping(Wrapping::None)
        .style(|t: &Theme| text::Style {
            color: Some(Tokens::of(t).text),
        })
        .into()
}

/// Row metadata on one line.
pub fn small_line<'a, M: 'a>(s: impl Into<String>) -> El<'a, M> {
    text(s.into())
        .size(theme::T_SMALL)
        .font(theme::REG)
        .wrapping(Wrapping::None)
        .style(|t: &Theme| text::Style {
            color: Some(Tokens::of(t).muted),
        })
        .into()
}


/// A section heading.
pub fn title<'a, M: 'a>(s: impl Into<String>) -> El<'a, M> {
    text(s.into())
        .size(theme::T_TITLE)
        .font(theme::SEMI)
        .style(|t: &Theme| text::Style {
            color: Some(Tokens::of(t).text),
        })
        .into()
}

/// A screen heading.
pub fn h1<'a, M: 'a>(s: impl Into<String>) -> El<'a, M> {
    text(s.into())
        .size(theme::T_H1)
        .font(theme::SEMI)
        .style(|t: &Theme| text::Style {
            color: Some(Tokens::of(t).text),
        })
        .into()
}


// ------------------------------------------------------------- primitives

/// A flexible horizontal spacer.
pub fn grow<'a, M: 'a>() -> El<'a, M> {
    Space::new().width(Length::Fill).into()
}

/// A fixed-size gap.
pub fn gap<'a, M: 'a>(w: f32) -> El<'a, M> {
    Space::new().width(Length::Fixed(w)).into()
}

/// A fixed vertical gap.
pub fn vgap<'a, M: 'a>(h: f32) -> El<'a, M> {
    Space::new().height(Length::Fixed(h)).into()
}

// ---------------------------------------------------------------- dialogs

/// The frame every dialog shares.
///
/// A padded header, a body that only scrolls when it has to, a hairline and a
/// padded footer. Every dialog goes through here, so the title, the content and
/// the buttons always line up on the same two rules — and nothing can ever be
/// painted flush against the card's rounded edge.
pub fn dialog<'a, M: 'a>(
    width: f32,
    head: El<'a, M>,
    body: Vec<El<'a, M>>,
    footer: Vec<El<'a, M>>,
    scroll: bool,
) -> El<'a, M> {
    const PAD: u16 = 18;
    // The side padding sits inside the scroll area, so the scrollbar floats in
    // the empty margin instead of being drawn over the cards.
    let inset: [u16; 2] = [0, PAD];

    let content: El<'a, M> = if scroll {
        scroller(column(body).spacing(9).padding(inset))
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    } else {
        column(body).spacing(9).padding(inset).into()
    };

    let mut foot: Vec<El<'a, M>> = vec![grow()];
    foot.extend(footer);

    column![
        container(head).padding([PAD, PAD]).width(Length::Fill),
        {
            // Only a scrolling body claims the full height; a short dialog
            // stays as tall as its contents and sits centred in the window.
            let block = container(content).width(Length::Fill);
            if scroll {
                block.height(Length::Fill)
            } else {
                block
            }
        },
        vgap(12.0),
        hline(),
        container(
            row(foot)
                .spacing(8)
                .width(Length::Fill)
                .align_y(Alignment::Center)
        )
        .padding([12, PAD])
        .width(Length::Fill),
    ]
    .width(Length::Fixed(width))
    .into()
}

// -------------------------------------------------------------- scrolling

/// A vertical scroll area with the app's slim scrollbar.
///
/// The bar floats over the content's right edge with a small margin, so it
/// never shifts the layout when it appears and never draws a rail.
pub fn scroller<'a, M: 'a>(
    content: impl Into<El<'a, M>>,
) -> iced::widget::Scrollable<'a, M> {
    iced::widget::scrollable(content)
        .direction(scrollable::Direction::Vertical(
            scrollable::Scrollbar::new()
                .width(14.0)
                .scroller_width(9.0)
                .margin(3.0),
        ))
        .style(theme::scrollbar)
}


/// A one-pixel horizontal separator that fills the available width.
pub fn hline<'a, M: 'a>() -> El<'a, M> {
    container(Space::new())
        .width(Length::Fill)
        .height(Length::Fixed(1.0))
        .style(|t: &Theme| container::Style {
            background: Some(Tokens::of(t).border.into()),
            ..container::Style::default()
        })
        .into()
}

/// A one-pixel vertical separator that fills the available height.
pub fn vline<'a, M: 'a>() -> El<'a, M> {
    container(Space::new())
        .width(Length::Fixed(1.0))
        .height(Length::Fill)
        .style(|t: &Theme| container::Style {
            background: Some(Tokens::of(t).border.into()),
            ..container::Style::default()
        })
        .into()
}


/// A vertical hairline.
pub fn vdivider<'a, M: 'a>() -> Element<'a, M> {
    container(Space::new())
        .width(Length::Fixed(1.0))
        .height(Length::Fixed(18.0))
        .style(|t: &Theme| container::Style {
            background: Some(Tokens::of(t).border.into()),
            ..container::Style::default()
        })
        .into()
}

// ---------------------------------------------------------------- buttons

/// A borderless icon button.
pub fn icon_button<'a, M: Clone + 'a>(
    g: Glyph,
    size: f32,
    message: Option<M>,
) -> button::Button<'a, M> {
    let b: button::Button<'a, M> = button({
        let content: El<'a, M> = glyph::icon(g, size).into();
        content
    })
    .padding([6, 7])
    .style(theme::bare);
    match message {
        Some(m) => b.on_press(m),
        None => b,
    }
}


/// The violet call-to-action.
pub fn primary_button<'a, M: Clone + 'a>(label: &'a str, message: M) -> button::Button<'a, M> {
    button(
        text(label.to_string())
            .size(theme::T_BODY)
            .font(theme::MED),
    )
    .padding([8, 15])
    .style(theme::primary)
    .on_press(message)
}

/// The violet call-to-action with a leading icon.
pub fn primary_icon_button<'a, M: Clone + 'a>(
    g: Glyph,
    label: &'a str,
    message: M,
) -> button::Button<'a, M> {
    button(
        row![
            glyph::colored(g, 15.0, Color::WHITE),
            text(label.to_string())
                .size(theme::T_BODY)
                .font(theme::MED)
                .color(Color::WHITE),
        ]
        .spacing(7)
        .align_y(Alignment::Center),
    )
    .padding([8, 14])
    .style(theme::primary)
    .on_press(message)
}

/// A quiet bordered button.
pub fn secondary_button<'a, M: Clone + 'a>(label: &'a str, message: M) -> button::Button<'a, M> {
    button(
        text(label.to_string())
            .size(theme::T_BODY)
            .font(theme::REG),
    )
    .padding([8, 14])
    .style(theme::secondary)
    .on_press(message)
}

/// A bordered button with a leading icon.
pub fn secondary_icon_button<'a, M: Clone + 'a>(
    g: Glyph,
    label: &'a str,
    message: M,
) -> button::Button<'a, M> {
    button(
        row![
            glyph::icon(g, 15.0),
            body(label.to_string()),
        ]
        .spacing(7)
        .align_y(Alignment::Center),
    )
    .padding([8, 13])
    .style(theme::secondary)
    .on_press(message)
}

/// A destructive button.
pub fn danger_button<'a, M: Clone + 'a>(label: &'a str, message: M) -> button::Button<'a, M> {
    button(
        text(label.to_string())
            .size(theme::T_BODY)
            .font(theme::MED)
            .color(Color::WHITE),
    )
    .padding([8, 14])
    .style(theme::destructive)
    .on_press(message)
}

/// A navigation-rail entry: icon, label, and an optional count.
pub fn nav_button<'a, M: Clone + 'a>(
    g: Glyph,
    label: impl Into<String>,
    count: Option<usize>,
    active: bool,
    message: M,
) -> button::Button<'a, M> {
    let label = label.into();
    let mut children: Vec<El<'a, M>> = vec![
        glyph::tinted(g, 16.0, if active { theme::accent } else { theme::muted }).into(),
        text(label)
            .size(theme::T_BODY)
            .font(if active { theme::MED } else { theme::REG })
            .style(move |t: &Theme| text::Style {
                color: Some(if active {
                    Tokens::of(t).accent
                } else {
                    Tokens::of(t).text
                }),
            })
            .into(),
        grow().into(),
    ];
    if let Some(n) = count {
        children.push(
            text(n.to_string())
                .size(theme::T_SMALL)
                .font(theme::REG)
                .style(move |t: &Theme| text::Style {
                    color: Some(if active {
                        Tokens::of(t).accent
                    } else {
                        Tokens::of(t).faint
                    }),
                })
                .into(),
        );
    }
    button(row(children).spacing(10).align_y(Alignment::Center))
        .width(Length::Fill)
        .padding([7, 10])
        .style(move |t: &Theme, s| theme::nav(t, s, active))
        .on_press(message)
}

/// A member of a segmented control.
pub fn segment<'a, M: Clone + 'a>(
    label: impl Into<String>,
    active: bool,
    message: M,
) -> button::Button<'a, M> {
    button(
        text(label.into())
            .size(theme::T_BODY)
            .font(if active { theme::MED } else { theme::REG }),
    )
    .padding([7, 13])
    .style(move |t: &Theme, s| theme::segment(t, s, active))
    .on_press(message)
}

/// A checkbox with a label.
pub fn check<'a, M: 'a>(
    label: impl Into<String>,
    value: bool,
    on_toggle: impl Fn(bool) -> M + 'a,
) -> El<'a, M> {
    iced::widget::checkbox(value)
        .label(label.into())
        .size(16.0)
        .text_size(theme::T_BODY)
        .font(theme::REG)
        .style(theme::checkbox)
        .on_toggle(on_toggle)
        .into()
}

/// A small rounded tile carrying an item-kind icon.
pub fn kind_tile<'a, M: 'a>(kind: aurapass_core::ItemKind, size: f32) -> El<'a, M> {
    let mark: El<'a, M> = glyph::tinted(Glyph::of_kind(kind), size * 0.48, theme::accent).into();
    container(mark)
    .width(Length::Fixed(size))
    .height(Length::Fixed(size))
    .center_x(Length::Fixed(size))
    .center_y(Length::Fixed(size))
    .style(|t: &Theme| {
        let k = Tokens::of(t);
        container::Style {
            background: Some(k.accent_soft.into()),
            border: rounded(theme::R_SM),
            ..container::Style::default()
        }
    })
    .into()
}

/// A flat colour block with rounded corners — used for meters and bars.
pub fn block<'a, M: 'a>(width: Length, height: f32, color: Color, radius: f32) -> El<'a, M> {
    container(Space::new())
        .width(width)
        .height(Length::Fixed(height))
        .style(move |_t: &Theme| container::Style {
            background: Some(color.into()),
            border: rounded(radius),
            ..container::Style::default()
        })
        .into()
}

/// A raised card with an uppercase heading and a stack of rows.
///
/// The detail pane and the preferences dialog both file their controls this
/// way, so the two read as the same interface.
pub fn card<'a, M: 'a>(heading: &str, rows: Vec<El<'a, M>>) -> El<'a, M> {
    container(
        column![
            micro::<M>(heading),
            vgap::<M>(7.0),
            column(rows).spacing(7)
        ]
        .width(Length::Fill),
    )
    .width(Length::Fill)
    .padding(12)
    .style(theme::card)
    .into()
}

/// A status chip: "Reused", "Weak", a tag, …
pub fn chip<'a, M: 'a>(label: impl Into<String>, tone: fn(&Tokens) -> Color) -> El<'a, M> {
    container(
        text(label.into())
            .size(theme::T_MICRO)
            .font(theme::MED),
    )
    .padding([2, 7])
    .style(move |t: &Theme| {
        let k = Tokens::of(t);
        let c = tone(&k);
        container::Style {
            background: Some(k.wash(c).into()),
            border: iced::Border {
                color: Color { a: 0.35, ..c },
                width: 1.0,
                radius: 99.0.into(),
            },
            text_color: Some(c),
            ..container::Style::default()
        }
    })
    .into()
}


/// The dimming layer plus a centred dialog.
pub fn scrim<'a, M: 'a>(dialog: impl Into<El<'a, M>>) -> El<'a, M> {
    container(
        container(dialog)
            .max_width(780.0)
            .clip(true)
            .style(theme::card),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .padding(26)
    .style(|t: &Theme| container::Style {
        background: Some(Tokens::of(t).scrim.into()),
        ..container::Style::default()
    })
    .into()
}

/// An empty-state block: icon, headline, hint.
pub fn empty_state<'a, M: 'a>(
    g: Glyph,
    headline: impl Into<String>,
    hint: impl Into<String>,
) -> El<'a, M> {
    let dial: El<'a, M> = container({
        let icon: El<'a, M> = glyph::icon(g, 30.0).into();
        icon
    })
    .padding(14)
    .style(|t: &Theme| {
        let k = Tokens::of(t);
        container::Style {
            background: Some(k.sunken.into()),
            border: rounded(99.0),
            ..container::Style::default()
        }
    })
    .into();
    container(
        column![
            dial,
            vgap(12.0),
            title(headline),
            vgap(4.0),
            small(hint),
        ]
        .spacing(0)
        .align_x(Alignment::Center),
    )
    .width(Length::Fill)
    .center_x(Length::Fill)
    .padding([30, 20])
    .into()
}

/// A compact horizontal strength meter.
pub fn strength_bar<'a, M: 'a>(score: u8, width: f32) -> El<'a, M> {
    let lit = score.min(4) as usize + 1;
    let mut bars: Vec<El<'a, M>> = Vec::with_capacity(5);
    for i in 0..5 {
        let on = i < lit;
        let color = if on {
            theme::score_color(score)
        } else {
            Color { a: 0.18, ..Color::BLACK }
        };
        bars.push(block(Length::Fill, 4.0, color, 2.0));
    }
    container(row(bars).spacing(3))
        .width(Length::Fixed(width))
        .into()
}



/// The AuraPass brand badge: a violet rounded tile with a white mark.
pub fn brand_badge<'a, M: 'a>(size: f32) -> El<'a, M> {
    let mark: El<'a, M> = glyph::colored(Glyph::Brand, size * 0.52, Color::WHITE).into();
    container(mark)
        .width(Length::Fixed(size))
        .height(Length::Fixed(size))
        .center_x(Length::Fixed(size))
        .center_y(Length::Fixed(size))
        .style(move |t: &Theme| container::Style {
            background: Some(Tokens::of(t).accent.into()),
            border: rounded(size * 0.26),
            ..container::Style::default()
        })
        .into()
}

/// Small helper: a border with only a radius set.
fn rounded(radius: f32) -> iced::Border {
    iced::Border {
        color: Color::TRANSPARENT,
        width: 0.0,
        radius: radius.into(),
    }
}
