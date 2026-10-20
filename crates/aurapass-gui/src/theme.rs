//! The AuraPass design system.
//!
//! One place for every colour, radius, type size and widget style in the
//! desktop app. Screens never hard-code a colour: they ask [`Tokens`] for one,
//! which keeps light and dark mode in step and makes the look easy to tune.
//!
//! The typeface is Inter (bundled, SIL Open Font License — see `NOTICE`). It is
//! loaded as a variable font, so every weight below is a real interpolation
//! rather than a synthesised bold.

use iced::theme::Palette;
use iced::widget::{
    button, checkbox as checkbox_widget, container, pick_list as pick_list_widget, scrollable,
    text_input,
};
use iced::{Border, Color, Font, Shadow, Theme, Vector};
use iced::font::{Family, Stretch, Style as FontStyle, Weight};

/// Inter, as shipped with the package. Variable, covering Latin/Greek/Cyrillic.
pub const INTER: &[u8] = include_bytes!("../assets/Inter.ttf");

/// Regular. The default UI weight.
pub const REG: Font = Font {
    family: Family::Name("Inter"),
    weight: Weight::Normal,
    stretch: Stretch::Normal,
    style: FontStyle::Normal,
};

/// Medium — used for emphasis without shouting.
pub const MED: Font = Font {
    weight: Weight::Medium,
    ..REG
};

/// Semibold — headings and primary buttons.
pub const SEMI: Font = Font {
    weight: Weight::Semibold,
    ..REG
};

/// Bold — the brand wordmark.
pub const BOLD: Font = Font {
    weight: Weight::Bold,
    ..REG
};

/// The icon face: Lucide, mapped to those 0..1 codepoints.
pub const ICON: Font = iced_fonts::LUCIDE_FONT;

// ---------------------------------------------------------------- type scale

/// Uppercase micro-labels above fields.
pub const T_MICRO: f32 = 10.5;
/// Secondary metadata (timestamps, counts).
pub const T_SMALL: f32 = 11.5;
/// The workhorse body size.
pub const T_BODY: f32 = 13.0;
/// Slightly larger body, for list rows.
pub const T_ROW: f32 = 13.5;
/// Section headings.
pub const T_TITLE: f32 = 15.0;
/// Screen title.
pub const T_H1: f32 = 21.0;

// -------------------------------------------------------------- geometry

/// Small radius: chips, inputs.
pub const R_SM: f32 = 7.0;
/// Medium radius: cards, buttons.
pub const R_MD: f32 = 9.0;
/// Large radius: windows and dialogs.
pub const R_LG: f32 = 13.0;

/// Width of the navigation rail.
pub const SIDEBAR_W: f32 = 226.0;
/// Width of the item detail pane.
pub const DETAIL_W: f32 = 392.0;
/// Height of the title/tool bar.
pub const TOOLBAR_H: f32 = 50.0;
/// Extra air above the toolbar contents, so the icons do not hug the top edge.
pub const TOOLBAR_PAD_TOP: f32 = 8.0;
/// Height of the footer status bar.
pub const STATUS_H: f32 = 26.0;

/// The un-shiftable, brand-neutral accent (AuraPass violet).
pub const ACCENT: Color = Color::from_rgb(0.427, 0.361, 1.0);

/// Every colour the UI uses, resolved for the active mode.
#[derive(Debug, Clone, Copy)]
pub struct Tokens {
    pub is_dark: bool,
    /// The main content surface.
    pub canvas: Color,
    /// The navigation rail / detail pane.
    pub panel: Color,
    /// Inset wells: search fields, table headers.
    pub sunken: Color,
    /// Hover state for list rows and menu entries.
    pub hover: Color,
    /// Active/selected tint.
    pub selected: Color,
    /// Hairline dividers and input outlines.
    pub border: Color,
    /// A heavier outline, for emphasis.
    pub border_strong: Color,
    /// Outlines around editable fields — a step darker than the hairline so
    /// inputs read as controls, not as empty space.
    pub field_border: Color,
    /// Primary text.
    pub text: Color,
    /// Secondary text.
    pub muted: Color,
    /// Tertiary text, hints and placeholders.
    pub faint: Color,
    /// Text drawn on top of the accent.
    pub on_accent: Color,
    /// The accent.
    pub accent: Color,
    /// The accent, pressed/hovered.
    pub accent_hover: Color,
    /// A very light accent wash for selected rows and badges.
    pub accent_soft: Color,
    /// Positive.
    pub ok: Color,
    /// Caution.
    pub warn: Color,
    /// Destructive / error.
    pub danger: Color,
    /// The wash behind a modal dialog.
    pub scrim: Color,
}

impl Tokens {
    /// Resolve the palette for a theme.
    pub fn of(theme: &Theme) -> Self {
        if theme.extended_palette().is_dark {
            Self::dark()
        } else {
            Self::light()
        }
    }

    /// The light palette: white canvas, soft grey rails, one violet accent.
    pub const fn light() -> Self {
        Self {
            is_dark: false,
            canvas: Color::from_rgb(1.0, 1.0, 1.0),
            panel: Color::from_rgb(0.9686, 0.9725, 0.9804), // #F7F8FA
            sunken: Color::from_rgb(0.9451, 0.9529, 0.9647), // #F1F3F6
            hover: Color::from_rgb(0.9333, 0.9412, 0.9569),  // #EEF0F4
            selected: Color::from_rgb(0.9333, 0.9176, 1.0),  // #EEE AFF
            border: Color::from_rgb(0.8902, 0.9020, 0.9216), // #E3E6EB
            border_strong: Color::from_rgb(0.8157, 0.8314, 0.8627),
            field_border: Color::from_rgb(0.7255, 0.7529, 0.8078), // #B9C0CE
            text: Color::from_rgb(0.0784, 0.0863, 0.1098),   // #14161C
            muted: Color::from_rgb(0.4196, 0.4510, 0.5137),  // #6B7383
            faint: Color::from_rgb(0.6039, 0.6392, 0.6941),  // #9AA3B1
            on_accent: Color::WHITE,
            accent: ACCENT,
            accent_hover: Color::from_rgb(0.357, 0.290, 0.910),
            accent_soft: Color::from_rgb(0.9333, 0.9176, 1.0),
            ok: Color::from_rgb(0.1804, 0.6392, 0.4196), // #2EA36B
            warn: Color::from_rgb(0.8510, 0.5569, 0.1216),
            danger: Color::from_rgb(0.8392, 0.2706, 0.2275), // #D64539
            scrim: Color { a: 0.42, ..Color::from_rgb(0.05, 0.05, 0.08) },
        }
    }

    /// The dark palette, for `system` on a dark desktop or an explicit choice.
    pub const fn dark() -> Self {
        Self {
            is_dark: true,
            canvas: Color::from_rgb(0.1098, 0.1059, 0.1333), // #1C1B22
            panel: Color::from_rgb(0.0863, 0.0824, 0.1098),  // #16151C
            sunken: Color::from_rgb(0.1333, 0.1294, 0.1647), // #22212A
            hover: Color::from_rgb(0.1569, 0.1529, 0.1922),
            selected: Color::from_rgb(0.1922, 0.1765, 0.2941),
            border: Color::from_rgb(0.2000, 0.1961, 0.2431),
            border_strong: Color::from_rgb(0.2706, 0.2667, 0.3216),
            field_border: Color::from_rgb(0.3255, 0.3294, 0.3961), // #535464
            text: Color::from_rgb(0.9176, 0.9255, 0.9451),
            muted: Color::from_rgb(0.6118, 0.6392, 0.7000),
            faint: Color::from_rgb(0.4314, 0.4588, 0.5216),
            on_accent: Color::WHITE,
            accent: Color::from_rgb(0.5451, 0.4863, 1.0),
            accent_hover: Color::from_rgb(0.6196, 0.5686, 1.0),
            accent_soft: Color::from_rgb(0.1922, 0.1804, 0.3137),
            ok: Color::from_rgb(0.3176, 0.7529, 0.5373),
            warn: Color::from_rgb(0.9059, 0.6588, 0.2784),
            danger: Color::from_rgb(0.9020, 0.4157, 0.3765),
            scrim: Color { a: 0.60, ..Color::BLACK },
        }
    }


    /// A washing background for a status pill of the given tone.
    pub fn wash(&self, tone: Color) -> Color {
        Color { a: 0.14, ..tone }
    }
}

/// Build the light [`Theme`].
pub fn light_theme() -> Theme {
    Theme::custom(
        "AuraPass Light".to_string(),
        Palette {
            background: Color::WHITE,
            text: Color::from_rgb(0.0784, 0.0863, 0.1098),
            primary: ACCENT,
            success: Color::from_rgb(0.1804, 0.6392, 0.4196),
            warning: Color::from_rgb(0.8510, 0.5569, 0.1216),
            danger: Color::from_rgb(0.8392, 0.2706, 0.2275),
        },
    )
}

/// Build the dark [`Theme`].
pub fn dark_theme() -> Theme {
    Theme::custom(
        "AuraPass Dark".to_string(),
        Palette {
            background: Color::from_rgb(0.1098, 0.1059, 0.1333),
            text: Color::from_rgb(0.9176, 0.9255, 0.9451),
            primary: Color::from_rgb(0.5451, 0.4863, 1.0),
            success: Color::from_rgb(0.3176, 0.7529, 0.5373),
            warning: Color::from_rgb(0.9059, 0.6588, 0.2784),
            danger: Color::from_rgb(0.9020, 0.4157, 0.3765),
        },
    )
}

// ------------------------------------------------------------------- styles

/// A raised surface: dialogs, detail cards.
pub fn card(t: &Theme) -> container::Style {
    let k = Tokens::of(t);
    container::Style {
        background: Some(k.canvas.into()),
        border: Border {
            color: k.border,
            width: 1.0,
            radius: R_LG.into(),
        },
        shadow: Shadow {
            color: Color {
                a: if k.is_dark { 0.45 } else { 0.10 },
                ..Color::BLACK
            },
            offset: Vector::new(0.0, 8.0),
            blur_radius: 26.0,
        },
        ..container::Style::default()
    }
}

/// An inset well: the detail pane's field boxes, read-only values.
pub fn well(t: &Theme) -> container::Style {
    let k = Tokens::of(t);
    container::Style {
        background: Some(k.panel.into()),
        border: Border {
            color: k.border,
            width: 1.0,
            radius: R_SM.into(),
        },
        ..container::Style::default()
    }
}

/// The style of a text input.
pub fn input(t: &Theme, status: text_input::Status) -> text_input::Style {
    let k = Tokens::of(t);
    let focused = matches!(status, text_input::Status::Focused { .. });
    text_input::Style {
        background: k.canvas.into(),
        border: Border {
            color: if focused { k.accent } else { k.field_border },
            width: 1.0,
            radius: R_SM.into(),
        },
        icon: k.muted,
        placeholder: k.faint,
        value: k.text,
        selection: k.accent_soft,
    }
}

/// A text input that sits inside a grey well.
pub fn input_soft(t: &Theme, status: text_input::Status) -> text_input::Style {
    let k = Tokens::of(t);
    let focused = matches!(status, text_input::Status::Focused { .. });
    text_input::Style {
        background: k.sunken.into(),
        border: Border {
            color: if focused { k.accent } else { k.field_border },
            width: 1.0,
            radius: R_MD.into(),
        },
        icon: k.muted,
        placeholder: k.faint,
        value: k.text,
        selection: k.accent_soft,
    }
}

/// The filled violet call-to-action.
pub fn primary(t: &Theme, status: button::Status) -> button::Style {
    let k = Tokens::of(t);
    button::Style {
        background: Some(
            (match status {
                button::Status::Hovered | button::Status::Pressed => k.accent_hover,
                button::Status::Disabled => Color { a: 0.45, ..k.accent },
                button::Status::Active => k.accent,
            })
            .into(),
        ),
        text_color: k.on_accent,
        border: Border::default().rounded(R_SM),
        shadow: Shadow {
            color: Color { a: 0.20, ..k.accent },
            offset: Vector::new(0.0, 1.0),
            blur_radius: 3.0,
        },
        snap: true,
    }
}

/// A quiet button: bordered, canvas-coloured.
pub fn secondary(t: &Theme, status: button::Status) -> button::Style {
    let k = Tokens::of(t);
    button::Style {
        background: Some(
            (match status {
                button::Status::Hovered => k.hover,
                button::Status::Pressed => k.sunken,
                button::Status::Disabled => Color { a: 0.5, ..k.canvas },
                button::Status::Active => k.canvas,
            })
            .into(),
        ),
        text_color: k.text,
        border: Border {
            color: k.border_strong,
            width: 1.0,
            radius: R_SM.into(),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

/// A destructive button.
pub fn destructive(t: &Theme, status: button::Status) -> button::Style {
    let k = Tokens::of(t);
    let base = if matches!(status, button::Status::Hovered | button::Status::Pressed) {
        k.danger
    } else {
        k.danger
    };
    button::Style {
        background: Some(Color { a: if matches!(status, button::Status::Hovered) { 1.0 } else { 0.92 }, ..base }.into()),
        text_color: Color::WHITE,
        border: Border::default().rounded(R_SM),
        shadow: Shadow::default(),
        snap: true,
    }
}

/// A button with no chrome at all — icon buttons in list rows and headers.
pub fn bare(t: &Theme, status: button::Status) -> button::Style {
    let k = Tokens::of(t);
    button::Style {
        background: match status {
            button::Status::Hovered | button::Status::Pressed => Some(k.hover.into()),
            button::Status::Disabled => None,
            button::Status::Active => None,
        },
        text_color: k.muted,
        border: Border::default().rounded(R_SM),
        shadow: Shadow::default(),
        snap: true,
    }
}

/// A navigation-rail entry.
pub fn nav(t: &Theme, status: button::Status, active: bool) -> button::Style {
    let k = Tokens::of(t);
    button::Style {
        background: Some(
            (if active {
                k.selected
            } else if matches!(status, button::Status::Hovered | button::Status::Pressed) {
                k.hover
            } else {
                Color::TRANSPARENT
            })
            .into(),
        ),
        text_color: if active { k.accent } else { k.text },
        border: Border::default().rounded(R_MD),
        shadow: Shadow::default(),
        snap: true,
    }
}

/// A row in the middle item list.
pub fn row(t: &Theme, status: button::Status, active: bool) -> button::Style {
    let k = Tokens::of(t);
    button::Style {
        background: Some(
            (if active {
                k.accent_soft
            } else if matches!(status, button::Status::Hovered | button::Status::Pressed) {
                k.hover
            } else {
                Color::TRANSPARENT
            })
            .into(),
        ),
        text_color: k.text,
        border: Border::default().rounded(R_MD),
        shadow: Shadow::default(),
        snap: true,
    }
}

/// A pill button used by the editor's kind and category pickers.
pub fn chip_button(t: &Theme, status: button::Status, active: bool) -> button::Style {
    let k = Tokens::of(t);
    button::Style {
        background: Some(
            (if active {
                k.accent
            } else if matches!(status, button::Status::Hovered | button::Status::Pressed) {
                k.hover
            } else {
                k.sunken
            })
            .into(),
        ),
        text_color: if active { k.on_accent } else { k.text },
        border: Border {
            color: if active { k.accent } else { k.border },
            width: 1.0,
            radius: 99.0.into(),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

/// A member of a segmented control.
pub fn segment(t: &Theme, status: button::Status, active: bool) -> button::Style {
    let k = Tokens::of(t);
    button::Style {
        background: Some(
            (if active {
                k.accent
            } else if matches!(status, button::Status::Hovered | button::Status::Pressed) {
                k.hover
            } else {
                k.sunken
            })
            .into(),
        ),
        text_color: if active { k.on_accent } else { k.text },
        border: Border::default().rounded(R_SM),
        shadow: Shadow::default(),
        snap: true,
    }
}

/// A clickable list entry that is not part of a selection.
pub fn row_plain(t: &Theme, status: button::Status) -> button::Style {
    let k = Tokens::of(t);
    button::Style {
        background: Some(
            (match status {
                button::Status::Hovered | button::Status::Pressed => k.hover,
                _ => k.sunken,
            })
            .into(),
        ),
        text_color: k.text,
        border: Border {
            color: k.border,
            width: 1.0,
            radius: R_SM.into(),
        },
        shadow: Shadow::default(),
        snap: true,
    }
}

/// The style of a dropdown selector.
pub fn pick_list(t: &Theme, status: pick_list_widget::Status) -> pick_list_widget::Style {
    let k = Tokens::of(t);
    let hot = match status {
        pick_list_widget::Status::Active => false,
        pick_list_widget::Status::Hovered | pick_list_widget::Status::Opened { .. } => true,
    };
    pick_list_widget::Style {
        text_color: k.text,
        placeholder_color: k.faint,
        handle_color: k.muted,
        background: k.canvas.into(),
        border: Border {
            color: if hot { k.accent } else { k.field_border },
            width: 1.0,
            radius: R_SM.into(),
        },
    }
}

/// The style of a dropdown's pop-up menu.
pub fn menu(t: &Theme) -> iced::overlay::menu::Style {
    let k = Tokens::of(t);
    iced::overlay::menu::Style {
        background: k.canvas.into(),
        border: Border {
            color: k.border,
            width: 1.0,
            radius: R_MD.into(),
        },
        text_color: k.text,
        selected_text_color: k.accent,
        selected_background: k.accent_soft.into(),
        shadow: Shadow {
            color: Color {
                a: if k.is_dark { 0.5 } else { 0.16 },
                ..Color::BLACK
            },
            offset: Vector::new(0.0, 6.0),
            blur_radius: 18.0,
        },
    }
}

/// A checkbox that reads as part of the design system.
pub fn checkbox(t: &Theme, status: checkbox_widget::Status) -> checkbox_widget::Style {
    let k = Tokens::of(t);
    let checked = matches!(
        status,
        checkbox_widget::Status::Active { is_checked: true } | checkbox_widget::Status::Hovered { is_checked: true }
    );
    checkbox_widget::Style {
        background: (if checked { k.accent } else { k.canvas }).into(),
        icon_color: k.on_accent,
        border: Border {
            color: if checked { k.accent } else { k.border_strong },
            width: 1.0,
            radius: 5.0.into(),
        },
        text_color: Some(k.text),
    }
}


/// A slim, track-less scrollbar: a rounded thumb that strengthens on hover.
///
/// iced's default rail paints a solid grey strip down the whole edge, which
/// reads as a seam in a white card. Hiding the rail and leaving only a soft
/// thumb keeps long lists and dialogs quiet until you actually need them.
pub fn scrollbar(t: &Theme, status: scrollable::Status) -> scrollable::Style {
    let k = Tokens::of(t);
    let alpha = match status {
        scrollable::Status::Active { .. } => 0.16,
        scrollable::Status::Hovered { .. } | scrollable::Status::Dragged { .. } => 0.30,
    };
    let rail = scrollable::Rail {
        background: None,
        border: Border::default(),
        scroller: scrollable::Scroller {
            background: Color { a: alpha, ..k.text }.into(),
            border: Border::default().rounded(4.0),
        },
    };
    scrollable::Style {
        container: container::Style::default(),
        vertical_rail: rail,
        horizontal_rail: rail,
        gap: None,
        auto_scroll: scrollable::AutoScroll {
            background: k.accent.into(),
            border: Border::default().rounded(20.0),
            shadow: Shadow {
                color: Color { a: 0.18, ..k.text },
                offset: Vector::new(0.0, 2.0),
                blur_radius: 8.0,
            },
            icon: k.on_accent,
        },
    }
}

/// Colour for a strength score, `0` (worst) to `4` (best).
pub fn score_color(score: u8) -> Color {
    match score {
        0 => Color::from_rgb(0.839, 0.271, 0.227),
        1 => Color::from_rgb(0.878, 0.518, 0.235),
        2 => Color::from_rgb(0.851, 0.557, 0.122),
        3 => Color::from_rgb(0.612, 0.788, 0.247),
        _ => Color::from_rgb(0.180, 0.639, 0.420),
    }
}

/// Replace a secret with dots unless it is being revealed.
pub fn mask(secret: &str, reveal: bool) -> String {
    if reveal {
        secret.to_string()
    } else {
        "•".repeat(secret.chars().count().clamp(6, 16))
    }
}

// Tone accessors, so callers can pass `theme::muted` where a
// `fn(&Tokens) -> Color` is wanted instead of writing a closure.

/// The accent tone.
pub fn accent(k: &Tokens) -> Color {
    k.accent
}


/// The secondary text tone.
pub fn muted(k: &Tokens) -> Color {
    k.muted
}


/// The positive tone.
pub fn ok(k: &Tokens) -> Color {
    k.ok
}

/// The caution tone.
pub fn warn(k: &Tokens) -> Color {
    k.warn
}

/// The destructive tone.
pub fn danger(k: &Tokens) -> Color {
    k.danger
}

/// The colour to draw on top of the accent.
pub fn on_accent(k: &Tokens) -> Color {
    k.on_accent
}
