//! The icon set.
//!
//! Every icon in the app comes from Lucide (ISC licence), shipped inside the
//! `iced_fonts` crate as a font. Using one consistent, pixel-crisp outline set
//! instead of homemade vector art is what makes the chrome read as a single
//! design rather than a pile of parts.

use iced::widget::{text, Text};
use iced::{Color, Renderer, Theme};

use aurapass_core::ItemKind;

use crate::theme::{self, Tokens};

/// The Lucide icon font, loaded at start-up.
pub use iced_fonts::LUCIDE_FONT_BYTES;

/// A named icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glyph {
    // ------------------------------------------------ item kinds
    Login,
    Password,
    Note,
    Card,
    Bank,
    Identity,
    Ssh,
    Api,
    Wifi,
    License,
    Database,
    Server,
    Custom,
    // ------------------------------------------------ chrome
    Brand,
    Search,
    Plus,
    Star,
    Trash,
    Restore,
    Edit,
    Copy,
    Eye,
    EyeOff,
    Lock,
    Gear,
    Shield,
    ShieldCheck,
    ShieldAlert,
    Folder,
    Globe,
    Warning,
    Check,
    Close,
    Import,
    Export,
    Grid,
    External,
    Key,
    Users,
    History,
    Gauge,
    QrCode,
    Sliders,
    Sparkle,
    ChevronRight,
    Minus,
    Info,
    CircleCheck,
    CircleAlert,
    Sun,
    Moon,
    Monitor,
    Download,
    HardDrive,
    Duplicate,
}

impl Glyph {
    /// The icon that represents a kind of vault item.
    pub fn of_kind(kind: ItemKind) -> Self {
        match kind {
            ItemKind::Login => Self::Login,
            ItemKind::Password => Self::Password,
            ItemKind::SecureNote => Self::Note,
            ItemKind::CreditCard => Self::Card,
            ItemKind::BankAccount => Self::Bank,
            ItemKind::Identity => Self::Identity,
            ItemKind::SshKey => Self::Ssh,
            ItemKind::ApiKey => Self::Api,
            ItemKind::Wifi => Self::Wifi,
            ItemKind::SoftwareLicense => Self::License,
            ItemKind::Database => Self::Database,
            ItemKind::Server => Self::Server,
            ItemKind::Custom => Self::Custom,
        }
    }

    /// The bare Lucide text widget for this glyph.
    fn raw(self) -> Text<'static, Theme, Renderer> {
        match self {
            Self::Login => iced_fonts::lucide::log_in(),
            Self::Password => iced_fonts::lucide::key(),
            Self::Note => iced_fonts::lucide::file_text(),
            Self::Card => iced_fonts::lucide::credit_card(),
            Self::Bank => iced_fonts::lucide::banknote(),
            Self::Identity => iced_fonts::lucide::user(),
            Self::Ssh => iced_fonts::lucide::terminal(),
            Self::Api => iced_fonts::lucide::code(),
            Self::Wifi => iced_fonts::lucide::wifi(),
            Self::License => iced_fonts::lucide::ticket(),
            Self::Database => iced_fonts::lucide::database(),
            Self::Server => iced_fonts::lucide::server(),
            Self::Custom => iced_fonts::lucide::package(),
            Self::Brand => iced_fonts::lucide::shield_check(),
            Self::Search => iced_fonts::lucide::search(),
            Self::Plus => iced_fonts::lucide::plus(),
            Self::Star => iced_fonts::lucide::star(),
            Self::Trash => iced_fonts::lucide::trash_two(),
            Self::Restore => iced_fonts::lucide::rotate_ccw(),
            Self::Edit => iced_fonts::lucide::pen_line(),
            Self::Copy => iced_fonts::lucide::copy(),
            Self::Eye => iced_fonts::lucide::eye(),
            Self::EyeOff => iced_fonts::lucide::eye_off(),
            Self::Lock => iced_fonts::lucide::lock(),
            Self::Gear => iced_fonts::lucide::settings(),
            Self::Shield => iced_fonts::lucide::shield(),
            Self::ShieldCheck => iced_fonts::lucide::shield_check(),
            Self::ShieldAlert => iced_fonts::lucide::shield_alert(),
            Self::Folder => iced_fonts::lucide::folder(),
            Self::Globe => iced_fonts::lucide::globe(),
            Self::Warning => iced_fonts::lucide::triangle_alert(),
            Self::Check => iced_fonts::lucide::check(),
            Self::Close => iced_fonts::lucide::x(),
            Self::Import => iced_fonts::lucide::import(),
            Self::Export => iced_fonts::lucide::upload(),
            Self::Grid => iced_fonts::lucide::layout_grid(),
            Self::External => iced_fonts::lucide::external_link(),
            Self::Key => iced_fonts::lucide::key(),
            Self::Users => iced_fonts::lucide::users(),
            Self::History => iced_fonts::lucide::history(),
            Self::Gauge => iced_fonts::lucide::gauge(),
            Self::QrCode => iced_fonts::lucide::qr_code(),
            Self::Sliders => iced_fonts::lucide::sliders_vertical(),
            Self::Sparkle => iced_fonts::lucide::zap(),
            Self::ChevronRight => iced_fonts::lucide::chevron_right(),
            Self::Minus => iced_fonts::lucide::minus(),
            Self::Info => iced_fonts::lucide::info(),
            Self::CircleCheck => iced_fonts::lucide::circle_check(),
            Self::CircleAlert => iced_fonts::lucide::circle_alert(),
            Self::Sun => iced_fonts::lucide::sun(),
            Self::Moon => iced_fonts::lucide::moon(),
            Self::Monitor => iced_fonts::lucide::monitor(),
            Self::Download => iced_fonts::lucide::download(),
            Self::HardDrive => iced_fonts::lucide::hard_drive(),
            Self::Duplicate => iced_fonts::lucide::copy(),
        }
    }
}

/// An icon, drawn at `size` in the chrome colour of the active theme.
pub fn icon(glyph: Glyph, size: f32) -> Text<'static, Theme, Renderer> {
    glyph
        .raw()
        .size(size)
        .font(theme::ICON)
        .style(|t: &Theme| text::Style {
            color: Some(Tokens::of(t).muted),
        })
}

/// An icon tinted from the active palette.
///
/// The `tone` closure receives the resolved tokens so the icon follows light
/// and dark mode without the caller knowing which is in use.
pub fn tinted(
    glyph: Glyph,
    size: f32,
    tone: fn(&Tokens) -> Color,
) -> Text<'static, Theme, Renderer> {
    glyph
        .raw()
        .size(size)
        .font(theme::ICON)
        .style(move |t: &Theme| text::Style {
            color: Some(tone(&Tokens::of(t))),
        })
}

/// An icon in an explicit colour, for tones that are already resolved.
pub fn colored(glyph: Glyph, size: f32, color: Color) -> Text<'static, Theme, Renderer> {
    glyph.raw().size(size).color(color).font(theme::ICON)
}
