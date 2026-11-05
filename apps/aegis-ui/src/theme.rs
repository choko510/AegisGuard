//! Design tokens: colors, spacing and text styles for light and dark mode.
use crate::status::Tone;
use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Visuals};

pub const SPACE_S: f32 = 6.0;
pub const SPACE_M: f32 = 12.0;
pub const SPACE_L: f32 = 20.0;
pub const RADIUS: u8 = 8;
pub const NAV_WIDTH: f32 = 208.0;

/// Colors for one theme. Tone colors were chosen to keep at least 4.5:1
/// contrast for text on the matching background.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub bg: Color32,
    pub surface: Color32,
    pub surface_alt: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text_muted: Color32,
    pub accent: Color32,
    pub neutral: (Color32, Color32),
    pub info: (Color32, Color32),
    pub good: (Color32, Color32),
    pub caution: (Color32, Color32),
    pub danger: (Color32, Color32),
}

pub const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(0xF4, 0xF6, 0xF8),
    surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    surface_alt: Color32::from_rgb(0xEC, 0xEF, 0xF3),
    border: Color32::from_rgb(0xD5, 0xDA, 0xE1),
    text: Color32::from_rgb(0x1B, 0x21, 0x2B),
    text_muted: Color32::from_rgb(0x4F, 0x5A, 0x69),
    accent: Color32::from_rgb(0x1F, 0x5F, 0xBF),
    // (foreground, background)
    neutral: (
        Color32::from_rgb(0x3D, 0x47, 0x55),
        Color32::from_rgb(0xE6, 0xE9, 0xED),
    ),
    info: (
        Color32::from_rgb(0x15, 0x4E, 0x9E),
        Color32::from_rgb(0xE0, 0xEC, 0xFB),
    ),
    good: (
        Color32::from_rgb(0x1E, 0x6B, 0x3A),
        Color32::from_rgb(0xE1, 0xF3, 0xE6),
    ),
    caution: (
        Color32::from_rgb(0x8A, 0x4B, 0x00),
        Color32::from_rgb(0xFD, 0xF0, 0xD9),
    ),
    danger: (
        Color32::from_rgb(0xA1, 0x1E, 0x1E),
        Color32::from_rgb(0xFB, 0xE4, 0xE4),
    ),
};

pub const DARK: Palette = Palette {
    bg: Color32::from_rgb(0x12, 0x15, 0x1B),
    surface: Color32::from_rgb(0x1C, 0x21, 0x29),
    surface_alt: Color32::from_rgb(0x25, 0x2B, 0x35),
    border: Color32::from_rgb(0x34, 0x3C, 0x48),
    text: Color32::from_rgb(0xE8, 0xEC, 0xF1),
    text_muted: Color32::from_rgb(0xA9, 0xB3, 0xC1),
    accent: Color32::from_rgb(0x7F, 0xB0, 0xFF),
    neutral: (
        Color32::from_rgb(0xC9, 0xD0, 0xDA),
        Color32::from_rgb(0x2C, 0x33, 0x3E),
    ),
    info: (
        Color32::from_rgb(0x9C, 0xC5, 0xFF),
        Color32::from_rgb(0x1B, 0x2C, 0x46),
    ),
    good: (
        Color32::from_rgb(0x8F, 0xD9, 0xA6),
        Color32::from_rgb(0x17, 0x33, 0x22),
    ),
    caution: (
        Color32::from_rgb(0xF5, 0xC2, 0x6B),
        Color32::from_rgb(0x3A, 0x2B, 0x10),
    ),
    danger: (
        Color32::from_rgb(0xFF, 0x9E, 0x9E),
        Color32::from_rgb(0x45, 0x1A, 0x1A),
    ),
};

pub fn palette(dark: bool) -> &'static Palette {
    if dark {
        &DARK
    } else {
        &LIGHT
    }
}

impl Palette {
    /// (foreground, background) for a tone.
    pub fn tone(&self, tone: Tone) -> (Color32, Color32) {
        match tone {
            Tone::Neutral => self.neutral,
            Tone::Info => self.info,
            Tone::Good => self.good,
            Tone::Caution => self.caution,
            Tone::Danger => self.danger,
        }
    }
}

/// Apply the design system to an egui context.
pub fn apply(ctx: &egui::Context, dark: bool) {
    let p = palette(dark);
    let mut visuals = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    visuals.panel_fill = p.bg;
    visuals.window_fill = p.surface;
    visuals.extreme_bg_color = p.surface_alt;
    visuals.faint_bg_color = p.surface_alt;
    visuals.override_text_color = Some(p.text);
    visuals.hyperlink_color = p.accent;
    visuals.selection.bg_fill = p.accent.gamma_multiply(0.35);
    visuals.selection.stroke = Stroke::new(1.0, p.accent);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    for w in [
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
    ] {
        w.corner_radius = CornerRadius::same(6);
    }
    // A clearly visible keyboard focus ring.
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.5, p.accent);
    let theme = if dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    };
    // Fixed theme: following the OS theme would swap in unstyled visuals.
    ctx.set_theme(theme);
    ctx.set_visuals_of(theme, visuals);

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        style.text_styles = [
            (
                TextStyle::Heading,
                FontId::new(24.0, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(15.0, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(15.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Small,
                FontId::new(12.5, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(13.5, FontFamily::Monospace),
            ),
        ]
        .into();
    });
}

pub fn card_frame(p: &Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(egui::Margin::same(SPACE_M as i8))
}
