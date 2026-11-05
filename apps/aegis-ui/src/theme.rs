//! Fluent Design (Windows 11 / Fluent 2) tokens for egui.
//!
//! Colors follow the WinUI 3 theme resources (`SolidBackgroundFillColorBase`,
//! `LayerFillColorDefault`, `CardBackgroundFillColorDefault`, the text fill
//! colors and the `SystemFillColor*` severity pairs used by InfoBar), with
//! translucent values pre-composited onto their usual backgrounds because egui
//! has no Mica/Acrylic material. The accent comes from the user's Windows
//! accent palette when it can be read, otherwise the Windows default blue.
//! Type ramp, corner radii (4 for controls and cards, 8 for overlays and
//! layers) and the 4px spacing grid follow the Windows design guidance.
use crate::status::Tone;
use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Theme, Visuals,
};

// --- spacing (4px grid) ---
pub const S4: f32 = 4.0;
pub const S8: f32 = 8.0;
pub const S12: f32 = 12.0;
pub const S16: f32 = 16.0;
pub const S24: f32 = 24.0;
pub const S36: f32 = 36.0;
/// ControlCornerRadius (buttons, text boxes, cards in lists).
pub const CONTROL_RADIUS: u8 = 4;
/// OverlayCornerRadius (layers, dialogs, tiles).
pub const OVERLAY_RADIUS: u8 = 8;
/// NavigationView pane widths (expanded / compact).
pub const PANE_OPEN: f32 = 280.0;
pub const PANE_COMPACT: f32 = 52.0;
/// Below this window width the pane collapses to icons only.
pub const COMPACT_BELOW: f32 = 860.0;
/// Readable maximum width of page content.
pub const CONTENT_MAX: f32 = 1000.0;

// --- type ramp (size, family) ---
pub const CAPTION: f32 = 12.0;
pub const BODY: f32 = 14.0;
pub const SUBTITLE: f32 = 20.0;
pub const TITLE: f32 = 28.0;
pub const ICON: f32 = 16.0;
pub const ICON_LARGE: f32 = 24.0;

pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn icons() -> FontFamily {
    FontFamily::Name("icons".into())
}

/// Subtitle font (20, semibold).
pub fn subtitle() -> FontId {
    FontId::new(SUBTITLE, semibold())
}

/// BodyStrong font (14, semibold).
pub fn body_strong() -> FontId {
    FontId::new(BODY, semibold())
}

pub fn subtitle_style() -> TextStyle {
    TextStyle::Name("Subtitle".into())
}

pub fn body_strong_style() -> TextStyle {
    TextStyle::Name("BodyStrong".into())
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    pub dark: bool,
    /// SolidBackgroundFillColorBase: window / navigation pane (Mica fallback).
    pub base: Color32,
    /// LayerFillColorDefault over base: the content area.
    pub layer: Color32,
    /// CardBackgroundFillColorDefault over layer.
    pub card: Color32,
    /// CardStrokeColorDefault.
    pub card_stroke: Color32,
    /// DividerStrokeColorDefault.
    pub divider: Color32,
    /// SubtleFillColorSecondary / Tertiary (hover / pressed).
    pub subtle_hover: Color32,
    pub subtle_pressed: Color32,
    /// ControlFillColorDefault and ControlStrokeColorDefault.
    pub control: Color32,
    pub control_hover: Color32,
    pub control_stroke: Color32,
    /// TextFillColorPrimary / Secondary / Tertiary.
    pub text: Color32,
    pub text_secondary: Color32,
    pub text_tertiary: Color32,
    /// AccentFillColorDefault, its text, and AccentTextFillColorPrimary.
    pub accent: Color32,
    pub on_accent: Color32,
    pub accent_text: Color32,
    /// InfoBar severity pairs: (icon/foreground, background).
    pub attention: (Color32, Color32),
    pub success: (Color32, Color32),
    pub caution: (Color32, Color32),
    pub critical: (Color32, Color32),
    pub neutral: (Color32, Color32),
}

const DEFAULT_ACCENT_LIGHT: Color32 = Color32::from_rgb(0x00, 0x5F, 0xB8);
const DEFAULT_ACCENT_DARK: Color32 = Color32::from_rgb(0x60, 0xCD, 0xFF);
const DEFAULT_ACCENT_TEXT_LIGHT: Color32 = Color32::from_rgb(0x00, 0x3E, 0x92);
const DEFAULT_ACCENT_TEXT_DARK: Color32 = Color32::from_rgb(0x99, 0xEB, 0xFF);

/// The user's accent palette: (light-theme fill, light-theme text,
/// dark-theme fill, dark-theme text), as Windows derives them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Accent {
    pub light_fill: Color32,
    pub light_text: Color32,
    pub dark_fill: Color32,
    pub dark_text: Color32,
}

impl Default for Accent {
    fn default() -> Self {
        Self {
            light_fill: DEFAULT_ACCENT_LIGHT,
            light_text: DEFAULT_ACCENT_TEXT_LIGHT,
            dark_fill: DEFAULT_ACCENT_DARK,
            dark_text: DEFAULT_ACCENT_TEXT_DARK,
        }
    }
}

impl Accent {
    /// `AccentPalette` is 8 RGBA entries: Light3, Light2, Light1, Accent,
    /// Dark1, Dark2, Dark3, unused. Light theme uses Dark1 (fill) and Dark2
    /// (text); dark theme uses Light2 (fill) and Light3 (text).
    pub fn from_palette(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 28 {
            return None;
        }
        let c = |i: usize| Color32::from_rgb(bytes[i * 4], bytes[i * 4 + 1], bytes[i * 4 + 2]);
        Some(Self {
            light_fill: c(4),
            light_text: c(5),
            dark_fill: c(1),
            dark_text: c(0),
        })
    }

    /// Read the accent palette from the registry (read-only), if available.
    pub fn system() -> Self {
        read_accent_palette()
            .and_then(|b| Self::from_palette(&b))
            .unwrap_or_default()
    }
}

#[cfg(windows)]
fn read_accent_palette() -> Option<Vec<u8>> {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_BINARY,
    };
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Explorer\Accent");
    let name = wide("AccentPalette");
    let mut buf = [0u8; 64];
    let mut len = buf.len() as u32;
    // SAFETY: key/name are NUL-terminated; buf has `len` bytes of space.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_BINARY,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    (status == 0).then(|| buf[..(len as usize).min(buf.len())].to_vec())
}

#[cfg(not(windows))]
fn read_accent_palette() -> Option<Vec<u8>> {
    None
}

/// Accessible text color on an accent fill (WCAG relative luminance).
fn on(fill: Color32) -> Color32 {
    let lin = |c: u8| {
        let c = f32::from(c) / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    let l = 0.2126 * lin(fill.r()) + 0.7152 * lin(fill.g()) + 0.0722 * lin(fill.b());
    // Pick whichever of black and white contrasts more with the fill.
    if (l + 0.05) / 0.05 > 1.05 / (l + 0.05) {
        Color32::BLACK
    } else {
        Color32::WHITE
    }
}

pub fn palette(dark: bool, accent: &Accent) -> Palette {
    let rgb = Color32::from_rgb;
    if dark {
        Palette {
            dark,
            base: rgb(0x20, 0x20, 0x20),
            layer: rgb(0x28, 0x28, 0x28),
            card: rgb(0x2D, 0x2D, 0x2D),
            card_stroke: rgb(0x1C, 0x1C, 0x1C),
            divider: rgb(0x38, 0x38, 0x38),
            subtle_hover: rgb(0x2D, 0x2D, 0x2D),
            subtle_pressed: rgb(0x29, 0x29, 0x29),
            control: rgb(0x2D, 0x2D, 0x2D),
            control_hover: rgb(0x32, 0x32, 0x32),
            control_stroke: rgb(0x3A, 0x3A, 0x3A),
            text: rgb(0xFF, 0xFF, 0xFF),
            text_secondary: rgb(0xC8, 0xC8, 0xC8),
            text_tertiary: rgb(0x9E, 0x9E, 0x9E),
            accent: accent.dark_fill,
            on_accent: on(accent.dark_fill),
            accent_text: accent.dark_text,
            attention: (accent.dark_fill, rgb(0x26, 0x26, 0x26)),
            success: (rgb(0x6C, 0xCB, 0x5F), rgb(0x39, 0x3D, 0x1B)),
            caution: (rgb(0xFC, 0xE1, 0x00), rgb(0x43, 0x35, 0x19)),
            critical: (rgb(0xFF, 0x99, 0xA4), rgb(0x44, 0x27, 0x26)),
            neutral: (rgb(0x9D, 0x9D, 0x9D), rgb(0x2E, 0x2E, 0x2E)),
        }
    } else {
        Palette {
            dark,
            base: rgb(0xF3, 0xF3, 0xF3),
            layer: rgb(0xF9, 0xF9, 0xF9),
            card: rgb(0xFE, 0xFE, 0xFE),
            card_stroke: rgb(0xE5, 0xE5, 0xE5),
            divider: rgb(0xEA, 0xEA, 0xEA),
            subtle_hover: rgb(0xEA, 0xEA, 0xEA),
            subtle_pressed: rgb(0xED, 0xED, 0xED),
            control: rgb(0xFB, 0xFB, 0xFB),
            control_hover: rgb(0xF6, 0xF6, 0xF6),
            control_stroke: rgb(0xE0, 0xE0, 0xE0),
            text: rgb(0x1A, 0x1A, 0x1A),
            text_secondary: rgb(0x5D, 0x5D, 0x5D),
            text_tertiary: rgb(0x8B, 0x8B, 0x8B),
            accent: accent.light_fill,
            on_accent: on(accent.light_fill),
            accent_text: accent.light_text,
            attention: (accent.light_fill, rgb(0xF7, 0xF7, 0xF7)),
            success: (rgb(0x0F, 0x7B, 0x0F), rgb(0xDF, 0xF6, 0xDD)),
            caution: (rgb(0x9D, 0x5D, 0x00), rgb(0xFF, 0xF4, 0xCE)),
            critical: (rgb(0xC4, 0x2B, 0x1C), rgb(0xFD, 0xE7, 0xE9)),
            neutral: (rgb(0x8A, 0x8A, 0x8A), rgb(0xF3, 0xF3, 0xF3)),
        }
    }
}

impl Palette {
    /// (icon/foreground, background) for an InfoBar severity.
    pub fn tone(&self, tone: Tone) -> (Color32, Color32) {
        match tone {
            Tone::Neutral => self.neutral,
            Tone::Info => self.attention,
            Tone::Good => self.success,
            Tone::Caution => self.caution,
            Tone::Danger => self.critical,
        }
    }
}

fn visuals(p: &Palette) -> Visuals {
    let mut v = if p.dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    let r = CornerRadius::same(CONTROL_RADIUS);
    v.panel_fill = p.base;
    v.window_fill = p.card;
    v.window_stroke = Stroke::new(1.0, p.card_stroke);
    v.window_corner_radius = CornerRadius::same(OVERLAY_RADIUS);
    v.extreme_bg_color = p.control;
    v.faint_bg_color = p.layer;
    v.code_bg_color = p.control;
    v.override_text_color = Some(p.text);
    v.hyperlink_color = p.accent_text;
    v.selection.bg_fill = p.accent.gamma_multiply(0.4);
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.widgets.noninteractive.bg_fill = p.card;
    v.widgets.noninteractive.weak_bg_fill = p.card;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.divider);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.noninteractive.corner_radius = r;
    let states = [
        (&mut v.widgets.inactive, p.control, p.control_stroke),
        (&mut v.widgets.hovered, p.control_hover, p.control_stroke),
        (&mut v.widgets.active, p.subtle_pressed, p.control_stroke),
        (&mut v.widgets.open, p.control_hover, p.control_stroke),
    ];
    for (w, fill, stroke) in states {
        w.bg_fill = fill;
        w.weak_bg_fill = fill;
        w.bg_stroke = Stroke::new(1.0, stroke);
        w.fg_stroke = Stroke::new(1.0, p.text);
        w.corner_radius = r;
        w.expansion = 0.0;
    }
    // Keyboard focus and hover keep a visible accent outline.
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.text_tertiary);
    v.widgets.active.bg_stroke = Stroke::new(2.0, p.accent);
    v.text_cursor.stroke = Stroke::new(2.0, p.accent);
    v
}

/// Install Fluent visuals and the type ramp for both themes; the theme
/// follows Windows unless the user picked one.
pub fn apply(ctx: &egui::Context, accent: &Accent, preference: egui::ThemePreference) {
    ctx.set_visuals_of(Theme::Light, visuals(&palette(false, accent)));
    ctx.set_visuals_of(Theme::Dark, visuals(&palette(true, accent)));
    ctx.set_theme(preference);
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(S8, S8);
        style.spacing.button_padding = egui::vec2(S12, 5.0);
        style.spacing.interact_size.y = 32.0;
        style.spacing.icon_width = 20.0;
        // Fluent scroll bars overlay the content (they never take layout
        // width, so showing one cannot reflow the page).
        style.spacing.scroll = egui::style::ScrollStyle::floating();
        style.text_styles = [
            (
                TextStyle::Small,
                FontId::new(CAPTION, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(BODY, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(BODY, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(13.0, FontFamily::Monospace),
            ),
            (TextStyle::Heading, FontId::new(TITLE, semibold())),
            (subtitle_style(), FontId::new(SUBTITLE, semibold())),
            (body_strong_style(), FontId::new(BODY, semibold())),
        ]
        .into();
    });
}

/// SettingsCard-style container.
pub fn card(p: &Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.card_stroke))
        .corner_radius(CornerRadius::same(CONTROL_RADIUS))
        .inner_margin(egui::Margin::symmetric(S16 as i8, S12 as i8))
}

/// Tile on the home page (overlay radius).
pub fn tile(p: &Palette) -> egui::Frame {
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.card_stroke))
        .corner_radius(CornerRadius::same(OVERLAY_RADIUS))
        .inner_margin(egui::Margin::same(S16 as i8))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contrast(a: Color32, b: Color32) -> f32 {
        let lum = |c: Color32| {
            let lin = |v: u8| {
                let v = f32::from(v) / 255.0;
                if v <= 0.03928 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * lin(c.r()) + 0.7152 * lin(c.g()) + 0.0722 * lin(c.b())
        };
        let (x, y) = (lum(a), lum(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn text_meets_wcag_contrast_on_every_surface() {
        for dark in [false, true] {
            let p = palette(dark, &Accent::default());
            for bg in [p.base, p.layer, p.card] {
                assert!(contrast(p.text, bg) >= 7.0, "dark={dark}");
                assert!(contrast(p.text_secondary, bg) >= 4.5, "dark={dark}");
            }
            for (fg, bg) in [p.success, p.caution, p.critical] {
                // Severity icons are paired with text; 3:1 for graphics.
                assert!(contrast(fg, bg) >= 3.0, "dark={dark}");
            }
            assert!(contrast(p.on_accent, p.accent) >= 4.5, "dark={dark}");
        }
    }

    #[test]
    fn accent_palette_is_parsed_or_defaults() {
        let mut bytes = vec![0u8; 32];
        for i in 0..8 {
            bytes[i * 4] = i as u8 * 30;
        }
        let a = Accent::from_palette(&bytes).unwrap();
        assert_eq!(a.light_fill.r(), 120);
        assert_eq!(a.dark_fill.r(), 30);
        assert!(Accent::from_palette(&[0; 8]).is_none());
        // Whatever the system accent is, text on it stays readable.
        let p = palette(false, &Accent::system());
        assert!(contrast(p.on_accent, p.accent) >= 4.5);
    }
}
