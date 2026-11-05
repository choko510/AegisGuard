//! Fluent controls drawn with egui: NavigationView item, InfoBar,
//! SettingsCard, status badge, accent button and section header.
use crate::status::Status;
use crate::theme::{self, Palette};
use eframe::egui::{
    self, Align2, Color32, CornerRadius, FontId, Response, RichText, Role, Sense, Stroke,
    StrokeKind, Vec2, WidgetInfo,
};

pub fn icon_text(glyph: &str, size: f32, color: Color32) -> RichText {
    RichText::new(glyph)
        .font(FontId::new(size, theme::icons()))
        .color(color)
}

/// NavigationView menu item: 36px tall, subtle fill on hover/selection, accent
/// selection pill on the left, icon at 16px and label at 48px.
pub fn nav_item(
    ui: &mut egui::Ui,
    p: &Palette,
    glyph: &str,
    label: &str,
    selected: bool,
    compact: bool,
) -> Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 36.0), Sense::click());
    response.widget_info(|| WidgetInfo::selected(Role::Tab, true, selected, label));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let body = rect.shrink2(Vec2::new(0.0, 2.0));
        let fill = if response.is_pointer_button_down_on() {
            Some(p.subtle_pressed)
        } else if selected || response.hovered() {
            Some(p.subtle_hover)
        } else {
            None
        };
        if let Some(fill) = fill {
            painter.rect_filled(body, CornerRadius::same(theme::CONTROL_RADIUS), fill);
        }
        if selected {
            let pill = egui::Rect::from_center_size(
                egui::pos2(body.left() + 1.5, body.center().y),
                Vec2::new(3.0, 16.0),
            );
            painter.rect_filled(pill, CornerRadius::same(2), p.accent);
        }
        if response.has_focus() {
            painter.rect_stroke(
                body,
                CornerRadius::same(theme::CONTROL_RADIUS),
                Stroke::new(2.0, p.text),
                StrokeKind::Inside,
            );
        }
        let icon_x = if compact {
            body.center().x
        } else {
            body.left() + 16.0 + 8.0
        };
        painter.text(
            egui::pos2(icon_x, body.center().y),
            Align2::CENTER_CENTER,
            glyph,
            FontId::new(theme::ICON, theme::icons()),
            p.text,
        );
        if !compact {
            painter.text(
                egui::pos2(body.left() + 48.0, body.center().y),
                Align2::LEFT_CENTER,
                label,
                FontId::new(theme::BODY, egui::FontFamily::Proportional),
                p.text,
            );
        }
    }
    if compact {
        response.on_hover_text(label)
    } else {
        response
    }
}

/// Status badge: severity-colored icon + text label (never color alone).
pub fn status_badge(ui: &mut egui::Ui, p: &Palette, status: Status) {
    let (fg, _) = p.tone(status.tone());
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.label(icon_text(status.icon(), 14.0, fg));
        ui.label(RichText::new(status.label()).color(p.text));
    });
}

/// InfoBar: severity background, icon, bold title and message.
pub fn info_bar(ui: &mut egui::Ui, p: &Palette, status: Status, title: &str, message: &str) {
    let (fg, bg) = p.tone(status.tone());
    egui::Frame::new()
        .fill(bg)
        .stroke(Stroke::new(1.0, p.card_stroke))
        .corner_radius(CornerRadius::same(theme::CONTROL_RADIUS))
        .inner_margin(egui::Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.label(icon_text(status.icon(), theme::ICON, fg));
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).font(theme::body_strong()));
                    ui.add(egui::Label::new(RichText::new(message).color(p.text)).wrap());
                });
            });
        });
}

/// Section header (BodyStrong) with Fluent spacing above.
pub fn section(ui: &mut egui::Ui, text: &str) {
    ui.add_space(theme::S24 - 8.0);
    ui.label(RichText::new(text).font(theme::body_strong()));
    ui.add_space(theme::S4);
}

/// SettingsCard: header icon, title, description, and status on the right
/// (below the text on narrow windows).
pub fn settings_card(
    ui: &mut egui::Ui,
    p: &Palette,
    glyph: &str,
    title: &str,
    description: &str,
    status: Option<Status>,
) {
    theme::card(p).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.set_min_height(44.0);
        let narrow = ui.available_width() < 560.0;
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            ui.label(icon_text(glyph, 20.0, p.text));
            ui.add_space(theme::S12);
            let status_width = if narrow || status.is_none() {
                0.0
            } else {
                200.0
            };
            let text_width = (ui.available_width() - status_width).max(120.0);
            ui.vertical(|ui| {
                ui.set_width(text_width);
                ui.label(RichText::new(title).color(p.text));
                ui.add(
                    egui::Label::new(
                        RichText::new(description)
                            .size(theme::CAPTION)
                            .color(p.text_secondary),
                    )
                    .wrap(),
                );
                if narrow {
                    if let Some(s) = status {
                        status_badge(ui, p, s);
                    }
                }
            });
            if !narrow {
                if let Some(s) = status {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        status_badge(ui, p, s);
                    });
                }
            }
        });
    });
    ui.add_space(theme::S4);
}

/// Accent (primary) button.
pub fn accent_button(ui: &mut egui::Ui, p: &Palette, label: &str, enabled: bool) -> Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(label).color(p.on_accent))
            .fill(p.accent)
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::same(theme::CONTROL_RADIUS))
            .min_size(Vec2::new(96.0, 32.0)),
    )
}

/// Standard button.
pub fn button(ui: &mut egui::Ui, label: &str) -> Response {
    ui.add(egui::Button::new(label).min_size(Vec2::new(80.0, 32.0)))
}
