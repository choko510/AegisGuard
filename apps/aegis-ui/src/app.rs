//! Application shell: navigation, header and the seven screens.
//!
//! The UI is read-only and runs as the normal user. It never starts
//! privileged processes, never parses CLI stdout, and never shows a state it
//! cannot back with data: features that do not exist yet are shown as
//! "まだ利用できません", missing data as "データなし".
use crate::status::Status;
use crate::theme::{self, Palette};
use eframe::egui::{self, Key, KeyboardShortcut, Modifiers, RichText};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Home,
    Scan,
    Browser,
    Realtime,
    Network,
    History,
    Settings,
}

impl Page {
    pub const ALL: [Page; 7] = [
        Page::Home,
        Page::Scan,
        Page::Browser,
        Page::Realtime,
        Page::Network,
        Page::History,
        Page::Settings,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Page::Home => "ホーム",
            Page::Scan => "スキャン",
            Page::Browser => "ブラウザー保護",
            Page::Realtime => "リアルタイム監視",
            Page::Network => "ネットワーク",
            Page::History => "検出履歴",
            Page::Settings => "ルール・設定",
        }
    }

    pub fn from_name(name: &str) -> Option<Page> {
        Some(match name {
            "home" => Page::Home,
            "scan" => Page::Scan,
            "browser" => Page::Browser,
            "realtime" => Page::Realtime,
            "network" => Page::Network,
            "history" => Page::History,
            "settings" => Page::Settings,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeChoice {
    Light,
    Dark,
}

/// One row of a status overview: what it is, its state and why.
pub struct StatusRow {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

pub struct AegisApp {
    pub page: Page,
    pub theme: ThemeChoice,
    applied_theme: Option<ThemeChoice>,
}

impl AegisApp {
    pub fn new(page: Page, theme: ThemeChoice) -> Self {
        Self {
            page,
            theme,
            applied_theme: None,
        }
    }

    fn dark(&self) -> bool {
        self.theme == ThemeChoice::Dark
    }

    /// Home overview. Every row says where its information would come from;
    /// without data nothing is reported as running or clean.
    pub fn home_rows(&self) -> Vec<StatusRow> {
        vec![
            StatusRow {
                name: "Microsoft Defender",
                status: Status::NoData,
                detail: "`aegisguard defender audit` の結果を読み込むと表示します（P7-02）。Defenderの代わりにはなりません。".into(),
            },
            StatusRow {
                name: "AegisGuard 常駐監視",
                status: Status::NotAvailable,
                detail: "常駐サービスは未実装です（P8）。現在は監視していません。".into(),
            },
            StatusRow {
                name: "センサー（Sysmon / イベントログ）",
                status: Status::NoData,
                detail: "収集結果が無いため、どのイベントが見えているか不明です。".into(),
            },
            StatusRow {
                name: "最終更新",
                status: Status::NoData,
                detail: "読み込んだ結果がありません。".into(),
            },
            StatusRow {
                name: "要確認の件数",
                status: Status::NoData,
                detail: "結果が無いことは「問題が無い」ことを意味しません。".into(),
            },
        ]
    }

    pub fn browser_rows(&self) -> Vec<StatusRow> {
        vec![
            StatusRow {
                name: "Chrome：k2f既知痕跡",
                status: Status::NoData,
                detail: "CLI `aegisguard browser k2f` で確認できます。GUIからの実行は未対応です。"
                    .into(),
            },
            StatusRow {
                name: "Chrome/Edge：DLL・COM乗っ取りの相関",
                status: Status::NoData,
                detail:
                    "Sysmon ID 7/11/13 の収集が必要です（`events correlate` の AG-B001〜005）。"
                        .into(),
            },
            StatusRow {
                name: "認証情報ファイルの読み取り",
                status: Status::NotAvailable,
                detail: "読み取り監査（P6-04）は未実装です。FIMでは読み取りは見えません。".into(),
            },
            StatusRow {
                name: "Brave / Firefox 固有の確認",
                status: Status::NotAvailable,
                detail: "ブラウザー別の確認（P6-05）は未実装です。".into(),
            },
        ]
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let keys = [
            Key::Num1,
            Key::Num2,
            Key::Num3,
            Key::Num4,
            Key::Num5,
            Key::Num6,
            Key::Num7,
        ];
        for (key, page) in keys.into_iter().zip(Page::ALL) {
            if ctx.input_mut(|i| i.consume_shortcut(&KeyboardShortcut::new(Modifiers::CTRL, key))) {
                self.page = page;
            }
        }
    }

    pub fn draw(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if self.applied_theme != Some(self.theme) {
            theme::apply(&ctx, self.dark());
            self.applied_theme = Some(self.theme);
        }
        self.shortcuts(&ctx);
        let p = *theme::palette(self.dark());

        egui::Panel::top("header")
            .frame(
                egui::Frame::new()
                    .fill(p.surface)
                    .inner_margin(egui::Margin::symmetric(
                        theme::SPACE_L as i8,
                        theme::SPACE_M as i8,
                    )),
            )
            .show(ui, |ui| self.header(ui, &p));
        egui::Panel::bottom("footer")
            .frame(
                egui::Frame::new()
                    .fill(p.surface_alt)
                    .inner_margin(egui::Margin::symmetric(theme::SPACE_L as i8, theme::SPACE_S as i8)),
            )
            .show(ui, |ui| {
                ui.label(
                    RichText::new(
                        "読み取り専用の監査ツールです。何も削除・遮断せず、OSやDefenderの設定を変更しません。結果が無いことは安全の証明ではありません。",
                    )
                    .small()
                    .color(p.text_muted),
                );
            });
        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(theme::NAV_WIDTH)
            .frame(
                egui::Frame::new()
                    .fill(p.surface)
                    .inner_margin(egui::Margin::same(theme::SPACE_M as i8)),
            )
            .show(ui, |ui| self.nav(ui, &p));
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(p.bg)
                    .inner_margin(egui::Margin::same(theme::SPACE_L as i8)),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.page_body(ui, &p));
            });
    }

    fn header(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("AegisGuard").heading().strong());
            badge(ui, p, "読み取り専用", Status::NotAvailable.tone());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = match self.theme {
                    ThemeChoice::Light => "ダークに切替",
                    ThemeChoice::Dark => "ライトに切替",
                };
                if ui.button(label).clicked() {
                    self.theme = match self.theme {
                        ThemeChoice::Light => ThemeChoice::Dark,
                        ThemeChoice::Dark => ThemeChoice::Light,
                    };
                }
            });
        });
    }

    fn nav(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.label(RichText::new("メニュー").small().color(p.text_muted));
        ui.add_space(theme::SPACE_S);
        for (i, page) in Page::ALL.into_iter().enumerate() {
            let selected = self.page == page;
            let text = RichText::new(format!("{}  {}", page.title(), i + 1));
            let response = ui
                .add_sized(
                    [ui.available_width(), 32.0],
                    egui::Button::selectable(selected, text),
                )
                .on_hover_text(format!("Ctrl+{}", i + 1));
            if response.clicked() {
                self.page = page;
            }
        }
    }

    fn page_body(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.label(RichText::new(self.page.title()).heading().strong());
        ui.add_space(theme::SPACE_S);
        match self.page {
            Page::Home => {
                intro(ui, p, "各項目は自分の情報源から確認できた範囲だけを表示します。確認できない項目を「正常」として表示することはありません。");
                status_list(ui, p, &self.home_rows());
            }
            Page::Scan => {
                intro(ui, p, "ファイルを実行せずに静的に検査します。");
                status_list(
                    ui,
                    p,
                    &[StatusRow {
                        name: "GUIからのスキャン実行",
                        status: Status::NotAvailable,
                        detail: "CLI `aegisguard scan <パス> --recursive --output scan.jsonl` を使ってください。結果の読み込みは次の段階（P7-02）で対応します。".into(),
                    }],
                );
            }
            Page::Browser => {
                intro(ui, p, "ブラウザー領域へのDLL配置・COM登録の変更・ブラウザーによる読込みを、観測できた範囲で確認します。ファイルやレジストリを削除・変更しません。");
                status_list(ui, p, &self.browser_rows());
            }
            Page::Realtime => {
                intro(ui, p, "常駐サービスとリアルタイム相関は未実装です。");
                status_list(
                    ui,
                    p,
                    &[StatusRow {
                        name: "リアルタイム監視",
                        status: Status::NotAvailable,
                        detail: "現在はCLIでの単発収集とオフライン相関のみです（P8で常駐化予定）。"
                            .into(),
                    }],
                );
            }
            Page::Network => {
                intro(ui, p, "C2 IOCとの照合は、収集済みのSysmonイベントとローカルのIOCキャッシュに対して行います。通信の遮断はしません。");
                status_list(
                    ui,
                    p,
                    &[
                        StatusRow {
                            name: "C2 IOCキャッシュ",
                            status: Status::NoData,
                            detail: "`aegisguard c2 status` の結果を読み込むと鮮度を表示します（P7-02）。".into(),
                        },
                        StatusRow {
                            name: "通信のライブ監査",
                            status: Status::NotAvailable,
                            detail: "常駐サービス（P8）の後に対応します。".into(),
                        },
                    ],
                );
            }
            Page::History => {
                intro(ui, p, "保存済みの結果（JSONL）から検出の履歴を表示します。");
                status_list(
                    ui,
                    p,
                    &[StatusRow {
                        name: "検出履歴",
                        status: Status::NoData,
                        detail: "まだ結果を読み込んでいません。".into(),
                    }],
                );
            }
            Page::Settings => {
                intro(
                    ui,
                    p,
                    "表示の設定です。ルールの更新・署名鍵の設定はまだGUIから行えません。",
                );
                ui.horizontal(|ui| {
                    ui.label("テーマ：");
                    ui.radio_value(&mut self.theme, ThemeChoice::Light, "ライト");
                    ui.radio_value(&mut self.theme, ThemeChoice::Dark, "ダーク");
                });
                ui.add_space(theme::SPACE_M);
                status_list(
                    ui,
                    p,
                    &[StatusRow {
                        name: "ルールパック",
                        status: Status::NoData,
                        detail: "`aegisguard rules status` の結果の表示は P7-02 で対応します。"
                            .into(),
                    }],
                );
            }
        }
    }
}

fn intro(ui: &mut egui::Ui, p: &Palette, text: &str) {
    ui.label(RichText::new(text).color(p.text_muted));
    ui.add_space(theme::SPACE_M);
}

pub fn badge(ui: &mut egui::Ui, p: &Palette, text: &str, tone: crate::status::Tone) {
    let (fg, bg) = p.tone(tone);
    egui::Frame::new()
        .fill(bg)
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).small().color(fg));
        });
}

/// Status chip: glyph + text label + tone color (never color alone).
pub fn status_chip(ui: &mut egui::Ui, p: &Palette, status: Status) {
    badge(
        ui,
        p,
        &format!("{} {}", status.glyph(), status.label()),
        status.tone(),
    );
}

fn status_list(ui: &mut egui::Ui, p: &Palette, rows: &[StatusRow]) {
    for row in rows {
        theme::card_frame(p).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(row.name).strong());
                status_chip(ui, p, row.status);
            });
            ui.add(egui::Label::new(RichText::new(&row.detail).color(p.text_muted)).wrap());
        });
        ui.add_space(theme::SPACE_S);
    }
}

impl eframe::App for AegisApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::FORBIDDEN_CLAIMS;

    /// Render a page headlessly at a given size and DPI scale.
    fn render(page: Page, theme: ThemeChoice, size: [f32; 2], scale: f32) -> Vec<String> {
        let ctx = egui::Context::default();
        crate::fonts::install(&ctx);
        ctx.set_pixels_per_point(scale);
        let mut app = AegisApp::new(page, theme);
        let input = || egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size.into())),
            ..Default::default()
        };
        let mut texts = Vec::new();
        for _ in 0..3 {
            let mut out = ctx.run_ui(input(), |ui| app.draw(ui));
            out.textures_delta.clear();
            texts = out
                .shapes
                .iter()
                .filter_map(|s| match &s.shape {
                    egui::epaint::Shape::Text(t) => Some(t.galley.text().to_string()),
                    _ => None,
                })
                .collect();
        }
        texts
    }

    #[test]
    fn every_page_renders_at_small_and_large_sizes_without_claiming_safety() {
        for page in Page::ALL {
            for theme in [ThemeChoice::Light, ThemeChoice::Dark] {
                for (size, scale) in [
                    ([640.0, 480.0], 1.0),
                    ([1280.0, 800.0], 1.5),
                    ([2560.0, 1440.0], 2.5),
                ] {
                    let texts = render(page, theme, size, scale);
                    let all = texts.join("\n");
                    assert!(all.contains(page.title()), "{page:?} title missing");
                    for word in FORBIDDEN_CLAIMS {
                        assert!(!all.contains(word), "{page:?} shows {word}");
                    }
                }
            }
        }
    }

    #[test]
    fn home_never_reports_monitoring_or_data_it_does_not_have() {
        let app = AegisApp::new(Page::Home, ThemeChoice::Light);
        let rows = app.home_rows();
        assert!(rows
            .iter()
            .all(|r| matches!(r.status, Status::NoData | Status::NotAvailable)));
        let service = rows.iter().find(|r| r.name.contains("常駐")).unwrap();
        assert_eq!(service.status, Status::NotAvailable);
    }

    #[test]
    fn keyboard_shortcuts_switch_pages() {
        let ctx = egui::Context::default();
        let mut app = AegisApp::new(Page::Home, ThemeChoice::Light);
        let input = egui::RawInput {
            events: vec![egui::Event::Key {
                key: Key::Num3,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Modifiers::CTRL,
            }],
            ..Default::default()
        };
        ctx.run_ui(input, |ui| app.draw(ui)).textures_delta.clear();
        assert_eq!(app.page, Page::Browser);
    }

    #[test]
    fn page_names_round_trip() {
        for (name, page) in [
            ("home", Page::Home),
            ("browser", Page::Browser),
            ("settings", Page::Settings),
        ] {
            assert_eq!(Page::from_name(name), Some(page));
        }
        assert_eq!(Page::from_name("nope"), None);
    }
}
