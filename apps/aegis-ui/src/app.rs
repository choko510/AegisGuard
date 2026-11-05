//! Application shell in Fluent Design: NavigationView (left pane on the
//! Mica-style base), a rounded content layer, page title, SettingsCards,
//! InfoBars and tiles.
//!
//! The UI is read-only and runs as the normal user. It never starts
//! privileged processes and never parses CLI stdout: saved results are read
//! through `aegisguard::api` on a worker thread (see `data`). Features that do
//! not exist yet are shown as "まだ利用できません", missing data as "データなし".
use crate::data::{self, Dataset, Job, Update};
use crate::fluent::{self, icon_text};
use crate::status::{icon, Status};
use crate::theme::{self, Accent, Palette};
use crate::views::{self, StatusRow};
use aegisguard::api::DocumentKind;
use eframe::egui::{
    self, CornerRadius, Key, KeyboardShortcut, Modifiers, RichText, Stroke, ThemePreference, Vec2,
};
use serde_json::Value;
use std::path::PathBuf;

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
            Page::Settings => "設定",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Page::Home => icon::HOME,
            Page::Scan => icon::SCAN,
            Page::Browser => icon::BROWSER,
            Page::Realtime => icon::REALTIME,
            Page::Network => icon::NETWORK,
            Page::History => icon::HISTORY,
            Page::Settings => icon::SETTINGS,
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

/// App theme: follows Windows by default, like Fluent apps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeChoice {
    System,
    Light,
    Dark,
}

impl ThemeChoice {
    fn preference(self) -> ThemePreference {
        match self {
            ThemeChoice::System => ThemePreference::System,
            ThemeChoice::Light => ThemePreference::Light,
            ThemeChoice::Dark => ThemePreference::Dark,
        }
    }

    fn label(self) -> &'static str {
        match self {
            ThemeChoice::System => "Windows の設定に合わせる",
            ThemeChoice::Light => "ライト",
            ThemeChoice::Dark => "ダーク",
        }
    }
}

/// Longest text shown in a list cell before eliding.
const MAX_CELL_CHARS: usize = 120;
const ROW_HEIGHT: f32 = 40.0;

/// Keep the end (file name) of a long string.
pub fn elide(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let tail: Vec<char> = text.chars().rev().take(max.saturating_sub(1)).collect();
    let tail: String = tail.into_iter().rev().collect();
    format!("…{tail}")
}

pub struct AegisApp {
    pub page: Page,
    pub theme: ThemeChoice,
    accent: Accent,
    applied: Option<ThemeChoice>,
    pub data: Dataset,
    job: Option<Job>,
    path_input: String,
    last_load_note: Option<String>,
    /// Scan list filter: hide rows where nothing was found.
    attention_only: bool,
}

impl AegisApp {
    pub fn new(page: Page, theme: ThemeChoice) -> Self {
        Self {
            page,
            theme,
            accent: Accent::system(),
            applied: None,
            data: Dataset::default(),
            job: None,
            path_input: String::new(),
            last_load_note: None,
            attention_only: false,
        }
    }

    /// Start loading files in the background (ignored while a job runs).
    pub fn load(&mut self, ctx: &egui::Context, paths: Vec<PathBuf>) {
        if self.job.is_some() || paths.is_empty() {
            return;
        }
        let repaint = ctx.clone();
        self.job = Some(data::start(paths, move || repaint.request_repaint()));
    }

    /// Load synchronously (used for `--open` before the first frame and tests).
    pub fn load_now(&mut self, paths: &[PathBuf]) {
        let cancel = std::sync::atomic::AtomicBool::new(false);
        for p in paths {
            self.data.absorb(data::load_file(p, &cancel));
        }
    }

    fn poll_job(&mut self) {
        let Some(job) = self.job.as_mut() else {
            return;
        };
        let mut finished = None;
        while let Ok(update) = job.rx.try_recv() {
            match update {
                Update::Progress {
                    done,
                    total,
                    current,
                } => {
                    job.done = done;
                    job.total = total;
                    job.current = Some(current);
                }
                Update::Finished(set, cancelled) => finished = Some((set, cancelled)),
            }
        }
        if let Some((set, cancelled)) = finished {
            let errors = set.errors.len();
            self.data.absorb(set);
            self.last_load_note = Some(if cancelled {
                "読み込みを中止しました。途中までの結果だけが表示されています。".into()
            } else if errors > 0 {
                format!("読み込み完了（{errors} 件のファイルに問題があります）")
            } else {
                "読み込み完了".into()
            });
            self.job = None;
        }
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

    pub fn palette(&self, ctx: &egui::Context) -> Palette {
        theme::palette(ctx.theme() == egui::Theme::Dark, &self.accent)
    }

    pub fn draw(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if self.applied != Some(self.theme) {
            theme::apply(&ctx, &self.accent, self.theme.preference());
            self.applied = Some(self.theme);
        }
        self.poll_job();
        self.shortcuts(&ctx);
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .filter(|p| !p.as_os_str().is_empty())
                .collect()
        });
        if !dropped.is_empty() {
            self.load(&ctx, dropped);
        }
        let p = self.palette(&ctx);
        let compact = ui.max_rect().width() < theme::COMPACT_BELOW;

        egui::Panel::left("navigation")
            .resizable(false)
            .show_separator_line(false)
            .exact_size(if compact {
                theme::PANE_COMPACT
            } else {
                theme::PANE_OPEN
            })
            .frame(
                egui::Frame::new()
                    .fill(p.base)
                    .inner_margin(egui::Margin::symmetric(4, 8)),
            )
            .show(ui, |ui| self.navigation(ui, &p, compact));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(p.base).inner_margin(egui::Margin {
                left: 0,
                right: 0,
                top: 8,
                bottom: 0,
            }))
            .show(ui, |ui| {
                // The content layer: rounded top-left corner, card stroke.
                egui::Frame::new()
                    .fill(p.layer)
                    .stroke(Stroke::new(1.0, p.card_stroke))
                    .corner_radius(CornerRadius {
                        nw: theme::OVERLAY_RADIUS,
                        ne: 0,
                        sw: 0,
                        se: 0,
                    })
                    .inner_margin(egui::Margin {
                        left: theme::S36 as i8,
                        right: theme::S36 as i8,
                        top: 28,
                        bottom: 0,
                    })
                    .show(ui, |ui| {
                        ui.set_min_size(ui.available_size());
                        self.page_frame(ui, &p);
                    });
            });
    }

    fn navigation(&mut self, ui: &mut egui::Ui, p: &Palette, compact: bool) {
        // Pane header: app identity.
        ui.horizontal(|ui| {
            ui.set_min_height(40.0);
            ui.add_space(if compact { 12.0 } else { 14.0 });
            ui.label(icon_text(icon::SHIELD, 18.0, p.accent));
            if !compact {
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.add_space(2.0);
                    ui.label(RichText::new("AegisGuard").font(theme::body_strong()));
                    ui.label(
                        RichText::new("読み取り専用の監査")
                            .size(theme::CAPTION)
                            .color(p.text_secondary),
                    );
                });
            }
        });
        ui.add_space(theme::S8);
        ui.spacing_mut().item_spacing.y = 0.0;
        let main = &Page::ALL[..Page::ALL.len() - 1];
        for (i, page) in main.iter().enumerate() {
            let r = fluent::nav_item(
                ui,
                p,
                page.icon(),
                page.title(),
                self.page == *page,
                compact,
            )
            .on_hover_text(format!("Ctrl+{}", i + 1));
            if r.clicked() {
                self.page = *page;
            }
        }
        // Settings sits in the pane footer, as in NavigationView.
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.add_space(theme::S4);
            let s = Page::Settings;
            if fluent::nav_item(ui, p, s.icon(), s.title(), self.page == s, compact)
                .on_hover_text("Ctrl+7")
                .clicked()
            {
                self.page = s;
            }
            ui.add_space(theme::S4);
            let (rect, _) =
                ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), egui::Sense::hover());
            ui.painter()
                .rect_filled(rect.shrink2(Vec2::new(8.0, 0.0)), 0.0, p.divider);
        });
    }

    fn page_frame(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.label(RichText::new(self.page.title()).heading());
        ui.add_space(theme::S16);
        match self.page {
            // Lists that virtualize their own scrolling.
            Page::Scan | Page::History => {
                let width = ui.available_width().min(theme::CONTENT_MAX);
                ui.allocate_ui(Vec2::new(width, ui.available_height()), |ui| {
                    if self.page == Page::Scan {
                        self.scan_page(ui, p);
                    } else {
                        self.history_page(ui, p);
                    }
                });
            }
            _ => {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let width = ui.available_width().min(theme::CONTENT_MAX);
                        ui.allocate_ui(Vec2::new(width, 0.0), |ui| {
                            ui.set_width(width);
                            self.page_body(ui, p);
                            ui.add_space(theme::S36);
                        });
                    });
            }
        }
    }

    fn page_body(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let now = views::now();
        match self.page {
            Page::Home => self.home_page(ui, p, now),
            Page::Browser => {
                fluent::info_bar(
                    ui,
                    p,
                    Status::Observed,
                    "観測できた範囲の確認です",
                    "ブラウザー領域へのDLL配置・COM登録の変更・ブラウザーによる読込みを、収集済みのイベントから確認します。ファイルやレジストリを削除・変更しません。",
                );
                fluent::section(ui, "確認項目");
                let icons = [icon::BROWSER, icon::SENSOR, icon::LOCK, icon::BROWSER];
                rows(ui, p, &views::browser_rows(&self.data, now), &icons);
                fluent::section(ui, "タイムライン");
                self.timelines(ui, p);
            }
            Page::Realtime => {
                fluent::settings_card(
                    ui,
                    p,
                    icon::REALTIME,
                    "リアルタイム監視",
                    "常駐サービスとリアルタイム相関は未実装です。現在はCLIでの単発収集とオフライン相関のみで、監視は行っていません（P8で常駐化予定）。",
                    Some(Status::NotAvailable),
                );
            }
            Page::Network => {
                fluent::info_bar(
                    ui,
                    p,
                    Status::Observed,
                    "通信は遮断しません",
                    "C2 IOCとの照合は、収集済みのSysmonイベントとローカルのIOCキャッシュに対して行います。",
                );
                fluent::section(ui, "状態");
                let icons = [icon::RULES, icon::NETWORK, icon::REALTIME];
                rows(ui, p, &views::network_rows(&self.data, now), &icons);
            }
            Page::Settings => self.settings_page(ui, p, now),
            Page::Scan | Page::History => {}
        }
    }

    fn home_page(&mut self, ui: &mut egui::Ui, p: &Palette, now: u64) {
        fluent::info_bar(
            ui,
            p,
            Status::Observed,
            "読み取り専用の監査ツールです",
            "何も削除・遮断せず、OSやMicrosoft Defenderの設定を変更しません。結果が無いことは安全の証明ではありません。",
        );
        fluent::section(ui, "概要");
        let tiles = views::home_rows(&self.data, now);
        let icons = [
            icon::SHIELD,
            icon::REALTIME,
            icon::SENSOR,
            icon::CLOCK,
            icon::HISTORY,
        ];
        let gap = theme::S8;
        let width = ui.available_width();
        let columns = ((width + gap) / (232.0 + gap)).floor().clamp(1.0, 3.0) as usize;
        let tile_width = (width - gap * (columns as f32 - 1.0)) / columns as f32;
        for chunk in tiles.iter().zip(icons).collect::<Vec<_>>().chunks(columns) {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = gap;
                for (row, glyph) in chunk {
                    ui.allocate_ui(Vec2::new(tile_width, 0.0), |ui| {
                        theme::tile(p).show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.set_width(tile_width - 34.0);
                                ui.set_min_height(172.0);
                                let (fg, _) = p.tone(row.status.tone());
                                ui.horizontal(|ui| {
                                    ui.label(icon_text(glyph, theme::ICON_LARGE, p.text));
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(icon_text(row.status.icon(), theme::ICON, fg));
                                        },
                                    );
                                });
                                ui.add_space(theme::S8);
                                ui.label(RichText::new(&row.name).font(theme::body_strong()));
                                ui.label(RichText::new(row.status.label()).color(fg));
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&row.detail)
                                            .size(theme::CAPTION)
                                            .color(p.text_secondary),
                                    )
                                    .wrap(),
                                );
                            })
                        });
                    });
                }
            });
            ui.add_space(gap);
        }
        fluent::section(ui, "結果を開く");
        self.loader(ui, p);
    }

    fn settings_page(&mut self, ui: &mut egui::Ui, p: &Palette, now: u64) {
        fluent::section(ui, "外観");
        theme::card(p).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                ui.label(icon_text("\u{E790}", 20.0, p.text));
                ui.add_space(theme::S12);
                ui.vertical(|ui| {
                    ui.label("アプリのテーマ");
                    ui.label(
                        RichText::new("表示するアプリのテーマを選択します")
                            .size(theme::CAPTION)
                            .color(p.text_secondary),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::ComboBox::from_id_salt("theme")
                        .selected_text(self.theme.label())
                        .width(220.0)
                        .show_ui(ui, |ui| {
                            for t in [ThemeChoice::System, ThemeChoice::Light, ThemeChoice::Dark] {
                                ui.selectable_value(&mut self.theme, t, t.label());
                            }
                        });
                });
            });
        });
        ui.add_space(theme::S4);
        fluent::section(ui, "ルール");
        rows(ui, p, &[views::rules_row(&self.data, now)], &[icon::RULES]);
        fluent::settings_card(
            ui,
            p,
            icon::LOCK,
            "ルールの更新・署名鍵",
            "GUIからのルール更新・署名鍵の設定はまだ利用できません（CLI `aegisguard rules`）。",
            Some(Status::NotAvailable),
        );
        fluent::section(ui, "このアプリについて");
        fluent::settings_card(
            ui,
            p,
            icon::INFO,
            &format!("AegisGuard {}", env!("CARGO_PKG_VERSION")),
            "通常ユーザー権限で動く読み取り専用のUIです。Microsoft Defenderの代わりにはなりません。フォントはWindowsのもの（Yu Gothic UI・Segoe UI Variable・Segoe Fluent Icons）を使い、同梱していません。",
            None,
        );
    }

    /// File loading card: path box, accent "開く" button, drag and drop,
    /// progress ring and cancel.
    fn loader(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::card(p).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                ui.label(icon_text(icon::OPEN_FILE, 20.0, p.text));
                ui.add_space(theme::S12);
                ui.vertical(|ui| {
                    ui.label("保存済みの結果を開く");
                    ui.add(
                        egui::Label::new(
                            RichText::new("CLIで保存したJSON/JSONL（scan, defender audit, c2 status, events correlate/iocs/timeline, browser k2f, rules status）のパスを入力するか、ウィンドウにドラッグ＆ドロップします。")
                                .size(theme::CAPTION)
                                .color(p.text_secondary),
                        )
                        .wrap(),
                    );
                });
            });
            ui.add_space(theme::S8);
            ui.horizontal(|ui| {
                let busy = self.job.is_some();
                let edit = ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut self.path_input)
                        .hint_text(r"C:\path\to\scan.jsonl")
                        .min_size(Vec2::new(0.0, 32.0))
                        .align(egui::Align2::LEFT_CENTER)
                        .desired_width((ui.available_width() - 112.0).max(120.0)),
                );
                let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if (fluent::accent_button(ui, p, "開く", !busy).clicked() || enter)
                    && !self.path_input.trim().is_empty()
                {
                    let path = PathBuf::from(self.path_input.trim().trim_matches('"'));
                    let ctx = ui.ctx().clone();
                    self.load(&ctx, vec![path]);
                }
            });
            if let Some(job) = &self.job {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().color(p.accent));
                    ui.label(format!(
                        "読み込み中 {}/{}：{}",
                        job.done + 1,
                        job.total,
                        job.current
                            .as_ref()
                            .map(|c| elide(&c.display().to_string(), 60))
                            .unwrap_or_default()
                    ));
                    if fluent::button(ui, "中止").clicked() {
                        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                });
            } else if let Some(note) = &self.last_load_note {
                ui.label(RichText::new(note).size(theme::CAPTION).color(p.text_secondary));
            }
        });
        ui.add_space(theme::S4);
        for e in self.data.errors.iter().rev().take(5) {
            fluent::info_bar(
                ui,
                p,
                Status::Incomplete,
                &elide(&e.path.display().to_string(), 80),
                &e.reason,
            );
            ui.add_space(theme::S4);
        }
    }

    fn scan_page(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let c = views::scan_counts(&self.data);
        if self.data.scans.is_empty() {
            fluent::settings_card(
                ui,
                p,
                icon::SCAN,
                "スキャン結果",
                "まだ結果を読み込んでいません。GUIからのスキャン実行はまだ利用できません（CLI `aegisguard scan <パス> --recursive --output scan.jsonl`）。",
                Some(Status::NoData),
            );
            self.loader(ui, p);
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("{} 件", c.total)).font(theme::subtitle()));
            ui.add_space(theme::S16);
            for (status, n) in [
                (Status::High, c.high),
                (Status::Review, c.review),
                (Status::Incomplete, c.incomplete + c.not_assessed),
                (Status::Stopped, c.stopped_runs),
            ] {
                if status == Status::Stopped && n == 0 {
                    continue;
                }
                fluent::status_badge(ui, p, status);
                ui.label(RichText::new(n.to_string()).font(theme::body_strong()));
                ui.add_space(theme::S12);
            }
            ui.checkbox(&mut self.attention_only, "該当なし以外だけ表示");
        });
        for f in self.data.scan_files.iter().filter(|f| !f.complete()) {
            ui.add_space(theme::S4);
            fluent::info_bar(
                ui,
                p,
                Status::Incomplete,
                &elide(&f.path.display().to_string(), 80),
                &format!(
                    "読み込んだ {} 件、読めない行 {}、新しい形式 {}、打切り {}",
                    f.records,
                    f.problems,
                    f.newer_schema,
                    f.truncated.map_or("なし".to_string(), |t| format!("{t:?}"))
                ),
            );
        }
        ui.add_space(theme::S12);
        let rows: Vec<usize> = self
            .data
            .scans
            .iter()
            .enumerate()
            .filter(|(_, r)| !self.attention_only || !r.nothing_found())
            .map(|(i, _)| i)
            .collect();
        // ListView in a card: header + virtualized rows.
        theme::card(p)
            .inner_margin(egui::Margin::symmetric(4, 4))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    for (label, w) in [
                        ("状態", 170.0),
                        ("種別", 56.0),
                        ("シグナル", 220.0),
                        ("パス", 0.0),
                    ] {
                        let text = RichText::new(label)
                            .size(theme::CAPTION)
                            .color(p.text_secondary);
                        if w > 0.0 {
                            ui.add_sized([w, 24.0], egui::Label::new(text));
                        } else {
                            ui.label(text);
                        }
                    }
                });
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show_rows(ui, ROW_HEIGHT, rows.len(), |ui, range| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        for &i in &rows[range] {
                            let r = &self.data.scans[i];
                            let (rect, resp) = ui.allocate_exact_size(
                                Vec2::new(ui.available_width(), ROW_HEIGHT),
                                egui::Sense::hover(),
                            );
                            if resp.hovered() {
                                ui.painter().rect_filled(
                                    rect,
                                    CornerRadius::same(theme::CONTROL_RADIUS),
                                    p.subtle_hover,
                                );
                            }
                            let mut row_ui = ui.new_child(
                                egui::UiBuilder::new()
                                    .max_rect(rect.shrink2(Vec2::new(12.0, 0.0)))
                                    .layout(egui::Layout::left_to_right(egui::Align::Center)),
                            );
                            let status = scan_status(r);
                            row_ui.allocate_ui(Vec2::new(170.0, ROW_HEIGHT), |ui| {
                                ui.set_width(170.0);
                                fluent::status_badge(ui, p, status);
                            });
                            row_ui.add_sized(
                                [56.0, ROW_HEIGHT],
                                egui::Label::new(
                                    RichText::new(r.kind.as_str())
                                        .size(theme::CAPTION)
                                        .color(p.text_secondary),
                                ),
                            );
                            let codes: Vec<&str> =
                                r.signals.iter().map(|s| s.code.as_str()).take(2).collect();
                            row_ui.add_sized(
                                [220.0, ROW_HEIGHT],
                                egui::Label::new(
                                    RichText::new(codes.join(", "))
                                        .size(theme::CAPTION)
                                        .color(p.text_secondary),
                                )
                                .truncate(),
                            );
                            let char_width = theme::BODY * 0.55;
                            let fit = (row_ui.available_width() / char_width) as usize;
                            row_ui
                                .add(
                                    egui::Label::new(elide(&r.path, fit.clamp(16, MAX_CELL_CHARS)))
                                        .truncate(),
                                )
                                .on_hover_text(elide(&r.path, 2000));
                        }
                    });
            });
    }

    fn history_page(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let findings: Vec<&Value> = self
            .data
            .documents
            .iter()
            .filter(|d| d.kind == DocumentKind::Correlation)
            .filter_map(|d| d.value["correlation"]["findings"].as_array())
            .flatten()
            .collect();
        let have_docs = self
            .data
            .documents
            .iter()
            .any(|d| d.kind == DocumentKind::Correlation);
        if !have_docs {
            fluent::settings_card(
                ui,
                p,
                icon::HISTORY,
                "検出履歴",
                "`events correlate` の結果をまだ読み込んでいません。ホームから開けます。",
                Some(Status::NoData),
            );
            return;
        }
        fluent::info_bar(
            ui,
            p,
            Status::Observed,
            &format!("所見 {} 件", findings.len()),
            "所見は確認のための根拠で、悪性の判定ではありません。評価できなかったルールはブラウザー保護・ホームに表示します。",
        );
        ui.add_space(theme::S12);
        if findings.is_empty() {
            fluent::settings_card(
                ui,
                p,
                icon::HISTORY,
                "所見なし",
                "評価できたルールの範囲で所見はありません。",
                Some(Status::NothingFound),
            );
            return;
        }
        let row_height = 60.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, findings.len(), |ui, range| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for f in &findings[range] {
                    let status = match (f["verdict"].as_str(), f["suppressed_reason"].is_null()) {
                        (Some("review"), true) => Status::Review,
                        (Some("review"), false) | (Some("observed"), _) => Status::Observed,
                        _ => Status::Incomplete,
                    };
                    let missing = f["missing_sources"]
                        .as_array()
                        .map(|m| {
                            m.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    let detail = format!(
                        "{}{}{}",
                        f["explanation"].as_str().unwrap_or(""),
                        if missing.is_empty() {
                            String::new()
                        } else {
                            format!("　見えていない情報源: {missing}")
                        },
                        f["suppressed_reason"]
                            .as_str()
                            .map(|s| format!("　抑制: {s}"))
                            .unwrap_or_default()
                    );
                    let (rect, _) = ui.allocate_exact_size(
                        Vec2::new(ui.available_width(), row_height),
                        egui::Sense::hover(),
                    );
                    let mut row = ui.new_child(
                        egui::UiBuilder::new().max_rect(rect.shrink2(Vec2::new(0.0, 2.0))),
                    );
                    theme::card(p).show(&mut row, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let (fg, _) = p.tone(status.tone());
                            ui.label(icon_text(status.icon(), theme::ICON, fg));
                            ui.label(
                                RichText::new(format!(
                                    "{} v{}",
                                    f["rule_id"].as_str().unwrap_or("?"),
                                    f["rule_version"]
                                ))
                                .font(theme::body_strong()),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "{} ・ 確度 {}",
                                    status.label(),
                                    f["confidence"].as_str().unwrap_or("?")
                                ))
                                .size(theme::CAPTION)
                                .color(p.text_secondary),
                            );
                        });
                        ui.add(
                            egui::Label::new(
                                RichText::new(elide(&detail, 400))
                                    .size(theme::CAPTION)
                                    .color(p.text_secondary),
                            )
                            .truncate(),
                        )
                        .on_hover_text(elide(&detail, 2000));
                    });
                }
            });
    }

    /// Browser-hijack timelines: a vertical stepper per DLL. Only observed
    /// stages are filled; the rest say whether they were unseen or unknown.
    fn timelines(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let Some(doc) = self.data.latest(DocumentKind::Timeline) else {
            fluent::settings_card(
                ui,
                p,
                icon::HISTORY,
                "ランチャー → DLL配置 → COM変更 → ブラウザー読込 → 外部通信",
                "`aegisguard events timeline --spool ... > timeline.json` の結果を開くと、観測できた段階だけを時系列で表示します。",
                Some(Status::NoData),
            );
            return;
        };
        let list = doc.value["timelines"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if list.is_empty() {
            fluent::settings_card(
                ui,
                p,
                icon::HISTORY,
                "該当するDLLはありません",
                "収集済みイベントの範囲で、HKCUのCOM登録先やブラウザーのユーザーデータに置かれたDLLは見つかりませんでした。収集していないイベント種別については不明です。",
                Some(Status::NothingFound),
            );
            return;
        }
        for t in list.iter().take(50) {
            theme::tile(p).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(icon_text(icon::DOCUMENT, theme::ICON, p.text));
                    ui.add(
                        egui::Label::new(
                            RichText::new(elide(t["dll_path"].as_str().unwrap_or(""), 90))
                                .font(theme::body_strong()),
                        )
                        .truncate(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "観測できた段階 {}/5",
                                t["observed_stages"].as_u64().unwrap_or(0)
                            ))
                            .size(theme::CAPTION)
                            .color(p.text_secondary),
                        );
                    });
                });
                ui.add_space(theme::S8);
                let stages = t["stages"].as_array().cloned().unwrap_or_default();
                let n = stages.len();
                for (i, s) in stages.iter().enumerate() {
                    stage_row(ui, p, s, i + 1 < n);
                }
            });
            ui.add_space(theme::S8);
        }
    }
}

fn stage_title(kind: &str) -> &'static str {
    match kind {
        "launcher" => "起動したプログラム",
        "dll_created" => "DLLの配置",
        "com_registered" => "COM登録（HKCU）の変更",
        "browser_loaded" => "ブラウザーがDLLを読込",
        "outbound" => "外部への通信",
        _ => "不明な段階",
    }
}

fn stage_row(ui: &mut egui::Ui, p: &Palette, s: &Value, connect: bool) {
    let state = s["state"].as_str().unwrap_or("");
    let observed = state == "observed";
    let marker = 24.0;
    let (fg_caution, _) = p.caution;
    ui.horizontal_top(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(marker, 52.0), egui::Sense::hover());
        let center = egui::pos2(rect.center().x, rect.top() + 10.0);
        let painter = ui.painter();
        if connect {
            painter.line_segment(
                [
                    egui::pos2(center.x, center.y + 9.0),
                    egui::pos2(center.x, rect.bottom() + 8.0),
                ],
                Stroke::new(2.0, if observed { p.accent } else { p.divider }),
            );
        }
        match state {
            "observed" => {
                painter.circle_filled(center, 8.0, p.accent);
                painter.text(
                    center,
                    egui::Align2::CENTER_CENTER,
                    "\u{E73E}",
                    egui::FontId::new(10.0, theme::icons()),
                    p.on_accent,
                );
            }
            "source_missing" => {
                painter.text(
                    center,
                    egui::Align2::CENTER_CENTER,
                    "\u{E7BA}",
                    egui::FontId::new(14.0, theme::icons()),
                    fg_caution,
                );
            }
            _ => {
                painter.circle_stroke(center, 7.0, Stroke::new(1.5, p.text_tertiary));
            }
        }
        ui.vertical(|ui| {
            let title = RichText::new(stage_title(s["kind"].as_str().unwrap_or("")));
            ui.label(if observed {
                title.font(theme::body_strong())
            } else {
                title.color(p.text_secondary)
            });
            let detail = match state {
                "observed" => {
                    let at = s["at_unix_ms"]
                        .as_i64()
                        .map(|t| format!("{} UTC", utc(t)))
                        .unwrap_or_else(|| "時刻不明".into());
                    let who = s["image"]
                        .as_str()
                        .map(|i| elide(i, 60))
                        .unwrap_or_default();
                    let extra = s["detail"]
                        .as_str()
                        .map(|d| elide(d, 80))
                        .unwrap_or_default();
                    format!("{at}　{who}　{extra}")
                }
                "source_missing" => {
                    "不明：このイベント種別は収集されていません（起きなかったとは限りません）"
                        .into()
                }
                _ => "未観測：イベントは収集済みですが該当がありません".into(),
            };
            ui.add(
                egui::Label::new(
                    RichText::new(detail)
                        .size(theme::CAPTION)
                        .color(p.text_secondary),
                )
                .truncate(),
            );
        });
    });
}

/// `YYYY-MM-DD hh:mm:ss` (UTC) from Unix milliseconds.
pub fn utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn rows(ui: &mut egui::Ui, p: &Palette, rows: &[StatusRow], icons: &[&str]) {
    for (i, row) in rows.iter().enumerate() {
        let glyph = icons.get(i).copied().unwrap_or(icon::INFO);
        fluent::settings_card(ui, p, glyph, &row.name, &row.detail, Some(row.status));
    }
}

fn scan_status(r: &aegisguard::api::ScanReportV2) -> Status {
    use aegisguard::api::SignalLevel;
    if r.is_scan_stopped() {
        return Status::Stopped;
    }
    match r.signal_level() {
        SignalLevel::High => Status::High,
        SignalLevel::Review => Status::Review,
        _ if r.nothing_found() => Status::NothingFound,
        _ => Status::Incomplete,
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

    /// Render the app headlessly; returns texts and whether a repaint was
    /// requested without input (continuous redraw).
    fn render_app(app: &mut AegisApp, size: [f32; 2], scale: f32) -> (Vec<String>, bool) {
        let ctx = egui::Context::default();
        crate::fonts::install(&ctx);
        ctx.set_pixels_per_point(scale);
        // Time advances one second per frame so animations can finish.
        let input = |t: f64| egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size.into())),
            time: Some(t),
            ..Default::default()
        };
        let mut texts = Vec::new();
        let mut busy = false;
        for frame in 0..6 {
            let mut out = ctx.run_ui(input(f64::from(frame)), |ui| app.draw(ui));
            out.textures_delta.clear();
            busy = out
                .viewport_output
                .get(&egui::ViewportId::ROOT)
                .is_some_and(|v| v.repaint_delay.is_zero());
            if busy && std::env::var_os("AEGIS_DEBUG_REPAINT").is_some() {
                eprintln!("CAUSES {:?}", ctx.repaint_causes());
            }
            texts = out
                .shapes
                .iter()
                .filter_map(|s| match &s.shape {
                    egui::epaint::Shape::Text(t) => Some(t.galley.text().to_string()),
                    _ => None,
                })
                .collect();
        }
        (texts, busy)
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
                    let (texts, busy) = render_app(&mut AegisApp::new(page, theme), size, scale);
                    let all = texts.join("\n");
                    assert!(all.contains(page.title()), "{page:?} title missing");
                    for word in FORBIDDEN_CLAIMS {
                        assert!(!all.contains(word), "{page:?} shows {word}");
                    }
                    // No continuous high-FPS redraw while idle.
                    assert!(!busy, "{page:?} {size:?} repaints continuously");
                }
            }
        }
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

    fn big_scan(dir: &std::path::Path, n: usize) -> PathBuf {
        let path = dir.join("big.jsonl");
        let long = "x".repeat(150);
        let mut text = String::new();
        for i in 0..n {
            text.push_str(&format!(
                r#"{{"path":"C:\\{long}\\{i}<script>.ps1","kind":"script","status":"analyzed","risk":"review","analysis_complete":true,"schema_version":2,"assessment":"analyzed","signal_level":"review","signals":[{{"code":"download_and_execute","severity":45,"source":"raw","reason":"r"}}]}}"#
            ));
            text.push('\n');
        }
        text.push_str("{not json\n");
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn large_hostile_dataset_renders_only_visible_rows() {
        let dir = std::env::temp_dir().join(format!("aegis-ui-big-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for n in [100, 1000, 100_000] {
            let mut app = AegisApp::new(Page::Scan, ThemeChoice::Dark);
            app.load_now(&[big_scan(&dir, n)]);
            assert_eq!(app.data.scans.len(), n);
            assert_eq!(app.data.scan_files[0].problems, 1);
            let start = std::time::Instant::now();
            let (texts, _) = render_app(&mut app, [1280.0, 800.0], 1.0);
            let rows = texts.iter().filter(|t| t.contains("<script>")).count();
            assert!(rows > 0 && rows < 60, "{n}: {rows}");
            assert!(start.elapsed() < std::time::Duration::from_secs(20));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn many_findings_and_timelines_render() {
        let mut app = AegisApp::new(Page::History, ThemeChoice::Light);
        let findings: Vec<Value> = (0..100_000)
            .map(|i| serde_json::json!({"rule_id": format!("AG-B00{}", i % 5), "rule_version": 1, "verdict": "review", "confidence": "high", "explanation": "x".repeat(3000), "missing_sources": ["sysmon_image_load"], "suppressed_reason": null}))
            .collect();
        app.data.documents.push(crate::data::Document {
            path: "c.json".into(),
            kind: DocumentKind::Correlation,
            value: serde_json::json!({"correlation": {"rules": [], "findings": findings}}),
            saved_at_unix: Some(1),
        });
        let (texts, _) = render_app(&mut app, [1280.0, 800.0], 1.0);
        assert!(texts.iter().any(|t| t.contains("所見 100000 件")));
        assert!(texts.iter().filter(|t| t.contains("AG-B00")).count() < 40);

        app.page = Page::Browser;
        app.data.documents.push(crate::data::Document {
            path: "t.json".into(),
            kind: DocumentKind::Timeline,
            value: serde_json::json!({"omitted": 0, "timelines": [{"dll_path": "C:\\a\\b.dll", "observed_stages": 2, "stages": [
                {"kind": "launcher", "state": "observed", "at_unix_ms": 1_793_000_000_000i64, "image": "C:\\Games\\launcher.exe"},
                {"kind": "dll_created", "state": "observed", "at_unix_ms": 1_793_000_001_000i64, "detail": "C:\\a\\b.dll"},
                {"kind": "com_registered", "state": "source_missing"},
                {"kind": "browser_loaded", "state": "not_observed"},
                {"kind": "outbound", "state": "source_missing"}
            ]}]}),
            saved_at_unix: Some(1),
        });
        let (texts, _) = render_app(&mut app, [1280.0, 1600.0], 1.0);
        let all = texts.join("\n");
        assert!(all.contains("観測できた段階 2/5"));
        assert!(all.contains("不明：このイベント種別は収集されていません"));
        assert!(all.contains("未観測"));
    }

    #[test]
    fn utc_formatting_and_elide() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(1_793_886_855_135), "2026-11-05 13:54:15");
        assert_eq!(elide("abc", 5), "abc");
        let e = elide("C:\\very\\long\\path\\file.txt", 10);
        assert!(e.starts_with('…') && e.ends_with("file.txt"));
        assert_eq!(e.chars().count(), 10);
    }
}
