//! Application shell: navigation, header, loading and the seven screens.
//!
//! The UI is read-only and runs as the normal user. It never starts
//! privileged processes and never parses CLI stdout: saved results are read
//! through `aegisguard::api` on a worker thread (see `data`). Features that do
//! not exist yet are shown as "まだ利用できません", missing data as "データなし".
use crate::data::{self, Dataset, Job, Update};
use crate::status::Status;
use crate::theme::{self, Palette};
use crate::views::{self, StatusRow};
use aegisguard::api::DocumentKind;
use eframe::egui::{self, Key, KeyboardShortcut, Modifiers, RichText};
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

/// Longest text shown in a table cell before eliding.
const MAX_CELL_CHARS: usize = 120;

fn elide(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let tail: Vec<char> = text.chars().rev().take(max - 1).collect();
    let tail: String = tail.into_iter().rev().collect();
    format!("…{tail}")
}

pub struct AegisApp {
    pub page: Page,
    pub theme: ThemeChoice,
    applied_theme: Option<ThemeChoice>,
    pub data: Dataset,
    job: Option<Job>,
    path_input: String,
    last_load_note: Option<String>,
    /// Scan table filter: hide rows where nothing was found.
    attention_only: bool,
}

impl AegisApp {
    pub fn new(page: Page, theme: ThemeChoice) -> Self {
        Self {
            page,
            theme,
            applied_theme: None,
            data: Dataset::default(),
            job: None,
            path_input: String::new(),
            last_load_note: None,
            attention_only: false,
        }
    }

    fn dark(&self) -> bool {
        self.theme == ThemeChoice::Dark
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

    pub fn draw(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if self.applied_theme != Some(self.theme) {
            theme::apply(&ctx, self.dark());
            self.applied_theme = Some(self.theme);
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
                if self.page == Page::Scan {
                    // The scan table scrolls itself (virtualized rows).
                    self.page_body(ui, &p);
                } else {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| self.page_body(ui, &p));
                }
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

    /// File loading controls: path box, drag and drop, progress and cancel.
    fn loader(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::card_frame(p).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("結果の読み込み").strong());
            ui.label(
                RichText::new("CLIで保存したJSON/JSONL（scan, defender audit, c2 status, events correlate/iocs, browser k2f, rules status 等）のパスを入力するか、ウィンドウへドラッグ＆ドロップします。")
                    .small()
                    .color(p.text_muted),
            );
            ui.horizontal(|ui| {
                let busy = self.job.is_some();
                let edit = ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut self.path_input)
                        .hint_text(r"C:\path\to\scan.jsonl")
                        .desired_width((ui.available_width() - 110.0).max(120.0)),
                );
                let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if (ui.add_enabled(!busy, egui::Button::new("読み込む")).clicked() || enter)
                    && !self.path_input.trim().is_empty()
                {
                    let path = PathBuf::from(self.path_input.trim().trim_matches('"'));
                    let ctx = ui.ctx().clone();
                    self.load(&ctx, vec![path]);
                }
            });
            if let Some(job) = &self.job {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new());
                    ui.label(format!(
                        "読み込み中 {}/{}：{}",
                        job.done + 1,
                        job.total,
                        job.current
                            .as_ref()
                            .map(|c| elide(&c.display().to_string(), 60))
                            .unwrap_or_default()
                    ));
                    if ui.button("中止").clicked() {
                        job.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                });
            } else if let Some(note) = &self.last_load_note {
                ui.label(RichText::new(note).small().color(p.text_muted));
            }
            for e in self.data.errors.iter().rev().take(5) {
                ui.label(
                    RichText::new(format!(
                        "{} {}：{}",
                        Status::Incomplete.glyph(),
                        elide(&e.path.display().to_string(), 60),
                        e.reason
                    ))
                    .small()
                    .color(p.caution.0),
                );
            }
        });
        ui.add_space(theme::SPACE_M);
    }

    fn page_body(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let now = views::now();
        ui.label(RichText::new(self.page.title()).heading().strong());
        ui.add_space(theme::SPACE_S);
        match self.page {
            Page::Home => {
                intro(ui, p, "各項目は自分の情報源から確認できた範囲だけを表示します。確認できない項目を「正常」として表示することはありません。");
                self.loader(ui, p);
                status_list(ui, p, &views::home_rows(&self.data, now));
            }
            Page::Scan => {
                intro(ui, p, "ファイルを実行せずに静的に検査した結果です。GUIからのスキャン実行はまだ利用できません（CLI `aegisguard scan <パス> --recursive --output scan.jsonl`）。");
                self.loader(ui, p);
                self.scan_table(ui, p);
            }
            Page::Browser => {
                intro(ui, p, "ブラウザー領域へのDLL配置・COM登録の変更・ブラウザーによる読込みを、観測できた範囲で確認します。ファイルやレジストリを削除・変更しません。");
                status_list(ui, p, &views::browser_rows(&self.data, now));
            }
            Page::Realtime => {
                intro(ui, p, "常駐サービスとリアルタイム相関は未実装です。");
                status_list(
                    ui,
                    p,
                    &[StatusRow {
                        name: "リアルタイム監視".into(),
                        status: Status::NotAvailable,
                        detail: "現在はCLIでの単発収集とオフライン相関のみです（P8で常駐化予定）。"
                            .into(),
                    }],
                );
            }
            Page::Network => {
                intro(ui, p, "C2 IOCとの照合は、収集済みのSysmonイベントとローカルのIOCキャッシュに対して行います。通信の遮断はしません。");
                status_list(ui, p, &views::network_rows(&self.data, now));
            }
            Page::History => {
                intro(ui, p, "読み込んだ相関結果の所見です。所見は確認のための根拠で、悪性の判定ではありません。");
                self.history(ui, p);
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
                status_list(ui, p, &[views::rules_row(&self.data, now)]);
            }
        }
    }

    fn scan_table(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let c = views::scan_counts(&self.data);
        if self.data.scans.is_empty() {
            status_list(
                ui,
                p,
                &[StatusRow {
                    name: "スキャン結果".into(),
                    status: Status::NoData,
                    detail: "まだ結果を読み込んでいません。".into(),
                }],
            );
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("{} 件", c.total));
            status_chip(ui, p, Status::High);
            ui.label(c.high.to_string());
            status_chip(ui, p, Status::Review);
            ui.label(c.review.to_string());
            status_chip(ui, p, Status::Incomplete);
            ui.label((c.incomplete + c.not_assessed).to_string());
            if c.stopped_runs > 0 {
                status_chip(ui, p, Status::Stopped);
                ui.label(format!("途中で停止した走査 {} 回", c.stopped_runs));
            }
            ui.checkbox(&mut self.attention_only, "該当なし以外だけ表示");
        });
        for f in self.data.scan_files.iter().filter(|f| !f.complete()) {
            ui.label(
                RichText::new(format!(
                    "{} {}：読み込んだ {} 件、読めない行 {}、新しい形式 {}、打切り {:?}",
                    Status::Incomplete.glyph(),
                    elide(&f.path.display().to_string(), 60),
                    f.records,
                    f.problems,
                    f.newer_schema,
                    f.truncated
                ))
                .small()
                .color(p.caution.0),
            );
        }
        let rows: Vec<usize> = self
            .data
            .scans
            .iter()
            .enumerate()
            .filter(|(_, r)| !self.attention_only || !r.nothing_found())
            .map(|(i, _)| i)
            .collect();
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 10.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, rows.len(), |ui, range| {
                for &i in &rows[range] {
                    let r = &self.data.scans[i];
                    let status = scan_status(r);
                    ui.horizontal(|ui| {
                        ui.set_min_height(row_height - 4.0);
                        status_chip(ui, p, status);
                        ui.label(RichText::new(r.kind.as_str()).small().color(p.text_muted));
                        if !r.signals.is_empty() {
                            let codes: Vec<&str> =
                                r.signals.iter().map(|s| s.code.as_str()).take(3).collect();
                            ui.label(RichText::new(codes.join(", ")).small().color(p.text_muted));
                        }
                        // Keep the end of the path (file name) visible in the space left.
                        let char_width = ui.text_style_height(&egui::TextStyle::Body) * 0.55;
                        let fit = (ui.available_width() / char_width) as usize;
                        ui.add(
                            egui::Label::new(elide(&r.path, fit.clamp(16, MAX_CELL_CHARS)))
                                .truncate(),
                        )
                        .on_hover_text(elide(&r.path, 2000));
                    });
                }
            });
    }

    fn history(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let docs: Vec<&data::Document> = self
            .data
            .documents
            .iter()
            .filter(|d| d.kind == DocumentKind::Correlation)
            .collect();
        if docs.is_empty() {
            status_list(
                ui,
                p,
                &[StatusRow {
                    name: "検出履歴".into(),
                    status: Status::NoData,
                    detail: "`events correlate` の結果をまだ読み込んでいません。".into(),
                }],
            );
            return;
        }
        for doc in docs {
            let findings = doc.value["correlation"]["findings"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if findings.is_empty() {
                status_list(
                    ui,
                    p,
                    &[StatusRow {
                        name: elide(&doc.path.display().to_string(), 80),
                        status: Status::NothingFound,
                        detail: "評価できたルールの範囲で所見はありません。評価できなかったルールはブラウザー保護・ホームを確認してください。".into(),
                    }],
                );
                continue;
            }
            let rows: Vec<StatusRow> = findings
                .iter()
                .take(500)
                .map(|f| {
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
                    StatusRow {
                        name: format!(
                            "{} v{}（確度 {}）",
                            f["rule_id"].as_str().unwrap_or("?"),
                            f["rule_version"],
                            f["confidence"].as_str().unwrap_or("?")
                        ),
                        status,
                        detail: format!(
                            "{}{}{}",
                            elide(f["explanation"].as_str().unwrap_or(""), 600),
                            if missing.is_empty() {
                                String::new()
                            } else {
                                format!("　見えていない情報源: {missing}")
                            },
                            f["suppressed_reason"]
                                .as_str()
                                .map(|s| format!("　抑制: {}", elide(s, 200)))
                                .unwrap_or_default()
                        ),
                    }
                })
                .collect();
            status_list(ui, p, &rows);
            if findings.len() > 500 {
                ui.label(format!(
                    "ほか {} 件は表示していません",
                    findings.len() - 500
                ));
            }
        }
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
                ui.label(RichText::new(&row.name).strong());
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

    /// Render the app headlessly at a given size and DPI scale.
    fn render_app(app: &mut AegisApp, size: [f32; 2], scale: f32) -> Vec<String> {
        let ctx = egui::Context::default();
        crate::fonts::install(&ctx);
        ctx.set_pixels_per_point(scale);
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
                    let texts = render_app(&mut AegisApp::new(page, theme), size, scale);
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

    #[test]
    fn large_hostile_dataset_renders_only_visible_rows() {
        let dir = std::env::temp_dir().join(format!("aegis-ui-big-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.jsonl");
        let long = "x".repeat(150);
        let mut text = String::new();
        for i in 0..100_000 {
            text.push_str(&format!(
                r#"{{"path":"C:\\{long}\\{i}<script>.ps1","kind":"script","status":"analyzed","risk":"review","analysis_complete":true,"schema_version":2,"assessment":"analyzed","signal_level":"review","signals":[{{"code":"download_and_execute","severity":45,"source":"raw","reason":"r"}}]}}"#
            ));
            text.push('\n');
        }
        text.push_str("{not json\n");
        std::fs::write(&path, text).unwrap();
        let mut app = AegisApp::new(Page::Scan, ThemeChoice::Dark);
        app.load_now(&[path]);
        assert_eq!(app.data.scans.len(), 100_000);
        assert_eq!(app.data.scan_files[0].problems, 1);
        let start = std::time::Instant::now();
        let texts = render_app(&mut app, [1280.0, 800.0], 1.0);
        // Virtualized: only about a screenful of rows is laid out.
        let rows = texts.iter().filter(|t| t.contains("<script>")).count();
        assert!(rows > 0 && rows < 100, "{rows}");
        assert!(start.elapsed() < std::time::Duration::from_secs(20));
        assert!(texts.iter().all(|t| t.chars().count() <= 1000));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn elide_keeps_the_end_of_long_paths() {
        assert_eq!(elide("abc", 5), "abc");
        let e = elide("C:\\very\\long\\path\\file.txt", 10);
        assert!(e.starts_with('…') && e.ends_with("file.txt"));
        assert_eq!(e.chars().count(), 10);
    }
}
