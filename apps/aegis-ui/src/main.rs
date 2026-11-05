//! AegisGuard desktop UI (read-only, runs as the normal user).
//!
//! Usage: `aegis-ui [--page home|scan|browser|realtime|network|history|settings]
//! [--theme system|light|dark] [--open result.json ...] [--screenshot out.png [--size 1280x800] [--scale 1.0]]`
//!
//! `--screenshot` renders the chosen page, writes a PNG and exits; it is used
//! to check layout, DPI scaling and Japanese text on a real machine.
#![cfg_attr(not(test), windows_subsystem = "windows")]

mod app;
mod data;
mod fluent;
mod fonts;
mod png;
mod status;
mod theme;
mod views;

use app::{AegisApp, Page, ThemeChoice};
use eframe::egui;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct Options {
    page: Page,
    theme: ThemeChoice,
    screenshot: Option<PathBuf>,
    size: [f32; 2],
    scale: Option<f32>,
    open: Vec<PathBuf>,
}

fn parse_args() -> Result<Options, String> {
    let mut o = Options {
        page: Page::Home,
        theme: ThemeChoice::System,
        screenshot: None,
        size: [1180.0, 760.0],
        scale: None,
        open: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--page" => {
                let v = value()?;
                o.page = Page::from_name(&v).ok_or(format!("unknown page {v}"))?;
            }
            "--theme" => {
                o.theme = match value()?.as_str() {
                    "system" => ThemeChoice::System,
                    "light" => ThemeChoice::Light,
                    "dark" => ThemeChoice::Dark,
                    other => return Err(format!("unknown theme {other}")),
                }
            }
            "--open" => o.open.push(PathBuf::from(value()?)),
            "--screenshot" => o.screenshot = Some(PathBuf::from(value()?)),
            "--size" => {
                let v = value()?;
                let (w, h) = v.split_once('x').ok_or("size is WIDTHxHEIGHT")?;
                o.size = [
                    w.parse().map_err(|_| "bad width")?,
                    h.parse().map_err(|_| "bad height")?,
                ];
            }
            "--scale" => {
                let s: f32 = value()?.parse().map_err(|_| "bad scale")?;
                if !(0.5..=4.0).contains(&s) {
                    return Err("scale must be between 0.5 and 4".into());
                }
                o.scale = Some(s);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(o)
}

/// Wraps the app to take one screenshot after layout settles, then exit.
struct ScreenshotApp {
    inner: AegisApp,
    out: PathBuf,
    frames: u32,
    requested: bool,
    done: Arc<AtomicBool>,
    scale: Option<f32>,
}

impl eframe::App for ScreenshotApp {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(scale) = self.scale.take() {
            ctx.set_pixels_per_point(scale);
        }
        eframe::App::ui(&mut self.inner, ui, frame);
        self.frames += 1;
        if self.done.load(Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else if self.frames >= 5 && !self.requested {
            self.requested = true;
            let out = self.out.clone();
            let done = self.done.clone();
            let repaint = ctx.clone();
            ctx.request_screenshot(move |image| {
                let rgba: Vec<u8> = image.pixels.iter().flat_map(|c| c.to_array()).collect();
                let result = u32::try_from(image.size[0])
                    .ok()
                    .zip(u32::try_from(image.size[1]).ok())
                    .ok_or_else(|| std::io::Error::other("image too large"))
                    .and_then(|(w, h)| png::encode(w, h, &rgba))
                    .and_then(|bytes| std::fs::write(&out, bytes));
                if let Err(e) = result {
                    eprintln!("screenshot failed: {e}");
                }
                done.store(true, Ordering::SeqCst);
                repaint.request_repaint();
            });
        }
        ctx.request_repaint();
    }
}

fn main() -> eframe::Result {
    let options = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("aegis-ui: {e}");
            std::process::exit(2);
        }
    };
    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("AegisGuard")
            .with_inner_size(options.size)
            .with_min_inner_size([520.0, 420.0]),
        ..Default::default()
    };
    let mut app = AegisApp::new(options.page, options.theme);
    // Files named on the command line are loaded before the first frame
    // (bounded and cancellable like drag and drop).
    app.load_now(&options.open);
    eframe::run_native(
        "AegisGuard",
        native,
        Box::new(move |cc| {
            let report = fonts::install(&cc.egui_ctx);
            if !report.regular {
                eprintln!("aegis-ui: no Japanese system font found; text may not render");
            }
            if !report.icons {
                eprintln!("aegis-ui: Segoe Fluent Icons not found; icons may not render");
            }
            Ok(match options.screenshot {
                Some(out) => Box::new(ScreenshotApp {
                    inner: app,
                    out,
                    frames: 0,
                    requested: false,
                    done: Arc::new(AtomicBool::new(false)),
                    scale: options.scale,
                }) as Box<dyn eframe::App>,
                None => {
                    if let Some(scale) = options.scale {
                        cc.egui_ctx.set_pixels_per_point(scale);
                    }
                    Box::new(app)
                }
            })
        }),
    )
}
