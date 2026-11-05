//! Fonts come from the operating system; none are bundled. Latin text uses
//! the system UI font and Japanese falls back to a CJK system font.
use eframe::egui::{self, FontData, FontDefinitions, FontFamily};
use std::sync::Arc;

/// Larger files are not loaded (a font file is never this big in practice).
const MAX_FONT_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(windows)]
fn windows_fonts_dir() -> std::path::PathBuf {
    let root = std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into());
    std::path::PathBuf::from(root).join("Fonts")
}

/// (name, candidate paths) in priority order for each role.
fn candidates() -> (
    Vec<std::path::PathBuf>,
    Vec<std::path::PathBuf>,
    Vec<std::path::PathBuf>,
) {
    #[cfg(windows)]
    {
        let d = windows_fonts_dir();
        (
            vec![d.join("segoeui.ttf")],
            vec![
                d.join("YuGothM.ttc"),
                d.join("meiryo.ttc"),
                d.join("NotoSansJP-VF.ttf"),
                d.join("msgothic.ttc"),
            ],
            vec![d.join("consola.ttf"), d.join("cour.ttf")],
        )
    }
    #[cfg(not(windows))]
    {
        let p = |s: &str| std::path::PathBuf::from(s);
        (
            vec![
                p("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
                p("/usr/share/fonts/TTF/DejaVuSans.ttf"),
                p("/System/Library/Fonts/Helvetica.ttc"),
            ],
            vec![
                p("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
                p("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc"),
                p("/usr/share/fonts/truetype/fonts-japanese-gothic.ttf"),
                p("/System/Library/Fonts/Hiragino Sans GB.ttc"),
            ],
            vec![
                p("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
                p("/usr/share/fonts/TTF/DejaVuSansMono.ttf"),
            ],
        )
    }
}

fn load_first(paths: &[std::path::PathBuf]) -> Option<(String, FontData)> {
    paths.iter().find_map(|path| {
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() > MAX_FONT_BYTES {
            return None;
        }
        let bytes = std::fs::read(path).ok()?;
        let name = path.file_name()?.to_string_lossy().into_owned();
        Some((name, FontData::from_owned(bytes)))
    })
}

/// Which roles found a font. A missing CJK font is shown as a warning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FontReport {
    pub latin: bool,
    pub cjk: bool,
    pub mono: bool,
}

pub fn install(ctx: &egui::Context) -> FontReport {
    let (latin, cjk, mono) = candidates();
    let mut defs = FontDefinitions::empty();
    let mut report = FontReport::default();
    let add = |defs: &mut FontDefinitions, found: Option<(String, FontData)>| {
        found.map(|(name, data)| {
            defs.font_data.insert(name.clone(), Arc::new(data));
            name
        })
    };
    let latin = add(&mut defs, load_first(&latin));
    let cjk = add(&mut defs, load_first(&cjk));
    let mono = add(&mut defs, load_first(&mono));
    report.latin = latin.is_some();
    report.cjk = cjk.is_some();
    report.mono = mono.is_some();
    // The CJK font comes first: it covers Latin too, and mixing two fonts in
    // one line gives Latin and Japanese different baselines.
    let prop: Vec<String> = [cjk.clone(), latin.clone()].into_iter().flatten().collect();
    let monos: Vec<String> = [mono, latin, cjk].into_iter().flatten().collect();
    defs.families.insert(FontFamily::Proportional, prop.clone());
    defs.families.insert(
        FontFamily::Monospace,
        if monos.is_empty() { prop } else { monos },
    );
    ctx.set_fonts(defs);
    report
}
