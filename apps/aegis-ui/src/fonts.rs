//! Fonts come from the operating system; none are bundled.
//!
//! Windows 11 (Fluent): Yu Gothic UI for Japanese UI text (it also covers
//! Latin, so mixed lines share one baseline), Segoe UI Variable as Latin
//! fallback, and Segoe Fluent Icons (or Segoe MDL2 Assets on Windows 10)
//! for icons. Other platforms fall back to common system fonts.
use eframe::egui::{self, FontData, FontDefinitions, FontFamily};
use std::path::PathBuf;
use std::sync::Arc;

/// Larger files are not loaded (a font file is never this big in practice).
const MAX_FONT_BYTES: u64 = 64 * 1024 * 1024;

/// (file, face index) candidates in priority order.
struct Candidates {
    regular: Vec<(PathBuf, u32)>,
    semibold: Vec<(PathBuf, u32)>,
    latin: Vec<(PathBuf, u32)>,
    mono: Vec<(PathBuf, u32)>,
    icons: Vec<(PathBuf, u32)>,
}

fn candidates() -> Candidates {
    #[cfg(windows)]
    {
        let root = std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into());
        let d = PathBuf::from(root).join("Fonts");
        Candidates {
            // YuGothM.ttc face 1 = "Yu Gothic UI Regular"; YuGothB.ttc face 2 =
            // "Yu Gothic UI Semibold".
            regular: vec![
                (d.join("YuGothM.ttc"), 1),
                (d.join("meiryo.ttc"), 2),
                (d.join("msgothic.ttc"), 1),
            ],
            semibold: vec![
                (d.join("YuGothB.ttc"), 2),
                (d.join("YuGothB.ttc"), 1),
                (d.join("meiryob.ttc"), 2),
            ],
            latin: vec![(d.join("SegUIVar.ttf"), 0), (d.join("segoeui.ttf"), 0)],
            mono: vec![(d.join("CascadiaMono.ttf"), 0), (d.join("consola.ttf"), 0)],
            icons: vec![(d.join("SegoeIcons.ttf"), 0), (d.join("segmdl2.ttf"), 0)],
        }
    }
    #[cfg(not(windows))]
    {
        let p = |s: &str| (PathBuf::from(s), 0);
        Candidates {
            regular: vec![
                p("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
                p("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            ],
            semibold: vec![
                p("/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"),
                p("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
            ],
            latin: vec![p("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")],
            mono: vec![p("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")],
            icons: vec![],
        }
    }
}

fn load_first(paths: &[(PathBuf, u32)]) -> Option<(String, FontData)> {
    paths.iter().find_map(|(path, index)| {
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() > MAX_FONT_BYTES {
            return None;
        }
        let bytes = std::fs::read(path).ok()?;
        let mut data = FontData::from_owned(bytes);
        data.index = *index;
        let name = format!("{}#{index}", path.file_name()?.to_string_lossy());
        Some((name, data))
    })
}

/// Which roles found a font. Missing Japanese text or icons are reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FontReport {
    pub regular: bool,
    pub icons: bool,
}

pub fn install(ctx: &egui::Context) -> FontReport {
    let c = candidates();
    let mut defs = FontDefinitions::empty();
    let mut add = |found: Option<(String, FontData)>| {
        found.map(|(name, data)| {
            defs.font_data.insert(name.clone(), Arc::new(data));
            name
        })
    };
    let regular = add(load_first(&c.regular));
    let semibold = add(load_first(&c.semibold));
    let latin = add(load_first(&c.latin));
    let mono = add(load_first(&c.mono));
    let icons = add(load_first(&c.icons));
    let chain = |names: &[&Option<String>]| -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for name in names.iter().copied().flatten() {
            if !v.contains(name) {
                v.push(name.clone());
            }
        }
        v
    };
    defs.families
        .insert(FontFamily::Proportional, chain(&[&regular, &latin, &icons]));
    defs.families
        .insert(FontFamily::Monospace, chain(&[&mono, &regular, &latin]));
    defs.families.insert(
        FontFamily::Name("semibold".into()),
        chain(&[&semibold, &regular, &latin, &icons]),
    );
    defs.families.insert(
        FontFamily::Name("icons".into()),
        chain(&[&icons, &regular, &latin]),
    );
    ctx.set_fonts(defs);
    FontReport {
        regular: regular.is_some(),
        icons: icons.is_some(),
    }
}
