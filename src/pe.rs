use crate::budget::Budget;
use crate::model::Report;
use serde::Serialize;

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let a = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([a[0], a[1]]))
}
fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let a = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([a[0], a[1], a[2], a[3]]))
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    counts
        .into_iter()
        .filter(|c| *c != 0)
        .map(|count| {
            let p = count as f64 / data.len() as f64;
            -p * p.log2()
        })
        .sum()
}

/// Strictly bounded PE structural triage; not Authenticode verification or a disassembler.
/// All offsets derive from the file and are checked before slicing.
pub fn inspect(data: &[u8], report: &mut Report, budget: &Budget) {
    report.analyzer("pe_header");
    if !data.starts_with(b"MZ") {
        report.unavailable("invalid_pe", "malformed_pe", "Missing DOS MZ signature");
        return;
    }
    let Some(pe_offset) = le_u32(data, 0x3c).map(|n| n as usize) else {
        report.unavailable("invalid_pe", "malformed_pe", "Truncated DOS header");
        return;
    };
    if data.get(pe_offset..pe_offset.saturating_add(4)) != Some(&b"PE\0\0"[..]) {
        report.unavailable("invalid_pe", "malformed_pe", "Missing NT PE signature");
        return;
    }
    let coff = pe_offset + 4;
    let Some(section_count) = le_u16(data, coff + 2).map(usize::from) else {
        report.unavailable("invalid_pe", "malformed_pe", "Truncated COFF header");
        return;
    };
    let Some(optional_header_bytes) = le_u16(data, coff + 16).map(usize::from) else {
        report.unavailable("invalid_pe", "malformed_pe", "Missing optional header size");
        return;
    };
    if section_count == 0 || section_count > 96 {
        report.unavailable(
            "invalid_pe",
            "malformed_pe",
            "Section count outside safe bounds",
        );
        return;
    }
    let Some(sections) = coff
        .checked_add(20)
        .and_then(|n| n.checked_add(optional_header_bytes))
    else {
        report.unavailable("invalid_pe", "malformed_pe", "Invalid PE section offsets");
        return;
    };
    let Some(end) = section_count
        .checked_mul(40)
        .and_then(|n| sections.checked_add(n))
    else {
        report.unavailable("invalid_pe", "malformed_pe", "Invalid PE section table");
        return;
    };
    if end > data.len() {
        report.unavailable("invalid_pe", "malformed_pe", "Truncated PE section table");
        return;
    }

    report.analyzer("pe_sections");
    let mut has_wx = false;
    let mut high_entropy = false;
    for i in 0..section_count {
        if let Some(reason) = budget.exceeded() {
            report.mark_incomplete(reason);
            break;
        }
        let at = sections + i * 40;
        let flags = le_u32(data, at + 36).unwrap_or(0);
        if flags & 0x2000_0000 != 0 && flags & 0x8000_0000 != 0 {
            has_wx = true;
        }
        let size = le_u32(data, at + 16).unwrap_or(0) as usize;
        let start = le_u32(data, at + 20).unwrap_or(0) as usize;
        if size == 0 {
            continue;
        }
        let Some(stop) = start.checked_add(size) else {
            report.unavailable(
                "invalid_pe",
                "malformed_pe",
                "Section raw data pointer overflow",
            );
            return;
        };
        let Some(raw) = data.get(start..stop) else {
            report.unavailable(
                "invalid_pe",
                "malformed_pe",
                "Section raw data outside file",
            );
            return;
        };
        if raw.len() >= 4096 && entropy(&raw[..raw.len().min(65536)]) >= 7.3 {
            high_entropy = true;
        }
    }
    if has_wx {
        report.add(
            "writable_executable_section",
            40,
            "pe_section",
            "A section is both writable and executable",
        );
    }
    if high_entropy {
        report.add(
            "high_section_entropy",
            20,
            "pe_section",
            "A section has high entropy (packing is possible, not proof of malware)",
        );
    }
    report.analyzer("pe_structure");
    let summary = structure(data, coff, sections, section_count, budget);
    for problem in &summary.problems {
        report.mark_incomplete(problem);
    }
    if injection_imports(&summary) {
        report.add(
            "process_injection_imports",
            20,
            "pe_imports",
            "Imports the APIs needed to write and start code in another process (debuggers and security tools do this too)",
        );
    }
    if summary
        .overlay
        .as_ref()
        .is_some_and(|o| o.high_entropy && o.size >= 4096)
    {
        report.add(
            "high_entropy_overlay",
            15,
            "pe_overlay",
            "Appended data after the last section has high entropy (installers and self-extractors do this too)",
        );
    }
    report.pe = Some(summary);
}

// ---------------------------------------------------------------------------
// P5-04: bounded structure (imports, exports, certificate table, overlay).

/// Caps keeping the structure walk bounded on hostile files.
const MAX_IMPORT_DLLS: usize = 256;
const MAX_IMPORTED_FUNCTIONS: usize = 16_384;
const MAX_NAMES_PER_DLL: usize = 64;
const MAX_EXPORT_NAMES: usize = 256;
const MAX_NAME_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportedDll {
    pub name: String,
    pub functions: usize,
    /// Up to 64 names; ordinal imports appear as `#<n>`.
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Overlay {
    pub offset: u64,
    pub size: u64,
    pub high_entropy: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CertificateTable {
    pub offset: u64,
    pub size: u64,
}

/// What the structure walk found. `problems` lists parts that could not be
/// read; they make the report incomplete instead of being skipped silently.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PeSummary {
    pub format: &'static str,
    pub machine: String,
    pub is_dll: bool,
    pub imports: Vec<ImportedDll>,
    pub imported_functions: usize,
    pub imports_truncated: bool,
    pub export_name: Option<String>,
    pub exported_functions: usize,
    pub export_names: Vec<String>,
    pub certificate_table: Option<CertificateTable>,
    pub overlay: Option<Overlay>,
    pub authenticode: Option<crate::authenticode::Authenticode>,
    pub problems: Vec<&'static str>,
}

struct Section {
    va: u32,
    vsize: u32,
    raw: u32,
    raw_size: u32,
}

fn rva_to_offset(sections: &[Section], rva: u32) -> Option<usize> {
    sections.iter().find_map(|s| {
        let span = s.vsize.max(s.raw_size);
        let delta = rva.checked_sub(s.va)?;
        (delta < span && delta < s.raw_size).then(|| s.raw as usize + delta as usize)
    })
}

/// A NUL-terminated ASCII name. Names longer than the cap (C++ mangled
/// exports can be) are kept truncated with "…"; `None` only for names that
/// are out of bounds or not printable ASCII.
fn c_string(data: &[u8], at: usize) -> Option<String> {
    let tail = data.get(at..)?;
    let window = &tail[..tail.len().min(MAX_NAME_BYTES)];
    let (raw, truncated) = match window.iter().position(|&b| b == 0) {
        Some(end) => (&window[..end], false),
        None if tail.len() > MAX_NAME_BYTES => (window, true),
        None => return None,
    };
    if raw.is_empty() || !raw.iter().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let mut name = String::from_utf8_lossy(raw).into_owned();
    if truncated {
        name.push('…');
    }
    Some(name)
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let a = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(a.try_into().ok()?))
}

/// Walk headers that were already validated by `inspect`.
fn structure(
    data: &[u8],
    coff: usize,
    sections_at: usize,
    count: usize,
    budget: &Budget,
) -> PeSummary {
    let mut s = PeSummary::default();
    let opt = coff + 20;
    let machine = le_u16(data, coff).unwrap_or(0);
    s.machine = match machine {
        0x14c => "x86".into(),
        0x8664 => "x64".into(),
        0xaa64 => "arm64".into(),
        0x1c4 => "arm".into(),
        other => format!("0x{other:04x}"),
    };
    s.is_dll = le_u16(data, coff + 18).is_some_and(|c| c & 0x2000 != 0);
    let (dirs_at, count_at, wide) = match le_u16(data, opt) {
        Some(0x10b) => (opt + 96, opt + 92, false),
        Some(0x20b) => (opt + 112, opt + 108, true),
        _ => {
            s.format = "unknown";
            s.problems.push("optional_header_magic");
            return s;
        }
    };
    s.format = if wide { "pe32+" } else { "pe32" };
    let dir_count = le_u32(data, count_at).unwrap_or(0).min(16) as usize;
    let dir = |i: usize| -> Option<(u32, u32)> {
        if i >= dir_count {
            return None;
        }
        let at = dirs_at + i * 8;
        Some((le_u32(data, at)?, le_u32(data, at + 4)?))
    };
    let sections: Vec<Section> = (0..count)
        .map(|i| {
            let at = sections_at + i * 40;
            Section {
                vsize: le_u32(data, at + 8).unwrap_or(0),
                va: le_u32(data, at + 12).unwrap_or(0),
                raw_size: le_u32(data, at + 16).unwrap_or(0),
                raw: le_u32(data, at + 20).unwrap_or(0),
            }
        })
        .collect();

    // Imports (directory 1).
    if let Some((rva, size)) = dir(1).filter(|(rva, _)| *rva != 0) {
        match rva_to_offset(&sections, rva) {
            None => s.problems.push("import_directory_outside_sections"),
            Some(mut at) => {
                let _ = size;
                loop {
                    if budget.exceeded().is_some() {
                        s.problems.push("analysis_time_limit");
                        break;
                    }
                    if s.imports.len() >= MAX_IMPORT_DLLS {
                        s.imports_truncated = true;
                        break;
                    }
                    let (Some(lookup), Some(name_rva), Some(iat)) = (
                        le_u32(data, at),
                        le_u32(data, at + 12),
                        le_u32(data, at + 16),
                    ) else {
                        s.problems.push("import_descriptor_truncated");
                        break;
                    };
                    if lookup == 0 && name_rva == 0 && iat == 0 {
                        break;
                    }
                    let name = rva_to_offset(&sections, name_rva)
                        .and_then(|o| c_string(data, o))
                        .unwrap_or_else(|| "<unreadable>".into());
                    let mut dll = ImportedDll {
                        name,
                        functions: 0,
                        names: Vec::new(),
                    };
                    let thunks = if lookup != 0 { lookup } else { iat };
                    match rva_to_offset(&sections, thunks) {
                        None => s.problems.push("import_thunks_outside_sections"),
                        Some(mut t) => loop {
                            if s.imported_functions >= MAX_IMPORTED_FUNCTIONS {
                                s.imports_truncated = true;
                                break;
                            }
                            let (value, ordinal) = if wide {
                                let Some(v) = le_u64(data, t) else {
                                    s.problems.push("import_thunks_truncated");
                                    break;
                                };
                                (v & 0x7fff_ffff, v & (1 << 63) != 0)
                            } else {
                                let Some(v) = le_u32(data, t) else {
                                    s.problems.push("import_thunks_truncated");
                                    break;
                                };
                                (u64::from(v & 0x7fff_ffff), v & 0x8000_0000 != 0)
                            };
                            if value == 0 && !ordinal {
                                break;
                            }
                            dll.functions += 1;
                            s.imported_functions += 1;
                            if dll.names.len() < MAX_NAMES_PER_DLL {
                                let name = if ordinal {
                                    format!("#{}", value & 0xffff)
                                } else {
                                    rva_to_offset(&sections, value as u32)
                                        .and_then(|o| c_string(data, o + 2))
                                        .unwrap_or_else(|| "<unreadable>".into())
                                };
                                dll.names.push(name);
                            }
                            t += if wide { 8 } else { 4 };
                        },
                    }
                    s.imports.push(dll);
                    at += 20;
                }
            }
        }
    }

    // Exports (directory 0).
    if let Some((rva, _)) = dir(0).filter(|(rva, _)| *rva != 0) {
        match rva_to_offset(&sections, rva) {
            None => s.problems.push("export_directory_outside_sections"),
            Some(at) => {
                s.export_name = le_u32(data, at + 12)
                    .and_then(|r| rva_to_offset(&sections, r))
                    .and_then(|o| c_string(data, o));
                s.exported_functions = le_u32(data, at + 20).unwrap_or(0) as usize;
                let names = le_u32(data, at + 24).unwrap_or(0) as usize;
                if let Some(table) = le_u32(data, at + 32).and_then(|r| rva_to_offset(&sections, r))
                {
                    for i in 0..names.min(MAX_EXPORT_NAMES) {
                        match le_u32(data, table + i * 4)
                            .and_then(|r| rva_to_offset(&sections, r))
                            .and_then(|o| c_string(data, o))
                        {
                            Some(n) => s.export_names.push(n),
                            None => {
                                s.problems.push("export_names_unreadable");
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Certificate table (directory 4) holds a *file offset*, not an RVA.
    if let Some((offset, size)) = dir(4).filter(|(o, sz)| *o != 0 && *sz != 0) {
        let end = u64::from(offset) + u64::from(size);
        if end > data.len() as u64 {
            s.problems.push("certificate_table_outside_file");
        }
        s.certificate_table = Some(CertificateTable {
            offset: u64::from(offset),
            size: u64::from(size),
        });
    }

    // Overlay: bytes after the last section that the certificate table does
    // not account for.
    let image_end = sections
        .iter()
        .map(|s| u64::from(s.raw) + u64::from(s.raw_size))
        .max()
        .unwrap_or(0);
    let cert = s.certificate_table.as_ref();
    let overlay_end = match cert {
        Some(c) if c.offset >= image_end => c.offset,
        _ => data.len() as u64,
    };
    if overlay_end > image_end && image_end > 0 {
        let start = image_end as usize;
        let stop = (overlay_end as usize).min(data.len());
        let bytes = &data[start.min(stop)..stop];
        s.overlay = Some(Overlay {
            offset: image_end,
            size: (stop - start.min(stop)) as u64,
            high_entropy: bytes.len() >= 4096 && entropy(&bytes[..bytes.len().min(65536)]) >= 7.3,
        });
    }
    s
}

/// APIs that together allow writing code into and running it in another
/// process. Debuggers and some security tools import them too.
const INJECTION_SETS: &[&[&str]] =
    &[&["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]];

fn injection_imports(summary: &PeSummary) -> bool {
    let all: Vec<&str> = summary
        .imports
        .iter()
        .flat_map(|d| d.names.iter().map(String::as_str))
        .collect();
    INJECTION_SETS
        .iter()
        .any(|set| set.iter().all(|f| all.iter().any(|n| n.starts_with(f))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_budget() -> Budget {
        Budget::new(Duration::from_secs(60))
    }
    use crate::model::Report;

    #[test]
    fn rejects_truncated_pe() {
        let mut report = Report::new("sample.exe".into(), "pe");
        inspect(b"MZ", &mut report, &test_budget());
        report.finish();
        assert_eq!(report.risk, "not_assessed");
        assert_eq!(report.status, "invalid_pe");
        assert_eq!(report.not_assessed_reason, Some("malformed_pe"));
        assert_eq!(report.score, 0);
    }

    #[test]
    fn detects_writable_executable_section() {
        let mut bytes = vec![0u8; 512];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0u16.to_le_bytes());
        let section = 0x80 + 4 + 20;
        bytes[section + 36..section + 40].copy_from_slice(&0xa000_0000u32.to_le_bytes());
        let mut report = Report::new("sample.dll".into(), "pe");
        inspect(&bytes, &mut report, &test_budget());
        report.finish();
        assert!(report
            .signals
            .iter()
            .any(|s| s.code == "writable_executable_section"));
    }
}

#[cfg(test)]
mod structure_tests {
    use super::*;
    use std::time::Duration;

    /// A PE32+ DLL with one section holding an import of three injection
    /// APIs from kernel32.dll and an export table. Synthetic and inert.
    fn dll_with_imports(names: &[&str]) -> Vec<u8> {
        let mut b = vec![0u8; 0x1000];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        b[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        b[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        b[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        b[coff + 18..coff + 20].copy_from_slice(&0x2000u16.to_le_bytes());
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let dirs = opt + 112;
        // Section: VA 0x1000 -> raw 0x400, size 0x800.
        let sec = opt + 240;
        b[sec..sec + 5].copy_from_slice(b".data");
        b[sec + 8..sec + 12].copy_from_slice(&0x800u32.to_le_bytes());
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 16..sec + 20].copy_from_slice(&0x800u32.to_le_bytes());
        b[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());
        b[sec + 36..sec + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
        let rva = |off: usize| (off - 0x400 + 0x1000) as u32;
        // Import descriptor at 0x400, thunks at 0x440, names from 0x500.
        b[dirs + 8..dirs + 12].copy_from_slice(&rva(0x400).to_le_bytes());
        b[dirs + 12..dirs + 16].copy_from_slice(&40u32.to_le_bytes());
        b[0x400..0x404].copy_from_slice(&rva(0x440).to_le_bytes());
        b[0x40c..0x410].copy_from_slice(&rva(0x4f0).to_le_bytes());
        b[0x410..0x414].copy_from_slice(&rva(0x440).to_le_bytes());
        b[0x4f0..0x4f0 + 13].copy_from_slice(b"kernel32.dll\0");
        let mut at = 0x500;
        for (i, n) in names.iter().enumerate() {
            b[0x440 + i * 8..0x448 + i * 8].copy_from_slice(&u64::from(rva(at)).to_le_bytes());
            b[at + 2..at + 2 + n.len()].copy_from_slice(n.as_bytes());
            at += 2 + n.len() + 1;
        }
        // Export directory at 0x600 with one name.
        b[dirs..dirs + 4].copy_from_slice(&rva(0x600).to_le_bytes());
        b[0x600 + 12..0x600 + 16].copy_from_slice(&rva(0x680).to_le_bytes());
        b[0x600 + 20..0x600 + 24].copy_from_slice(&1u32.to_le_bytes());
        b[0x600 + 24..0x600 + 28].copy_from_slice(&1u32.to_le_bytes());
        b[0x600 + 32..0x600 + 36].copy_from_slice(&rva(0x660).to_le_bytes());
        b[0x660..0x664].copy_from_slice(&rva(0x690).to_le_bytes());
        b[0x680..0x689].copy_from_slice(b"stub.dll\0");
        b[0x690..0x69a].copy_from_slice(b"DllMain2\0\0");
        b
    }

    fn inspect_bytes(bytes: &[u8]) -> Report {
        let mut r = Report::new("x.dll".into(), "pe");
        inspect(bytes, &mut r, &Budget::new(Duration::from_secs(10)));
        r.finish();
        r
    }

    #[test]
    fn imports_exports_and_injection_combination_are_read() {
        let r = inspect_bytes(&dll_with_imports(&[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ]));
        let pe = r.pe.as_ref().unwrap();
        assert_eq!(pe.format, "pe32+");
        assert_eq!(pe.machine, "x64");
        assert!(pe.is_dll);
        assert_eq!(pe.imports[0].name, "kernel32.dll");
        assert_eq!(pe.imports[0].functions, 3);
        assert_eq!(pe.export_name.as_deref(), Some("stub.dll"));
        assert_eq!(pe.export_names, vec!["DllMain2".to_string()]);
        assert!(pe.problems.is_empty(), "{:?}", pe.problems);
        assert!(r
            .signals
            .iter()
            .any(|s| s.code == "process_injection_imports"));
        assert_eq!(r.assessment, crate::model::Assessment::Analyzed);
    }

    #[test]
    fn ordinary_imports_add_no_signal_and_overlay_is_measured() {
        let mut bytes = dll_with_imports(&["GetProcAddress", "LoadLibraryW"]);
        // 8 KiB of pseudo-random appended data (overlay).
        let mut x: u32 = 0x1234_5678;
        for _ in 0..8192 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            bytes.push(x as u8);
        }
        let r = inspect_bytes(&bytes);
        let pe = r.pe.as_ref().unwrap();
        assert!(!r
            .signals
            .iter()
            .any(|s| s.code == "process_injection_imports"));
        let overlay = pe.overlay.as_ref().unwrap();
        assert_eq!(overlay.offset, 0xc00);
        assert_eq!(overlay.size, 0x1000 - 0xc00 + 8192);
        assert!(r.signals.iter().any(|s| s.code == "high_entropy_overlay"));
    }

    #[test]
    fn long_names_are_truncated_not_unreadable() {
        let mut data = vec![b'A'; 600];
        data.push(0);
        let name = c_string(&data, 0).unwrap();
        assert_eq!(name.chars().count(), MAX_NAME_BYTES + 1);
        assert!(name.ends_with('…'));
        assert!(c_string(b"bad\x01name\0", 0).is_none());
        assert!(c_string(b"no-terminator", 0).is_none());
    }

    #[test]
    fn broken_tables_make_the_report_incomplete_not_clean() {
        let mut bytes = dll_with_imports(&["GetProcAddress"]);
        // Point the import directory far outside every section.
        let dirs = 0x84 + 20 + 112;
        bytes[dirs + 8..dirs + 12].copy_from_slice(&0x00ff_0000u32.to_le_bytes());
        let r = inspect_bytes(&bytes);
        assert!(r
            .pe
            .as_ref()
            .unwrap()
            .problems
            .contains(&"import_directory_outside_sections"));
        assert_eq!(r.assessment, crate::model::Assessment::Incomplete);
        assert_ne!(r.risk, "low_signal");
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::model::{Assessment, Report};
    use std::time::Duration;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn minimal_pe(sections: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200 + usize::from(sections) * 40];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x86..0x88].copy_from_slice(&sections.to_le_bytes());
        bytes
    }

    fn check(bytes: &[u8], budget: Duration) -> Report {
        let mut report = Report::new("x.exe".into(), "pe");
        inspect(bytes, &mut report, &Budget::new(budget));
        report.finish();
        assert_eq!(
            report.analysis_complete,
            report.assessment == Assessment::Analyzed
        );
        if report.risk == "low_signal" {
            assert_eq!(report.assessment, Assessment::Analyzed);
        }
        report
    }

    #[test]
    fn mutated_headers_never_panic() {
        let mut rng = Rng(0x1234_5678_9abc_def1);
        for i in 0..3000u64 {
            let mut bytes = minimal_pe((i % 100) as u16);
            for _ in 0..(1 + rng.next() % 8) {
                let at = (rng.next() as usize) % bytes.len();
                bytes[at] = rng.next() as u8;
            }
            // Point the first section at random raw ranges, including past the end.
            let size = (rng.next() % 0x2_0000) as u32;
            let start = (rng.next() % 0x2_0000) as u32;
            bytes[0x98 + 16..0x98 + 20].copy_from_slice(&size.to_le_bytes());
            bytes[0x98 + 20..0x98 + 24].copy_from_slice(&start.to_le_bytes());
            check(&bytes, Duration::from_secs(60));
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut rng = Rng(0x0f0f_1e1e_2d2d_3c3c);
        for i in 0..1000 {
            let len = (rng.next() % 2048) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            if i % 2 == 0 && bytes.len() >= 2 {
                bytes[..2].copy_from_slice(b"MZ");
            }
            check(&bytes, Duration::from_secs(60));
        }
    }

    #[test]
    fn exhausted_budget_marks_pe_incomplete() {
        let report = check(&minimal_pe(1), Duration::ZERO);
        assert_eq!(report.assessment, Assessment::Incomplete);
        assert!(report.incomplete_reasons.contains(&"analysis_time_limit"));
    }
}
