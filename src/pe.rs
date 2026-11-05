use crate::model::Report;

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
    counts.into_iter().filter(|c| *c != 0).map(|count| {
        let p = count as f64 / data.len() as f64;
        -p * p.log2()
    }).sum()
}

/// Strictly bounded PE structural triage; not Authenticode verification or a disassembler.
/// All offsets derive from the file and are checked before slicing.
pub fn inspect(data: &[u8], report: &mut Report) {
    if data.get(..2) != Some(b"MZ") {
        report.unavailable("invalid_pe", "Missing DOS MZ signature");
        return;
    }
    let Some(pe_offset) = le_u32(data, 0x3c).map(|n| n as usize) else {
        report.unavailable("invalid_pe", "Truncated DOS header");
        return;
    };
    if data.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0") {
        report.unavailable("invalid_pe", "Missing NT PE signature");
        return;
    }
    let coff = pe_offset + 4;
    let Some(section_count) = le_u16(data, coff + 2).map(usize::from) else {
        report.unavailable("invalid_pe", "Truncated COFF header");
        return;
    };
    let Some(optional_header_bytes) = le_u16(data, coff + 16).map(usize::from) else {
        report.unavailable("invalid_pe", "Missing optional header size");
        return;
    };
    if section_count == 0 || section_count > 96 {
        report.unavailable("invalid_pe", "Section count outside safe bounds");
        return;
    }
    let Some(sections) = coff.checked_add(20).and_then(|n| n.checked_add(optional_header_bytes)) else {
        report.unavailable("invalid_pe", "Invalid PE section offsets");
        return;
    };
    let Some(end) = section_count.checked_mul(40).and_then(|n| sections.checked_add(n)) else {
        report.unavailable("invalid_pe", "Invalid PE section table");
        return;
    };
    if end > data.len() {
        report.unavailable("invalid_pe", "Truncated PE section table");
        return;
    }

    let mut has_wx = false;
    let mut high_entropy = false;
    for i in 0..section_count {
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
            report.unavailable("invalid_pe", "Section raw data pointer overflow");
            return;
        };
        let Some(raw) = data.get(start..stop) else {
            report.unavailable("invalid_pe", "Section raw data outside file");
            return;
        };
        if raw.len() >= 4096 && entropy(&raw[..raw.len().min(65536)]) >= 7.3 {
            high_entropy = true;
        }
    }
    if has_wx {
        report.add("writable_executable_section", 40, "pe_section", "A section is both writable and executable");
    }
    if high_entropy {
        report.add("high_section_entropy", 20, "pe_section", "A section has high entropy (packing is possible, not proof of malware)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Report;

    #[test]
    fn rejects_truncated_pe() {
        let mut report = Report::new("sample.exe".into(), "pe");
        inspect(b"MZ", &mut report);
        report.finish();
        assert_eq!(report.risk, "not_assessed");
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
        inspect(&bytes, &mut report);
        report.finish();
        assert!(report.signals.iter().any(|s| s.code == "writable_executable_section"));
    }
}
