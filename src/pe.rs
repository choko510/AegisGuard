use crate::budget::Budget;
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
