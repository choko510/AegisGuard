//! Strict, bounded parser for Zone.Identifier. Never keeps or returns URL values.
pub const MAX_STREAM_BYTES: usize = 64 * 1024;
const MAX_LINES: usize = 1024;
const MAX_LINE_CHARS: usize = 8192;

#[derive(Debug)]
pub struct Parsed {
    pub zone_id: Option<u8>,
    pub source_url_recorded: bool,
    pub referrer_url_recorded: bool,
    pub complete: bool,
    pub warnings: Vec<&'static str>,
}

fn warn(warnings: &mut Vec<&'static str>, code: &'static str) {
    if !warnings.contains(&code) {
        warnings.push(code);
    }
}

fn decode(bytes: &[u8]) -> Result<String, &'static str> {
    if bytes.len() > MAX_STREAM_BYTES {
        return Err("stream_size_limit_exceeded");
    }
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        if (bytes.len() - 2) % 2 != 0 {
            return Err("malformed_utf16");
        }
        let little = bytes[0] == 0xff;
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| {
                if little {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            })
            .collect();
        return String::from_utf16(&units).map_err(|_| "malformed_utf16");
    }
    let content = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    std::str::from_utf8(content)
        .map(str::to_owned)
        .map_err(|_| "invalid_text_encoding")
}

pub fn parse(bytes: &[u8]) -> Parsed {
    let mut result = Parsed {
        zone_id: None,
        source_url_recorded: false,
        referrer_url_recorded: false,
        complete: true,
        warnings: vec![],
    };
    let text = match decode(bytes) {
        Ok(text) => text,
        Err(code) => {
            result.complete = false;
            result.warnings.push(code);
            return result;
        }
    };
    let mut in_zone_transfer = false;
    let mut seen_section = false;
    let mut seen_zone = false;
    let mut ambiguous_zone = false;
    for (index, line) in text.split('\n').enumerate() {
        if index >= MAX_LINES {
            warn(&mut result.warnings, "line_count_limit_exceeded");
            result.complete = false;
            ambiguous_zone = true;
            break;
        }
        if line.chars().count() > MAX_LINE_CHARS {
            warn(&mut result.warnings, "line_length_limit_exceeded");
            result.complete = false;
            ambiguous_zone = true;
            break;
        }
        // CRLF is legal; all other C0 controls (including injected CR/NUL) are not.
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.chars().any(|c| c.is_control() && c != '\t') {
            warn(&mut result.warnings, "invalid_control_character");
            result.complete = false;
            ambiguous_zone = true;
            break;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                warn(&mut result.warnings, "malformed_section");
                result.complete = false;
                ambiguous_zone = true;
                break;
            }
            let section = &line[1..line.len() - 1];
            in_zone_transfer = section.eq_ignore_ascii_case("ZoneTransfer");
            if in_zone_transfer {
                if seen_section {
                    warn(&mut result.warnings, "duplicate_zone_transfer_section");
                    result.complete = false;
                    ambiguous_zone = true;
                }
                seen_section = true;
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            warn(&mut result.warnings, "malformed_line");
            result.complete = false;
            ambiguous_zone = true;
            continue;
        };
        if !in_zone_transfer {
            continue;
        }
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case("ZoneId") {
            if seen_zone {
                warn(&mut result.warnings, "duplicate_zone_id");
                result.complete = false;
                ambiguous_zone = true;
            }
            seen_zone = true;
            match value.parse::<u8>() {
                Ok(zone @ 0..=4) if value.len() == 1 => result.zone_id = Some(zone),
                _ => {
                    warn(&mut result.warnings, "invalid_zone_id");
                    result.complete = false;
                    ambiguous_zone = true;
                }
            }
        } else if key.eq_ignore_ascii_case("HostUrl") {
            result.source_url_recorded = true;
        } else if key.eq_ignore_ascii_case("ReferrerUrl") {
            result.referrer_url_recorded = true;
        } else {
            warn(&mut result.warnings, "unknown_keys_ignored");
        }
    }
    if !seen_section {
        warn(&mut result.warnings, "zone_transfer_section_missing");
        result.complete = false;
    }
    if !seen_zone {
        warn(&mut result.warnings, "zone_id_missing");
        result.complete = false;
    }
    if ambiguous_zone {
        result.zone_id = None;
    }
    result
}

pub fn zone_name(id: u8) -> &'static str {
    match id {
        0 => "local_machine",
        1 => "local_intranet",
        2 => "trusted_sites",
        3 => "internet",
        4 => "restricted_sites",
        _ => "unknown",
    }
}
