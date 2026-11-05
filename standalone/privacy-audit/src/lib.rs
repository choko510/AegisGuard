//! Standalone, read-only QA of explicitly supplied UTF-8 JSONL or log files.
//! This is a detector, not a sanitizer: callers must not publish unchecked input.
use regex::Regex;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 64 * 1024;
pub const MAX_TOKEN_BYTES: usize = 4096;
pub const MAX_LINES: usize = 20_000;
pub const MAX_FINDINGS: usize = 1000;
pub const MAX_JSON_NODES: usize = 10_000;
pub const MAX_JSON_DEPTH: usize = 32;
const MAX_DURATION: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Auto,
    Jsonl,
    Log,
}

impl Mode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "jsonl" => Some(Self::Jsonl),
            "log" => Some(Self::Log),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Jsonl => "jsonl",
            Self::Log => "log",
        }
    }
}

#[derive(Clone, Debug)]
struct LeakFinding {
    category: &'static str,
    severity: &'static str,
    line_no: usize,
    rule_id: &'static str,
}

impl LeakFinding {
    fn to_json(&self) -> Value {
        json!({
            "category": self.category,
            "severity": self.severity,
            "line_no": self.line_no,
            "rule_id": self.rule_id,
            "redacted_excerpt_or_hash": "[REDACTED]"
        })
    }
}

struct Rule {
    id: &'static str,
    category: &'static str,
    severity: &'static str,
    expression: Regex,
    captured: bool,
}

fn rules() -> &'static Vec<Rule> {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let patterns = [
            (
                "authorization_bearer",
                "credential",
                "high",
                r#"(?i)\b(?:authorization["']?\s*[:=]\s*["']?bearer|bearer)\s+([A-Za-z0-9._~+/-]{8,})"#,
                true,
            ),
            (
                "jwt_compact",
                "credential",
                "high",
                r"\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b",
                true,
            ),
            (
                "cookie_header",
                "browser_credential",
                "high",
                r#"(?i)\b(?:set-cookie|cookie)["']?\s*[:=]\s*["']?([A-Za-z0-9_.-]{2,}=[^\s;,"']{4,})"#,
                true,
            ),
            (
                "secret_assignment",
                "credential",
                "high",
                r#"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|pwd|secret|token)["']?\s*[:=]\s*["']?([A-Za-z0-9._~+/-]{8,})"#,
                true,
            ),
            (
                "powershell_secret_argument",
                "command_line_secret",
                "high",
                r#"(?i)(?:--|-|/)(?:password|token|api[_-]?key|secret)\s+["']?([A-Za-z0-9._~+/-]{8,})"#,
                true,
            ),
            (
                "sensitive_url_query",
                "url_credential",
                "high",
                r#"(?i)[?&](?:access_token|refresh_token|api[_-]?key|apikey|token|password|secret|auth|signature|sig|key|code)=([^&#\s"'<>]{8,})"#,
                true,
            ),
            (
                "bitlocker_recovery_password",
                "recovery_key",
                "critical",
                r"\b((?:[0-9]{6}-){7}[0-9]{6})\b",
                true,
            ),
            (
                "windows_home_path",
                "personal_path",
                "medium",
                r#"(?i)\b[A-Z]:\\Users\\([^\\/"'\r\n]{2,64})(?:\\|$|\s|["'])"#,
                true,
            ),
            (
                "unix_home_path",
                "personal_path",
                "medium",
                r"(?i)(?:^|[\s=:(])(?:/home/|/Users/)([A-Za-z0-9_.-]{2,})",
                true,
            ),
            (
                "private_key_pem",
                "private_key",
                "critical",
                r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
                true,
            ),
        ];
        patterns
            .into_iter()
            .map(|(id, category, severity, pattern, captured)| Rule {
                id,
                category,
                severity,
                expression: regex::RegexBuilder::new(pattern)
                    .size_limit(2 * 1024 * 1024)
                    .build()
                    .expect("fixed built-in rule must compile"),
                captured,
            })
            .collect()
    })
}

fn is_masked(text: &str) -> bool {
    let mut t = text
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == ' ');
    // Masked header values commonly retain a "Bearer " or "sid=" prefix.
    // Limit peeling to three levels to avoid adversarial recursion.
    for _ in 0..3 {
        if t.get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("bearer "))
        {
            t = &t[7..];
        } else if let Some((name, value)) = t.split_once('=') {
            if !name.is_empty()
                && name.len() <= 64
                && !name.contains(char::is_whitespace)
                && !value.is_empty()
            {
                t = value;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    let lower = t.to_ascii_lowercase();
    t.is_empty()
        || matches!(
            lower.as_str(),
            "redacted"
                | "[redacted]"
                | "<redacted>"
                | "[masked]"
                | "<masked>"
                | "masked"
                | "[hidden]"
                | "null"
                | "none"
                | "n/a"
                | "unknown"
                | "-"
        )
        || (t.len() >= 3 && t.bytes().all(|b| b == b'*' || b == b'x' || b == b'X'))
}

fn fold_limited(text: &str) -> String {
    // Full-width ASCII compatibility folding, not a complete Unicode NFKC operation.
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let c = if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
            char::from_u32(c as u32 - 0xFEE0).unwrap_or(c)
        } else if c == '\u{3000}' {
            ' '
        } else {
            c
        };
        out.push(c);
    }
    for (from, to) in [
        ("&amp;", "&"),
        ("&#38;", "&"),
        ("&#x26;", "&"),
        ("&#X26;", "&"),
        ("&#61;", "="),
        ("&#x3d;", "="),
        ("&#x3D;", "="),
        ("&equals;", "="),
        ("&quot;", "\""),
        ("&#34;", "\""),
        ("&apos;", "'"),
        ("&#39;", "'"),
    ] {
        out = out.replace(from, to);
    }
    // Common percent encodings that can hide a URL query separator.
    for (from, to) in [
        ("%3D", "="),
        ("%3d", "="),
        ("%26", "&"),
        ("%3F", "?"),
        ("%3f", "?"),
    ] {
        out = out.replace(from, to);
    }
    out
}

fn sensitive_field(key: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let canonical: String = fold_limited(key)
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    match canonical.as_str() {
        "authorization" | "bearertoken" | "accesstoken" | "refreshtoken" | "idtoken" | "apikey"
        | "clientsecret" | "password" | "passwd" | "pwd" | "secret" | "token" | "credential"
        | "credentials" | "privatekey" => Some(("credential", "high", "structured_secret_field")),
        "cookie" | "setcookie" | "browserpassword" => {
            Some(("browser_credential", "high", "structured_browser_secret"))
        }
        "bitlockerrecoverykey" | "recoverypassword" => {
            Some(("recovery_key", "critical", "structured_recovery_key"))
        }
        "username" | "userprofile" | "homepath" | "homedir" | "computername" => {
            Some(("personal_identifier", "medium", "structured_identifier"))
        }
        _ => None,
    }
}

fn safe_account(account: &str) -> bool {
    matches!(
        account.to_ascii_lowercase().as_str(),
        "public"
            | "default"
            | "default user"
            | "defaultuser0"
            | "system"
            | "shared"
            | "allusers"
            | "all users"
            | "administrator"
            | "username"
            | "yourname"
            | "user"
    )
}

// JSON maps must not silently drop an earlier value on duplicate keys.
// The normal serde_json::Value representation keeps the last key. Fail
// closed instead of allowing overwritten secrets to produce a clean report.
struct UniqueKeys;

struct UniqueKeysVisitor;

impl<'de> Deserialize<'de> for UniqueKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueKeysVisitor)
    }
}

impl<'de> Visitor<'de> for UniqueKeysVisitor {
    type Value = UniqueKeys;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate_json_key"));
            }
            let _: UniqueKeys = map.next_value()?;
        }
        Ok(UniqueKeys)
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        while seq.next_element::<UniqueKeys>()?.is_some() {}
        Ok(UniqueKeys)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(UniqueKeys)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(UniqueKeys)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(UniqueKeys)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(UniqueKeys)
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(UniqueKeys)
    }
    fn visit_string<E: de::Error>(self, _: String) -> Result<Self::Value, E> {
        Ok(UniqueKeys)
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueKeys)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueKeys)
    }
}

fn reject_duplicate_json_keys(line: &str) -> Result<(), &'static str> {
    serde_json::from_str::<UniqueKeys>(line)
        .map(|_| ())
        .map_err(|e| {
            if e.to_string().contains("duplicate_json_key") {
                "duplicate_json_key"
            } else {
                "malformed_json"
            }
        })
}

struct Inspector {
    entries: Vec<LeakFinding>,
    seen: HashSet<(usize, &'static str)>,
    json_nodes: usize,
    lines_json: usize,
    lines_log: usize,
    started: Instant,
}

impl Inspector {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            seen: HashSet::new(),
            json_nodes: 0,
            lines_json: 0,
            lines_log: 0,
            started: Instant::now(),
        }
    }

    fn add(
        &mut self,
        line_no: usize,
        rule_id: &'static str,
        category: &'static str,
        severity: &'static str,
    ) -> Result<(), &'static str> {
        if self.seen.insert((line_no, rule_id)) {
            if self.entries.len() >= MAX_FINDINGS {
                return Err("finding_limit_exceeded");
            }
            self.entries.push(LeakFinding {
                category,
                severity,
                line_no,
                rule_id,
            });
        }
        Ok(())
    }

    fn scan_text(&mut self, text: &str, line_no: usize) -> Result<(), &'static str> {
        if text.len() > MAX_LINE_BYTES {
            return Err("line_limit_exceeded");
        }
        let normalized = fold_limited(text);
        for rule in rules() {
            for capture in rule.expression.captures_iter(&normalized) {
                let candidate = if rule.captured {
                    capture.get(1).map(|m| m.as_str()).unwrap_or("")
                } else {
                    capture.get(0).map(|m| m.as_str()).unwrap_or("")
                };
                if is_masked(candidate) {
                    continue;
                }
                if matches!(rule.id, "windows_home_path" | "unix_home_path")
                    && safe_account(candidate)
                {
                    continue;
                }
                self.add(line_no, rule.id, rule.category, rule.severity)?;
            }
        }
        Ok(())
    }

    fn visit_json(
        &mut self,
        value: &Value,
        parent_key: Option<&str>,
        depth: usize,
        line_no: usize,
    ) -> Result<(), &'static str> {
        if depth > MAX_JSON_DEPTH {
            return Err("json_depth_limit_exceeded");
        }
        if self.started.elapsed() > MAX_DURATION {
            return Err("time_limit_exceeded");
        }
        self.json_nodes += 1;
        if self.json_nodes > MAX_JSON_NODES {
            return Err("json_node_limit_exceeded");
        }
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if key.len() > MAX_TOKEN_BYTES {
                        return Err("token_limit_exceeded");
                    }
                    self.scan_text(key, line_no)?;
                    // A secret-bearing parent object/array stays sensitive until a
                    // more specific secret key overrides it.
                    let effective_key = if sensitive_field(key).is_some() {
                        Some(key.as_str())
                    } else {
                        parent_key
                    };
                    self.visit_json(child, effective_key, depth + 1, line_no)?;
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.visit_json(item, parent_key, depth + 1, line_no)?;
                }
            }
            Value::String(value) => {
                if value.len() > MAX_TOKEN_BYTES {
                    return Err("token_limit_exceeded");
                }
                if !is_masked(value) {
                    if let Some((category, severity, rule_id)) =
                        parent_key.and_then(sensitive_field)
                    {
                        self.add(line_no, rule_id, category, severity)?;
                    }
                    self.scan_text(value, line_no)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn inspect_line(&mut self, line: &str, line_no: usize, mode: Mode) -> Result<(), &'static str> {
        if self.started.elapsed() > MAX_DURATION {
            return Err("time_limit_exceeded");
        }
        if line.trim().is_empty() {
            return Ok(());
        }
        let json = match mode {
            Mode::Jsonl => true,
            Mode::Log => false,
            Mode::Auto => matches!(
                line.trim_start().as_bytes().first(),
                Some(b'{') | Some(b'[')
            ),
        };
        if json {
            // Duplicate keys (including Unicode-escaped aliases) must not hide
            // an earlier sensitive value in serde_json::Value's last-wins map.
            reject_duplicate_json_keys(line)?;
            let parsed: Value = serde_json::from_str(line).map_err(|_| "malformed_json")?;
            if !parsed.is_object() && !parsed.is_array() {
                return Err("json_top_level_not_container");
            }
            self.lines_json += 1;
            // Parsed maps discard earlier duplicate keys. Check raw syntax too,
            // so an overwritten secret does not disappear from inspection.
            self.scan_text(line, line_no)?;
            self.visit_json(&parsed, None, 0, line_no)?;
        } else {
            self.lines_log += 1;
            if line
                .split_whitespace()
                .any(|token| token.len() > MAX_TOKEN_BYTES)
            {
                return Err("token_limit_exceeded");
            }
            self.scan_text(line, line_no)?;
        }
        Ok(())
    }
}

fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn report(
    status: &str,
    problem: Option<&'static str>,
    inspected: Inspector,
    lines_read: usize,
    bytes_read: u64,
    mode: Mode,
) -> Value {
    let mut warnings = Vec::new();
    if let Some(reason) = problem {
        warnings.push(reason);
    }
    if inspected.lines_json + inspected.lines_log == 0 && problem.is_none() {
        warnings.push("empty_input_not_assessed");
    }
    let entries: Vec<Value> = inspected.entries.iter().map(LeakFinding::to_json).collect();
    json!({
        "schema_version": 1,
        "module": "privacy-audit",
        "generated_at_unix_ms": timestamp_ms(),
        "status": status,
        "entries": entries,
        "warnings": warnings,
        "coverage": {
            "lines_read": lines_read,
            "bytes_read": bytes_read,
            "json_lines": inspected.lines_json,
            "log_lines": inspected.lines_log,
            "json_nodes": inspected.json_nodes,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_line_bytes": MAX_LINE_BYTES,
            "max_token_bytes": MAX_TOKEN_BYTES,
            "max_lines": MAX_LINES,
            "max_findings": MAX_FINDINGS,
            "mode": mode.label(),
            "complete": status == "complete"
        }
    })
}

fn failure(
    reason: &'static str,
    inspected: Inspector,
    lines_read: usize,
    bytes_read: u64,
    mode: Mode,
) -> Value {
    let status = if reason == "permission_denied" {
        "permission_denied"
    } else if lines_read > 0 {
        "partial"
    } else {
        "error"
    };
    report(
        status,
        Some(reason),
        inspected,
        lines_read,
        bytes_read,
        mode,
    )
}

/// Public in-memory path used by the synthetic tests; never writes the input.
pub fn audit_reader<R: BufRead>(mut reader: R, mode: Mode) -> Value {
    let mut inspected = Inspector::new();
    let mut bytes_read = 0u64;
    let mut lines_read = 0usize;
    loop {
        if inspected.started.elapsed() > MAX_DURATION {
            return failure(
                "time_limit_exceeded",
                inspected,
                lines_read,
                bytes_read,
                mode,
            );
        }
        let mut line = Vec::new();
        let count = {
            let mut limited = (&mut reader).take(MAX_LINE_BYTES as u64 + 1);
            limited.read_until(b'\n', &mut line)
        };
        let count = match count {
            Ok(count) => count,
            Err(error) => {
                return failure(
                    if error.kind() == std::io::ErrorKind::PermissionDenied {
                        "permission_denied"
                    } else {
                        "read_failed"
                    },
                    inspected,
                    lines_read,
                    bytes_read,
                    mode,
                );
            }
        };
        if count == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(count as u64);
        if bytes_read > MAX_FILE_BYTES {
            return failure(
                "file_limit_exceeded",
                inspected,
                lines_read,
                bytes_read,
                mode,
            );
        }
        if count > MAX_LINE_BYTES {
            return failure(
                "line_limit_exceeded",
                inspected,
                lines_read,
                bytes_read,
                mode,
            );
        }
        if lines_read >= MAX_LINES {
            return failure(
                "line_count_limit_exceeded",
                inspected,
                lines_read,
                bytes_read,
                mode,
            );
        }
        lines_read += 1;
        let line = match std::str::from_utf8(&line) {
            Ok(line) => line.trim_end_matches(['\n', '\r']),
            Err(_) => {
                return failure("invalid_utf8", inspected, lines_read, bytes_read, mode);
            }
        };
        if let Err(reason) = inspected.inspect_line(line, lines_read, mode) {
            return failure(reason, inspected, lines_read, bytes_read, mode);
        }
    }
    let status = if inspected.lines_json + inspected.lines_log == 0 {
        "partial"
    } else {
        "complete"
    };
    report(status, None, inspected, lines_read, bytes_read, mode)
}

/// Explicit file only. No directory traversal, browser access, network, or mutations.
pub fn audit_path(path: &Path, mode: Mode) -> Value {
    let empty = || Inspector::new();
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            let code = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "permission_denied"
            } else {
                "file_metadata_unavailable"
            };
            return failure(code, empty(), 0, 0, mode);
        }
    };
    if meta.file_type().is_symlink() {
        return failure("symlink_not_followed", empty(), 0, 0, mode);
    }
    if !meta.is_file() {
        return failure("not_regular_file", empty(), 0, 0, mode);
    }
    if meta.len() > MAX_FILE_BYTES {
        return failure("file_limit_exceeded", empty(), 0, 0, mode);
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            let code = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "permission_denied"
            } else {
                "file_open_failed"
            };
            return failure(code, empty(), 0, 0, mode);
        }
    };
    let opened = match file.metadata() {
        Ok(m) => m,
        Err(_) => return failure("file_metadata_unavailable", empty(), 0, 0, mode),
    };
    if !opened.is_file() || opened.len() > MAX_FILE_BYTES || opened.len() != meta.len() {
        return failure("input_changed_or_invalid", empty(), 0, 0, mode);
    }
    let mut reader = BufReader::new(file);
    let mut output = audit_reader(&mut reader, mode);
    let after = reader.get_ref().metadata();
    if after.is_err() || after.ok().is_some_and(|m| m.len() != opened.len()) {
        output["status"] = json!("partial");
        output["coverage"]["complete"] = json!(false);
        if let Some(warnings) = output["warnings"].as_array_mut() {
            warnings.push(json!("input_changed_during_read"));
        }
    }
    output
}

/// Exit 0: complete/no findings; exit 2: complete with findings; exit 3: incomplete/error.
pub fn exit_code(output: &Value) -> i32 {
    if output["status"] != "complete" {
        3
    } else if output["entries"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        2
    } else {
        0
    }
}

/// Safety self-test uses only synthetic strings and keeps all test data out of output.
pub fn self_test() -> Value {
    let fixtures = [
        (r#"{"Authorization":"Bearer syntheticabcdefgh1234"}"#, true),
        (r#"{"event":{"CommandLine":"-Password syntheticPass1234"}}"#, true),
        (r#"{"Cookie":"session=syntheticCookieExample"}"#, true),
        (r#"{"path":"C:\\Users\\test-person\\Desktop\\file.txt"}"#, true),
        (r#"{"secret":"[REDACTED]"}"#, false),
        (r#"{"description":"token bucket rate limiter"}"#, false),
        (r#"{"filename":"base64_dGVzdF9ub3Rfc2VjcmV0"}"#, false),
    ];
    let mut passed = 0usize;
    for (content, expected_finding) in fixtures {
        let output = audit_reader(content.as_bytes(), Mode::Jsonl);
        let found = output["entries"].as_array().is_some_and(|v| !v.is_empty());
        if output["status"] == "complete" && found == expected_finding {
            passed += 1;
        }
    }
    json!({
        "schema_version": 1,
        "module": "privacy-audit",
        "generated_at_unix_ms": timestamp_ms(),
        "status": if passed == fixtures.len() { "complete" } else { "error" },
        "entries": [],
        "warnings": if passed == fixtures.len() { Vec::<&str>::new() } else { vec!["self_test_failed"] },
        "coverage": {
            "synthetic_tests_passed": passed,
            "synthetic_tests_total": fixtures.len(),
            "complete": passed == fixtures.len()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_and_plain_log_are_separate() {
        let json = audit_reader(
            r#"{"api_key":"syntheticSECRET12345","note":"cookie recipe"}"#.as_bytes(),
            Mode::Jsonl,
        );
        assert_eq!(json["status"], "complete");
        assert_eq!(json["coverage"]["json_lines"], 1);
        assert!(!json["entries"].as_array().unwrap().is_empty());
        let log = audit_reader(&b"Authorization: Bearer syntheticTEST12345\n"[..], Mode::Log);
        assert_eq!(log["coverage"]["log_lines"], 1);
        assert_eq!(exit_code(&log), 2);
    }

    #[test]
    fn no_raw_values_or_local_paths_in_findings() {
        let secret = "syntheticSECRET12345";
        let input = format!(
            "{{\"token\":\"{secret}\",\"path\":\"C:\\\\Users\\\\real-looking-name\\\\a\"}}"
        );
        let result = audit_reader(input.as_bytes(), Mode::Jsonl);
        let encoded = result.to_string();
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains("real-looking-name"));
        assert!(!encoded.contains("C:\\"));
        assert_eq!(
            result["entries"][0]["redacted_excerpt_or_hash"],
            "[REDACTED]"
        );
    }

    #[test]
    fn detects_recovery_url_cookie_jwt_and_powershell() {
        let sample = concat!(
            "https://example.invalid/?ignored=0&token=syntheticTOKEN123456789\n",
            "Cookie: sid=syntheticSESSION1234\n",
            "000011-000022-000033-000044-000055-000066-000077-000088\n",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlMQ\n",
            "powershell -Password syntheticPASS0123\n"
        );
        let result = audit_reader(sample.as_bytes(), Mode::Log);
        assert_eq!(exit_code(&result), 2);
        assert!(result["entries"].as_array().unwrap().len() >= 5);
    }

    #[test]
    fn duplicate_json_key_cannot_hide_the_first_secret() {
        let input = r#"{"token":"syntheticFIRST12345","token":"[REDACTED]"}"#;
        let result = audit_reader(input.as_bytes(), Mode::Jsonl);
        assert_eq!(exit_code(&result), 3);
        assert_eq!(result["warnings"][0], "duplicate_json_key");
        assert!(!result.to_string().contains("syntheticFIRST12345"));
    }

    #[test]
    fn masked_false_positives_and_fullwidth() {
        let clean = concat!(
            "{\"Authorization\":\"[REDACTED]\",\"Cookie\":\"***\",\"password\":null}\n",
            "{\"note\":\"Bearer [REDACTED] and cookie recipe\"}\n",
            "{\"tag\":\"base64 dGVzdF9ub3Rfc2VjcmV0\"}\n"
        );
        let clean_result = audit_reader(clean.as_bytes(), Mode::Jsonl);
        assert_eq!(exit_code(&clean_result), 0);
        let header_masks = audit_reader(
            &br#"{"Authorization":"Bearer [REDACTED]","Cookie":"sid=***"}"#[..],
            Mode::Jsonl,
        );
        assert_eq!(exit_code(&header_masks), 0);
        let personal = audit_reader(
            r#"{"path":"C:\\Users\\an example user\\Documents\\notes.txt"}"#.as_bytes(),
            Mode::Jsonl,
        );
        assert_eq!(exit_code(&personal), 2);
        let wide = audit_reader("ｔｏｋｅｎ＝syntheticABCDEFG12345\n".as_bytes(), Mode::Log);
        assert_eq!(exit_code(&wide), 2);
    }

    #[test]
    fn invalid_utf8_giant_line_and_malformed_json_fail_closed() {
        assert_eq!(exit_code(&audit_reader(&[0xff][..], Mode::Log)), 3);
        let huge = "x".repeat(MAX_LINE_BYTES + 5);
        let result = audit_reader(huge.as_bytes(), Mode::Log);
        assert_eq!(result["warnings"][0], "line_limit_exceeded");
        let bad = audit_reader(&b"{\"token\":\"syntheticSECRET12345\""[..], Mode::Auto);
        assert_eq!(bad["warnings"][0], "malformed_json");
        assert_eq!(exit_code(&bad), 3);
        assert!(!bad.to_string().contains("syntheticSECRET"));
    }

    #[test]
    fn empty_and_oversized_tokens_are_not_success() {
        assert_eq!(exit_code(&audit_reader(&b""[..], Mode::Auto)), 3);
        assert_eq!(exit_code(&audit_reader(&b"  \n\t\n"[..], Mode::Auto)), 3);
        let token = "A".repeat(MAX_TOKEN_BYTES + 1);
        let result = audit_reader(token.as_bytes(), Mode::Log);
        assert_eq!(exit_code(&result), 3);
        assert_eq!(result["warnings"][0], "token_limit_exceeded");
    }

    #[test]
    fn self_test_is_silent_about_synthetic_values() {
        let result = self_test();
        assert_eq!(result["status"], "complete");
        assert_eq!(result["coverage"]["synthetic_tests_total"], 7);
        assert_eq!(result["entries"].as_array().map(Vec::len), Some(0));
        assert!(!result.to_string().contains("syntheticSECRET12345"));
    }
}
