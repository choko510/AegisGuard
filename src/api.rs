//! Public I/O contract for front ends (CLI, GUI, service, IPC).
//!
//! The engine writes JSON/JSONL documents; front ends read them back through
//! the owned, deserializable views here. Every reader is bounded and
//! cancellable, and it reports what it could not read (corrupt lines, newer
//! schema versions, unknown fields, truncation, cancellation) instead of
//! silently dropping it, so nothing unreadable can be displayed as "clean".
use crate::{model, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// Version of this contract. Bump on any breaking change to the views below.
pub const API_VERSION: u32 = 1;

/// Completeness axis of a scan report (see [`model::Assessment`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    Analyzed,
    Incomplete,
    NotAssessed,
    /// A value this build does not know (written by a newer engine).
    #[serde(other)]
    Unknown,
}

/// Detection axis of a scan report (see [`model::SignalLevel`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalLevel {
    LowSignal,
    Review,
    High,
    NotEvaluated,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalView {
    pub code: String,
    pub severity: u32,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageView {
    #[serde(default)]
    pub bytes_read: u64,
    #[serde(default)]
    pub size_limit_bytes: Option<u64>,
    #[serde(default)]
    pub analyzers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineView {
    pub name: String,
    pub version: String,
    pub ruleset: String,
}

/// One scan report, v1 or v2. v2-only fields are `None` for v1 records, and
/// the axes are derived from the v1 `risk` so a v1 record is never upgraded
/// to "analyzed" without evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReportV2 {
    pub path: String,
    pub kind: String,
    pub status: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub score: u32,
    pub risk: String,
    #[serde(default)]
    pub decoded_layers: usize,
    #[serde(default)]
    pub signals: Vec<SignalView>,
    #[serde(default)]
    pub warning: Option<String>,
    #[serde(default)]
    pub analysis_complete: bool,
    #[serde(default)]
    pub incomplete_reasons: Vec<String>,
    /// Absent in v1 records.
    #[serde(default)]
    pub schema_version: Option<u32>,
    #[serde(default)]
    pub assessment: Option<Assessment>,
    #[serde(default)]
    pub signal_level: Option<SignalLevel>,
    #[serde(default)]
    pub not_assessed_reason: Option<String>,
    #[serde(default)]
    pub coverage: Option<CoverageView>,
    #[serde(default)]
    pub engine: Option<EngineView>,
    #[serde(default)]
    pub yara: Option<Value>,
    #[serde(default)]
    pub file_identity: Option<Value>,
    #[serde(default)]
    pub started_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub completed_at_unix_ms: Option<u64>,
    /// Fields this build does not know, kept so nothing is silently lost.
    #[serde(flatten)]
    pub unknown_fields: Map<String, Value>,
}

impl ScanReportV2 {
    /// Completeness, falling back to the v1 `risk`/`analysis_complete` fields.
    pub fn assessment(&self) -> Assessment {
        if let Some(a) = self.assessment {
            return a;
        }
        match self.risk.as_str() {
            "not_assessed" => Assessment::NotAssessed,
            _ if !self.analysis_complete => Assessment::Incomplete,
            "incomplete" => Assessment::Incomplete,
            "low_signal" | "review" | "high" => Assessment::Analyzed,
            _ => Assessment::Unknown,
        }
    }

    /// Detection strength, falling back to the v1 `risk`/`score` fields.
    pub fn signal_level(&self) -> SignalLevel {
        if let Some(s) = self.signal_level {
            return s;
        }
        match self.risk.as_str() {
            "review" => SignalLevel::Review,
            "high" => SignalLevel::High,
            "low_signal" | "incomplete" => SignalLevel::LowSignal,
            "not_assessed" if self.score == 0 => SignalLevel::NotEvaluated,
            _ => SignalLevel::Unknown,
        }
    }

    /// A record from a newer schema than this build understands.
    pub fn is_newer_schema(&self) -> bool {
        self.schema_version
            .is_some_and(|v| v > model::REPORT_SCHEMA_VERSION)
    }

    /// The run-level stop record written when a scan hit a budget or Ctrl-C.
    pub fn is_scan_stopped(&self) -> bool {
        self.status == "scan_stopped"
    }

    /// Only a complete analysis with a low signal may be shown as "nothing
    /// found", and even then not as "safe".
    pub fn nothing_found(&self) -> bool {
        self.assessment() == Assessment::Analyzed && self.signal_level() == SignalLevel::LowSignal
    }
}

/// Health of one event source (mirrors `events::collector::SensorHealth`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorHealth {
    pub source: String,
    pub channel_available: bool,
    #[serde(default)]
    pub resumed_from: Option<String>,
    #[serde(default)]
    pub received: u64,
    #[serde(default)]
    pub persisted: u64,
    #[serde(default)]
    pub parse_errors: u64,
    #[serde(default)]
    pub oversized: u64,
    #[serde(default)]
    pub drops: u64,
    #[serde(default)]
    pub queue_depth: u64,
    #[serde(default)]
    pub durable_cursor: Option<u64>,
    #[serde(default)]
    pub gap_detected: bool,
    #[serde(default)]
    pub access_error: Option<String>,
    #[serde(default)]
    pub last_success_at_unix_ms: Option<u64>,
    pub status: String,
}

/// Whether a correlation rule could be evaluated with the observed sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleStatus {
    pub rule_id: String,
    pub rule_version: u32,
    pub evaluable: bool,
    #[serde(default)]
    pub missing_sources: Vec<String>,
}

/// One correlation finding (mirrors `events::correlate::Finding`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationFinding {
    pub rule_id: String,
    pub rule_version: u32,
    pub process_key: String,
    #[serde(default)]
    pub event_refs: Vec<String>,
    #[serde(default)]
    pub window_start_unix_ms: Option<i64>,
    #[serde(default)]
    pub window_end_unix_ms: Option<i64>,
    pub confidence: String,
    #[serde(default)]
    pub missing_sources: Vec<String>,
    #[serde(default)]
    pub suppressed_reason: Option<String>,
    pub verdict: String,
    #[serde(default)]
    pub explanation: String,
}

/// Freshness of one IOC / rule source at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    Fresh,
    Stale,
    NeverUpdated,
    /// Timestamp in the future: treated as not fresh.
    ClockSkew,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFreshness {
    pub source_id: String,
    pub last_success_unix: Option<u64>,
    pub ttl_secs: u64,
    pub freshness: Freshness,
}

impl SourceFreshness {
    pub fn evaluate(
        source_id: &str,
        last_success_unix: Option<u64>,
        ttl_secs: u64,
        now: u64,
    ) -> Self {
        let freshness = match last_success_unix {
            None | Some(0) => Freshness::NeverUpdated,
            Some(t) if t > now.saturating_add(300) => Freshness::ClockSkew,
            Some(t) if now.saturating_sub(t) <= ttl_secs => Freshness::Fresh,
            Some(_) => Freshness::Stale,
        };
        Self {
            source_id: source_id.to_string(),
            last_success_unix,
            ttl_secs,
            freshness,
        }
    }
}

/// Progress of a long-running job, for UIs. `total` is `None` when unknown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobProgress {
    pub phase: String,
    pub done: u64,
    pub total: Option<u64>,
    pub cancelled: bool,
    pub finished: bool,
}

/// Limits for reading a JSONL document.
#[derive(Debug, Clone, Copy)]
pub struct ReadLimits {
    pub max_bytes: u64,
    pub max_records: usize,
    pub max_line_bytes: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024,
            max_records: 1_000_000,
            max_line_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineProblem {
    /// 1-based line number.
    pub line: u64,
    pub reason: String,
}

/// Why reading stopped before the end of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Truncation {
    MaxBytes,
    MaxRecords,
    Cancelled,
}

/// The result of a bounded read. `truncated` and `problems` must be shown;
/// a partially read file is not a complete history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadOutcome<T> {
    pub records: Vec<T>,
    pub problems: Vec<LineProblem>,
    /// Problems beyond the stored `problems` list (which is capped).
    pub problems_omitted: u64,
    pub newer_schema_records: u64,
    pub records_with_unknown_fields: u64,
    pub truncated: Option<Truncation>,
}

impl<T> ReadOutcome<T> {
    /// True when every line was read and understood.
    pub fn complete(&self) -> bool {
        self.truncated.is_none()
            && self.problems.is_empty()
            && self.problems_omitted == 0
            && self.newer_schema_records == 0
    }
}

const MAX_STORED_PROBLEMS: usize = 1000;

/// Read scan JSONL (from `scan --output` or stdout) with limits and
/// cancellation. Over-long, non-UTF-8 and malformed lines are reported per
/// line and do not stop the read.
pub fn read_scan_jsonl(
    path: &Path,
    limits: ReadLimits,
    cancel: &AtomicBool,
) -> Result<ReadOutcome<ScanReportV2>> {
    let file = std::fs::File::open(path)?;
    read_scan_jsonl_from(file, limits, cancel)
}

pub fn read_scan_jsonl_from(
    reader: impl Read,
    limits: ReadLimits,
    cancel: &AtomicBool,
) -> Result<ReadOutcome<ScanReportV2>> {
    let mut reader = BufReader::new(reader.take(limits.max_bytes.saturating_add(1)));
    let mut out = ReadOutcome {
        records: Vec::new(),
        problems: Vec::new(),
        problems_omitted: 0,
        newer_schema_records: 0,
        records_with_unknown_fields: 0,
        truncated: None,
    };
    let problem = |out: &mut ReadOutcome<ScanReportV2>, line: u64, reason: String| {
        if out.problems.len() < MAX_STORED_PROBLEMS {
            out.problems.push(LineProblem { line, reason });
        } else {
            out.problems_omitted += 1;
        }
    };
    let mut consumed: u64 = 0;
    let mut line_no: u64 = 0;
    let mut buf = Vec::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            out.truncated = Some(Truncation::Cancelled);
            break;
        }
        if out.records.len() >= limits.max_records {
            // Only a truncation if there is anything left to read.
            if !reader.fill_buf()?.is_empty() {
                out.truncated = Some(Truncation::MaxRecords);
            }
            break;
        }
        buf.clear();
        let cap = u64::try_from(limits.max_line_bytes).unwrap_or(u64::MAX) + 1;
        let n = (&mut reader).take(cap).read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        consumed += n as u64;
        if consumed > limits.max_bytes {
            out.truncated = Some(Truncation::MaxBytes);
            break;
        }
        line_no += 1;
        if buf.len() > limits.max_line_bytes && buf.last() != Some(&b'\n') {
            // Skip the rest of the over-long line without buffering it.
            loop {
                let chunk = reader.fill_buf()?;
                if chunk.is_empty() {
                    break;
                }
                let (skip, done) = match chunk.iter().position(|&b| b == b'\n') {
                    Some(i) => (i + 1, true),
                    None => (chunk.len(), false),
                };
                reader.consume(skip);
                consumed += skip as u64;
                if done {
                    break;
                }
            }
            problem(&mut out, line_no, "line exceeds the length limit".into());
            if consumed > limits.max_bytes {
                out.truncated = Some(Truncation::MaxBytes);
                break;
            }
            continue;
        }
        let text = match std::str::from_utf8(&buf) {
            Ok(t) => t.trim(),
            Err(_) => {
                problem(&mut out, line_no, "line is not UTF-8".into());
                continue;
            }
        };
        if text.is_empty() {
            continue;
        }
        match serde_json::from_str::<ScanReportV2>(text) {
            Ok(record) => {
                if record.is_newer_schema() {
                    out.newer_schema_records += 1;
                }
                if !record.unknown_fields.is_empty() {
                    out.records_with_unknown_fields += 1;
                }
                out.records.push(record);
            }
            Err(e) => problem(&mut out, line_no, format!("not a scan report: {e}")),
        }
    }
    Ok(out)
}

/// Kind of a saved engine output, detected from its content (not its name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKind {
    ScanReport,
    SensorHealth,
    Correlation,
    IocAttribution,
    DefenderAudit,
    C2Status,
    FimCheck,
    /// `rules status/install/rollback` output.
    RulePack,
    /// `browser k2f` output.
    BrowserCheck,
    Unknown,
}

/// Recognize which command produced a JSON object.
pub fn classify(value: &Value) -> DocumentKind {
    let has = |key: &str| value.get(key).is_some();
    if has("path") && has("risk") {
        DocumentKind::ScanReport
    } else if has("channel_available") && has("durable_cursor") {
        DocumentKind::SensorHealth
    } else if value
        .get("correlation")
        .is_some_and(|c| c.get("rules").is_some())
    {
        DocumentKind::Correlation
    } else if value
        .get("report")
        .is_some_and(|r| r.get("visibility").is_some())
    {
        DocumentKind::IocAttribution
    } else if has("controls") && has("available") {
        DocumentKind::DefenderAudit
    } else if has("feeds") && has("indicators") {
        DocumentKind::C2Status
    } else if has("changes") && has("not_monitored") {
        DocumentKind::FimCheck
    } else if has("payload_sha256") && has("sequence") {
        DocumentKind::RulePack
    } else if has("check_id") && has("verdict") {
        DocumentKind::BrowserCheck
    } else {
        DocumentKind::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str, limits: ReadLimits) -> ReadOutcome<ScanReportV2> {
        read_scan_jsonl_from(text.as_bytes(), limits, &AtomicBool::new(false)).unwrap()
    }

    const V1: &str = r#"{"path":"a.ps1","kind":"script","status":"incomplete","sha256":null,"score":0,"risk":"incomplete","decoded_layers":0,"signals":[],"warning":"w","analysis_complete":false,"incomplete_reasons":["decode_limit"]}"#;

    #[test]
    fn v1_records_keep_their_meaning() {
        let out = read(V1, ReadLimits::default());
        assert!(out.complete());
        let r = &out.records[0];
        assert_eq!(r.schema_version, None);
        assert_eq!(r.assessment(), Assessment::Incomplete);
        assert!(!r.nothing_found());
    }

    #[test]
    fn current_engine_output_round_trips() {
        let mut report = model::Report::new("x.ps1".into(), "script");
        report.add("DOWNLOAD", 30, "raw", "downloads");
        report.finish();
        let line = serde_json::to_string(&report).unwrap();
        let out = read(&line, ReadLimits::default());
        assert!(out.complete(), "{:?}", out.problems);
        let r = &out.records[0];
        assert_eq!(r.schema_version, Some(model::REPORT_SCHEMA_VERSION));
        assert_eq!(r.assessment(), Assessment::Analyzed);
        assert_eq!(r.signal_level(), SignalLevel::Review);
        assert!(r.unknown_fields.is_empty());
        assert_eq!(
            classify(&serde_json::from_str(&line).unwrap()),
            DocumentKind::ScanReport
        );
    }

    #[test]
    fn newer_schema_and_unknown_values_are_flagged_not_trusted() {
        let line = r#"{"path":"a","kind":"pe","status":"analyzed","risk":"low_signal","analysis_complete":true,"schema_version":99,"assessment":"partially_magic","signal_level":"low_signal","future_field":1}"#;
        let out = read(line, ReadLimits::default());
        assert!(!out.complete());
        assert_eq!(out.newer_schema_records, 1);
        assert_eq!(out.records_with_unknown_fields, 1);
        let r = &out.records[0];
        assert_eq!(r.assessment(), Assessment::Unknown);
        assert!(!r.nothing_found());
    }

    #[test]
    fn corrupt_lines_are_reported_and_do_not_stop_the_read() {
        let text = format!("{V1}\n{{broken\n\u{0}\n{V1}\n");
        let out = read(&text, ReadLimits::default());
        assert_eq!(out.records.len(), 2);
        assert_eq!(out.problems.len(), 2);
        assert_eq!(out.problems[0].line, 2);
        assert!(!out.complete());
    }

    #[test]
    fn non_utf8_and_over_long_lines_are_skipped_with_a_reason() {
        let mut bytes = vec![0xff, 0xfe, b'\n'];
        bytes.extend(std::iter::repeat_n(b'a', 5000));
        bytes.push(b'\n');
        bytes.extend(V1.as_bytes());
        let limits = ReadLimits {
            max_line_bytes: 1024,
            ..ReadLimits::default()
        };
        let out = read_scan_jsonl_from(&bytes[..], limits, &AtomicBool::new(false)).unwrap();
        assert_eq!(out.records.len(), 1);
        assert_eq!(out.problems.len(), 2);
        assert!(out.problems[1].reason.contains("length"));
    }

    #[test]
    fn limits_and_cancellation_mark_the_read_truncated() {
        let text = format!("{V1}\n{V1}\n{V1}\n");
        let out = read(
            &text,
            ReadLimits {
                max_records: 2,
                ..ReadLimits::default()
            },
        );
        assert_eq!(out.records.len(), 2);
        assert_eq!(out.truncated, Some(Truncation::MaxRecords));

        let exact = read(
            &format!("{V1}\n{V1}\n"),
            ReadLimits {
                max_records: 2,
                ..ReadLimits::default()
            },
        );
        assert_eq!(exact.truncated, None);

        let out = read(
            &text,
            ReadLimits {
                max_bytes: 300,
                ..ReadLimits::default()
            },
        );
        assert_eq!(out.truncated, Some(Truncation::MaxBytes));

        let cancelled = read_scan_jsonl_from(
            text.as_bytes(),
            ReadLimits::default(),
            &AtomicBool::new(true),
        )
        .unwrap();
        assert_eq!(cancelled.truncated, Some(Truncation::Cancelled));
        assert!(cancelled.records.is_empty());
    }

    #[test]
    fn freshness_never_treats_missing_or_future_times_as_fresh() {
        let now = 1_000_000;
        assert_eq!(
            SourceFreshness::evaluate("s", None, 10, now).freshness,
            Freshness::NeverUpdated
        );
        assert_eq!(
            SourceFreshness::evaluate("s", Some(now + 3600), 10, now).freshness,
            Freshness::ClockSkew
        );
        assert_eq!(
            SourceFreshness::evaluate("s", Some(now - 5), 10, now).freshness,
            Freshness::Fresh
        );
        assert_eq!(
            SourceFreshness::evaluate("s", Some(now - 50), 10, now).freshness,
            Freshness::Stale
        );
    }

    #[test]
    fn sensor_health_reads_engine_output() {
        let health = crate::events::collector::SensorHealth {
            source: "windows_event_log".into(),
            channel_available: false,
            resumed_from: None,
            received: 0,
            persisted: 0,
            parse_errors: 0,
            oversized: 0,
            drops: 0,
            queue_depth: 0,
            durable_cursor: None,
            gap_detected: false,
            gaps: Vec::new(),
            access_error: Some("access denied".into()),
            last_success_at_unix_ms: None,
            status: "degraded",
        };
        let value = serde_json::to_value(&health).unwrap();
        assert_eq!(classify(&value), DocumentKind::SensorHealth);
        let view: SensorHealth = serde_json::from_value(value).unwrap();
        assert!(!view.channel_available);
    }
}
