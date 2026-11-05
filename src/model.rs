use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// JSONL report schema. v1 had no `schema_version` field; v2 only adds fields
/// and keeps every v1 field name, type and meaning unchanged.
pub const REPORT_SCHEMA_VERSION: u32 = 2;
/// Identifies the built-in static heuristics. Bump whenever a signal, its
/// severity or a deobfuscation rule changes so that old results can be told apart.
pub const BUILTIN_RULESET: &str = "builtin-static-1";

#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub code: &'static str,
    pub severity: u32,
    pub source: String,
    pub reason: &'static str,
}

impl Signal {
    pub fn new(
        code: &'static str,
        severity: u32,
        source: impl Into<String>,
        reason: &'static str,
    ) -> Self {
        Self {
            code,
            severity,
            source: source.into(),
            reason,
        }
    }
}

/// Completeness axis: how much of the input the analyzers actually reached.
/// Independent of whether any signal matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    Analyzed,
    Incomplete,
    NotAssessed,
}

/// Detection axis: strength of the matched signals only, ignoring completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalLevel {
    LowSignal,
    Review,
    High,
    /// Nothing was analyzed and nothing matched; no detection statement is possible.
    NotEvaluated,
}

#[derive(Debug, Serialize)]
pub struct Engine {
    pub name: &'static str,
    pub version: &'static str,
    pub ruleset: &'static str,
}

/// What the scanner reached. Unreached parts are listed in
/// `incomplete_reasons` / `not_assessed_reason`, never inferred from absence.
#[derive(Debug, Default, Serialize)]
pub struct Coverage {
    pub bytes_read: u64,
    pub size_limit_bytes: Option<u64>,
    pub analyzers: Vec<&'static str>,
}

/// Metadata of the scanned object. `observed_via` states whether it came from
/// the path (before open) or the opened handle; it is not yet a TOCTOU-proof identity.
#[derive(Debug, Serialize)]
pub struct FileIdentity {
    pub observed_via: &'static str,
    pub size_bytes: u64,
    pub modified_unix_ms: Option<u64>,
}

impl FileIdentity {
    pub fn from_metadata(meta: &std::fs::Metadata, observed_via: &'static str) -> Self {
        Self {
            observed_via,
            size_bytes: meta.len(),
            modified_unix_ms: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .and_then(|d| u64::try_from(d.as_millis()).ok()),
        }
    }
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[derive(Debug, Serialize)]
pub struct Report {
    // --- v1 fields (unchanged) ---
    pub path: String,
    pub kind: &'static str,
    pub status: &'static str,
    pub sha256: Option<String>,
    pub score: u32,
    pub risk: &'static str,
    pub decoded_layers: usize,
    pub signals: Vec<Signal>,
    pub warning: Option<String>,
    /// False when deobfuscation was bounded or truncated. Never imply a clean scan.
    pub analysis_complete: bool,
    pub incomplete_reasons: Vec<&'static str>,
    // --- v2 additions ---
    pub schema_version: u32,
    pub assessment: Assessment,
    pub signal_level: SignalLevel,
    /// Machine-readable cause when `assessment` is `not_assessed`.
    pub not_assessed_reason: Option<&'static str>,
    pub coverage: Coverage,
    pub file_identity: Option<FileIdentity>,
    pub engine: Engine,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
}

impl Report {
    pub fn new(path: String, kind: &'static str) -> Self {
        Self {
            path,
            kind,
            status: "analyzed",
            sha256: None,
            score: 0,
            risk: "low_signal",
            decoded_layers: 0,
            signals: Vec::new(),
            warning: None,
            analysis_complete: true,
            incomplete_reasons: Vec::new(),
            schema_version: REPORT_SCHEMA_VERSION,
            assessment: Assessment::Analyzed,
            signal_level: SignalLevel::LowSignal,
            not_assessed_reason: None,
            coverage: Coverage::default(),
            file_identity: None,
            engine: Engine {
                name: "aegisguard-static",
                version: env!("CARGO_PKG_VERSION"),
                ruleset: BUILTIN_RULESET,
            },
            started_at_unix_ms: now_unix_ms(),
            completed_at_unix_ms: 0,
        }
    }

    pub fn add(
        &mut self,
        code: &'static str,
        severity: u32,
        source: impl Into<String>,
        reason: &'static str,
    ) {
        let source = source.into();
        if !self
            .signals
            .iter()
            .any(|s| s.code == code && s.source == source)
        {
            self.signals
                .push(Signal::new(code, severity, source, reason));
        }
    }

    /// Record an analyzer that ran on this input (fully or partially).
    pub fn analyzer(&mut self, name: &'static str) {
        if !self.coverage.analyzers.contains(&name) {
            self.coverage.analyzers.push(name);
        }
    }

    /// An incomplete static analysis is not a clean result even if no indicators matched.
    pub fn mark_incomplete(&mut self, reason: &'static str) {
        self.analysis_complete = false;
        if self.assessment == Assessment::NotAssessed {
            return;
        }
        self.assessment = Assessment::Incomplete;
        self.status = "incomplete";
        if !self.incomplete_reasons.contains(&reason) {
            self.incomplete_reasons.push(reason);
        }
        self.warning = Some("Deobfuscation was incomplete; undetected behavior is possible".into());
    }

    pub fn finish(&mut self) {
        self.score = self
            .signals
            .iter()
            .map(|s| s.severity)
            .sum::<u32>()
            .min(100);
        self.signal_level = match self.score {
            0 if self.assessment == Assessment::NotAssessed => SignalLevel::NotEvaluated,
            0..=24 => SignalLevel::LowSignal,
            25..=64 => SignalLevel::Review,
            _ => SignalLevel::High,
        };
        // v1 `risk` combines both axes; "low_signal" is only possible for a complete analysis.
        self.risk = match (self.assessment, self.signal_level) {
            (Assessment::NotAssessed, _) => "not_assessed",
            (Assessment::Incomplete, SignalLevel::LowSignal) => "incomplete",
            (_, SignalLevel::LowSignal | SignalLevel::NotEvaluated) => "low_signal",
            (_, SignalLevel::Review) => "review",
            (_, SignalLevel::High) => "high",
        };
        self.completed_at_unix_ms = now_unix_ms();
    }

    /// `status` keeps its v1 value; `reason` is the finer v2 reason code.
    pub fn unavailable(
        &mut self,
        status: &'static str,
        reason: &'static str,
        explanation: impl Into<String>,
    ) {
        self.status = status;
        self.assessment = Assessment::NotAssessed;
        self.not_assessed_reason = Some(reason);
        self.analysis_complete = false;
        self.warning = Some(explanation.into());
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_without_signals_is_never_low_signal() {
        let mut report = Report::new("test.cmd".into(), "script");
        report.mark_incomplete("limit_reached");
        report.finish();
        assert_eq!(report.status, "incomplete");
        assert_eq!(report.risk, "incomplete");
        assert_eq!(report.score, 0);
        assert!(!report.analysis_complete);
        assert_eq!(report.incomplete_reasons, vec!["limit_reached"]);
        assert_eq!(report.assessment, Assessment::Incomplete);
        assert_eq!(report.signal_level, SignalLevel::LowSignal);
    }

    #[test]
    fn incomplete_preserves_high_risk_indicators() {
        let mut report = Report::new("test.ps1".into(), "script");
        report.add("suspicious", 85, "raw", "Synthetic test signal");
        report.mark_incomplete("limit_reached");
        report.mark_incomplete("limit_reached");
        report.finish();
        assert_eq!(report.risk, "high");
        assert_eq!(report.incomplete_reasons.len(), 1);
        assert_eq!(report.assessment, Assessment::Incomplete);
        assert_eq!(report.signal_level, SignalLevel::High);
    }

    #[test]
    fn not_assessed_is_sticky_and_never_low_signal() {
        let mut report = Report::new("x.exe".into(), "pe");
        report.unavailable("invalid_pe", "malformed_pe", "Synthetic");
        report.mark_incomplete("late_limit");
        report.finish();
        assert_eq!(report.status, "invalid_pe");
        assert_eq!(report.risk, "not_assessed");
        assert_eq!(report.assessment, Assessment::NotAssessed);
        assert_eq!(report.signal_level, SignalLevel::NotEvaluated);
        assert_eq!(report.not_assessed_reason, Some("malformed_pe"));
        assert!(report.incomplete_reasons.is_empty());
        assert!(!report.analysis_complete);
    }

    /// Every combination of completeness and detection: a report with zero
    /// signals may only read as `low_signal` when the analysis was complete.
    #[test]
    fn axes_are_independent_and_partial_results_never_become_negative() {
        for assessment in [
            Assessment::Analyzed,
            Assessment::Incomplete,
            Assessment::NotAssessed,
        ] {
            for severity in [None, Some(10), Some(30), Some(90)] {
                let mut r = Report::new("x.ps1".into(), "script");
                if let Some(severity) = severity {
                    r.add("synthetic", severity, "raw", "Synthetic test signal");
                }
                match assessment {
                    Assessment::Analyzed => {}
                    Assessment::Incomplete => r.mark_incomplete("synthetic_limit"),
                    Assessment::NotAssessed => r.unavailable("unreadable", "read_failed", "x"),
                }
                r.finish();
                assert_eq!(r.assessment, assessment);
                assert_eq!(r.analysis_complete, assessment == Assessment::Analyzed);
                if r.risk == "low_signal" {
                    assert_eq!(assessment, Assessment::Analyzed);
                }
                if severity.is_some() {
                    assert_ne!(r.signal_level, SignalLevel::NotEvaluated);
                    assert!(!r.signals.is_empty());
                }
                if assessment == Assessment::NotAssessed {
                    assert_eq!(r.risk, "not_assessed");
                    assert!(r.not_assessed_reason.is_some());
                }
            }
        }
    }

    #[test]
    fn serializes_v1_fields_with_v2_additions() {
        let mut r = Report::new("x.py".into(), "script");
        r.finish();
        let value = serde_json::to_value(&r).unwrap();
        for key in [
            "path",
            "kind",
            "status",
            "sha256",
            "score",
            "risk",
            "decoded_layers",
            "signals",
            "warning",
            "analysis_complete",
            "incomplete_reasons",
        ] {
            assert!(value.get(key).is_some(), "missing v1 field {key}");
        }
        assert_eq!(value["schema_version"], REPORT_SCHEMA_VERSION);
        assert_eq!(value["assessment"], "analyzed");
        assert_eq!(value["signal_level"], "low_signal");
        assert_eq!(value["engine"]["ruleset"], BUILTIN_RULESET);
    }
}
