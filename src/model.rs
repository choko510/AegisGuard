use serde::Serialize;

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

#[derive(Debug, Serialize)]
pub struct Report {
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

    /// An incomplete static analysis is not a clean result even if no indicators matched.
    pub fn mark_incomplete(&mut self, reason: &'static str) {
        self.analysis_complete = false;
        if self.status == "analyzed" || self.status == "incomplete" {
            self.status = "incomplete";
        }
        if !self.incomplete_reasons.contains(&reason) {
            self.incomplete_reasons.push(reason);
        }
        self.warning = Some("Deobfuscation was incomplete; undetected behavior is possible".into());
    }

    pub fn finish(&mut self) {
        if self.status != "analyzed" && self.status != "incomplete" {
            self.risk = "not_assessed";
            return;
        }
        self.score = self
            .signals
            .iter()
            .map(|s| s.severity)
            .sum::<u32>()
            .min(100);
        self.risk = match self.score {
            0..=24 if !self.analysis_complete => "incomplete",
            0..=24 => "low_signal",
            25..=64 => "review",
            _ => "high",
        };
    }

    pub fn unavailable(&mut self, status: &'static str, explanation: impl Into<String>) {
        self.status = status;
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
    }
}
