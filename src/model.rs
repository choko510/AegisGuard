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

    pub fn finish(&mut self) {
        if self.status != "analyzed" {
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
            0..=24 => "low_signal",
            25..=64 => "review",
            _ => "high",
        };
    }

    pub fn unavailable(&mut self, status: &'static str, explanation: impl Into<String>) {
        self.status = status;
        self.warning = Some(explanation.into());
        self.finish();
    }
}
