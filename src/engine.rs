//! Typed engine operations shared by the CLI, the GUI and the service.
//!
//! These functions hold the work that used to live in `main.rs`; front ends
//! only choose inputs and render the returned values. The CLI prints these
//! values through `serde_json::Value` (sorted keys), so its output is the same
//! as before this module existed.
use crate::events::{self, process::ProcessTable, EventEnvelope};
use crate::{ioc, model, policy, rulepack, store, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

pub fn now() -> u64 {
    model::now_unix_ms() / 1000
}

/// Where IOC evidence comes from for event analyses.
#[derive(Debug, Clone, Default)]
pub struct IocOptions {
    /// C2 IP cache; a missing file means only local IOCs are used.
    pub c2_cache: PathBuf,
    pub local_iocs: Option<PathBuf>,
    pub allowlist: Option<PathBuf>,
}

impl IocOptions {
    /// Load the IOC set. The returned warnings must be shown to the user.
    pub fn load(&self, now: u64) -> Result<(ioc::IocSet, Vec<String>)> {
        let mut warnings = Vec::new();
        let cache = self.c2_cache.exists().then_some(self.c2_cache.as_path());
        if cache.is_none() {
            warnings.push(format!(
                "no C2 cache at {}; only local IOCs are used",
                self.c2_cache.display()
            ));
        }
        let set = ioc::IocSet::load(
            cache,
            self.local_iocs.as_deref(),
            self.allowlist.as_deref(),
            now,
        )?;
        Ok((set, warnings))
    }
}

/// Spooled events with the process table rebuilt from them.
pub struct SpoolAnalysis {
    pub events: Vec<EventEnvelope>,
    pub bad_lines: u64,
    pub table: ProcessTable,
}

pub fn analyze_spools(spools: &[PathBuf]) -> Result<SpoolAnalysis> {
    let (events, bad_lines) = events::process::read_spools(spools)?;
    let table = ProcessTable::build(&events);
    Ok(SpoolAnalysis {
        events,
        bad_lines,
        table,
    })
}

#[derive(Serialize)]
pub struct ProcessesOutput<'a> {
    pub bad_lines: u64,
    pub events: usize,
    pub note: &'static str,
    pub table: &'a ProcessTable,
    pub unobserved: Vec<&'static str>,
}

impl SpoolAnalysis {
    pub fn processes(&self) -> ProcessesOutput<'_> {
        ProcessesOutput {
            bad_lines: self.bad_lines,
            events: self.events.len(),
            note: "Unobserved event types mean unknown activity, not absence of activity.",
            table: &self.table,
            unobserved: self.table.unobserved(),
        }
    }

    /// Run the built-in correlation rules; only fresh IOCs count as active.
    pub fn correlate(&self, iocs: &ioc::IocSet) -> CorrelateOutput {
        let active = |ip: &str| {
            iocs.ip(ip)
                .into_iter()
                .filter(ioc::IocEvidence::active)
                .map(|e| e.source_id)
                .collect()
        };
        CorrelateOutput {
            anomalies: self.table.anomalies.len(),
            bad_lines: self.bad_lines,
            correlation: events::correlate::correlate(&self.table, &active),
            duplicates: self.table.duplicates,
            events: self.events.len(),
            unobserved: self.table.unobserved(),
        }
    }

    /// Browser-hijack timelines; only fresh IOCs are named.
    pub fn timeline(&self, iocs: &ioc::IocSet) -> events::timeline::TimelineReport {
        let active = |ip: &str| {
            iocs.ip(ip)
                .into_iter()
                .filter(ioc::IocEvidence::active)
                .map(|e| e.source_id)
                .collect()
        };
        events::timeline::build(&self.table, &active)
    }

    pub fn attribute(&self, iocs: &ioc::IocSet) -> IocsOutput {
        IocsOutput {
            bad_lines: self.bad_lines,
            events: self.events.len(),
            report: events::network::attribute(&self.table, iocs),
        }
    }
}

#[derive(Serialize)]
pub struct CorrelateOutput {
    pub anomalies: usize,
    pub bad_lines: u64,
    pub correlation: events::correlate::Correlation,
    pub duplicates: u64,
    pub events: usize,
    pub unobserved: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct IocsOutput {
    pub bad_lines: u64,
    pub events: usize,
    pub report: events::network::NetworkReport,
}

#[derive(Serialize)]
pub struct PlanOutput {
    pub candidates: usize,
    pub dry_run: bool,
    pub note: &'static str,
    pub out: String,
    pub plan_id: String,
    pub rejected: usize,
    pub visibility: Vec<&'static str>,
}

/// Build a dry-run block plan and save it to a new file. Nothing is applied.
pub fn plan_blocks(
    analysis: &SpoolAnalysis,
    iocs: &ioc::IocSet,
    expiry_hours: u64,
    out: &Path,
    now: u64,
) -> Result<PlanOutput> {
    let report = events::network::attribute(&analysis.table, iocs);
    let plan = policy::plan(&report.findings, now, expiry_hours.saturating_mul(3600))?;
    policy::save(&plan, out)?;
    Ok(PlanOutput {
        candidates: plan.candidates.len(),
        dry_run: plan.dry_run,
        note: "Nothing was applied. Applying plans is not implemented in this build.",
        out: out.display().to_string(),
        plan_id: plan.plan_id,
        rejected: plan.rejected.len(),
        visibility: report.visibility,
    })
}

/// Collect new events of one Windows Event Log channel into a spool.
#[cfg(windows)]
pub fn collect_events(
    channel: &str,
    spool: PathBuf,
    checkpoint: PathBuf,
    max: u64,
) -> events::collector::SensorHealth {
    let mut source = events::winevt::WinEventSource::new(channel);
    let paths = events::collector::Paths { spool, checkpoint };
    events::collector::collect(&mut source, &paths, max)
}

#[derive(Serialize)]
pub struct KeygenOutput {
    pub key_id: String,
    pub public_key: String,
    pub secret_key: String,
}

/// Create an Ed25519 key pair; the secret file is owner-only before any key
/// material is written, and existing files are never overwritten.
pub fn keygen(out: &Path) -> Result<KeygenOutput> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("no OS randomness: {e}"))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let secret = out.with_extension("key");
    let public = out.with_extension("pub");
    for path in [&secret, &public] {
        if path.exists() {
            return Err(format!("{} already exists; not overwriting", path.display()).into());
        }
    }
    let mut file = std::fs::File::create_new(&secret)?;
    store::restrict_to_owner(&secret)?;
    std::io::Write::write_all(&mut file, hex::encode(seed).as_bytes())?;
    std::fs::write(&public, hex::encode(key.verifying_key().as_bytes()))?;
    Ok(KeygenOutput {
        key_id: rulepack::key_id(&key.verifying_key()),
        public_key: public.display().to_string(),
        secret_key: secret.display().to_string(),
    })
}

#[derive(Serialize)]
pub struct ManifestOutput {
    pub expires_at_unix: u64,
    pub generation: Option<String>,
    pub issued_at_unix: u64,
    pub issuer: String,
    pub key_id: String,
    pub payload_sha256: String,
    pub sequence: u64,
    pub status: String,
}

impl ManifestOutput {
    pub fn new(status: &str, manifest: &rulepack::Manifest, generation: Option<&str>) -> Self {
        Self {
            expires_at_unix: manifest.expires_at,
            generation: generation.map(str::to_string),
            issued_at_unix: manifest.issued_at,
            issuer: manifest.issuer.clone(),
            key_id: manifest.key_id.clone(),
            payload_sha256: manifest.payload_sha256.clone(),
            sequence: manifest.sequence,
            status: status.to_string(),
        }
    }
}
