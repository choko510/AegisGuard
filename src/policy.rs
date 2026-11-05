//! Outbound-block *planning* only (PolicyPlan v1, dry run). Nothing in this
//! module changes Windows Firewall, WFP or any other OS setting: it turns
//! attributed IOC findings into a reviewable list of candidate rules and a
//! list of rejected candidates with reasons, and records approvals for audit.
//! Applying a plan is a separate, not-yet-implemented step (P3-03).
use crate::events::network::NetworkFinding;
use crate::ioc::IocEvidence;
use crate::{model, store, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

pub const PLAN_SCHEMA: &str = "aegisguard-policy-plan/1";
pub const OWNER_NAMESPACE: &str = "AegisGuard";
pub const MAX_RULES: usize = 50;
pub const MAX_EXPIRY_SECS: u64 = 7 * 24 * 3600;
/// IOC sources whose matches may justify a block candidate. C2IntelFeeds is
/// investigation-only (ADOPTION_MATRIX), so it is deliberately absent.
const BLOCKING_SOURCES: &[&str] = &["feodo", "local"];
/// Processes shared by many functions; blocking them breaks unrelated things
/// or interferes with Defender, so they are never candidates.
const SHARED_PROCESSES: &[&str] = &[
    "system",
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "spoolsv.exe",
    "dllhost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "explorer.exe",
    "msmpeng.exe",
    "mpdefendercoreservice.exe",
    "nissrv.exe",
    "securityhealthservice.exe",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    pub rule_name: String,
    pub application_path: String,
    pub destination_ip: String,
    pub protocol: String,
    pub direction: String,
    pub action: String,
    pub expires_at_unix: u64,
    pub ioc_sources: Vec<String>,
    pub evidence_event_refs: Vec<String>,
    pub expected_diff: String,
    pub rollback_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rejected {
    pub process_guid: String,
    pub application_path: Option<String>,
    pub destination: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Approval {
    pub approver: String,
    pub approved_at_unix: u64,
    pub plan_sha256: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyPlan {
    pub schema: String,
    pub plan_id: String,
    pub created_at_unix: u64,
    /// Always true: this build has no code path that applies rules.
    pub dry_run: bool,
    pub owner_namespace: String,
    pub candidates: Vec<Candidate>,
    pub rejected: Vec<Rejected>,
    pub admin_approval: Option<Approval>,
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn public_destination(ip: &str) -> bool {
    ip.parse().is_ok_and(crate::c2::public_ip)
}

fn blocking_evidence(evidence: &[IocEvidence]) -> Vec<String> {
    let mut sources: Vec<String> = evidence
        .iter()
        .filter(|e| e.active() && BLOCKING_SOURCES.contains(&e.source_id.as_str()))
        .map(|e| e.source_id.clone())
        .collect();
    sources.sort();
    sources.dedup();
    sources
}

/// Why a finding cannot become a block candidate, or `None` if it can.
fn rejection(f: &NetworkFinding) -> Option<&'static str> {
    if f.basis == "dns_query" {
        return Some("dns_name_is_not_a_destination");
    }
    let Some(image) = f.image.as_deref() else {
        return Some("unattributed_process");
    };
    if SHARED_PROCESSES.contains(&basename(image).as_str()) {
        return Some("shared_system_service");
    }
    if f.verdict == "suppressed" {
        return Some("user_exception");
    }
    if f.verdict == "stale_only" || !f.evidence.iter().any(IocEvidence::active) {
        return Some("expired_evidence");
    }
    if f.shared_destination {
        return Some("shared_destination");
    }
    if blocking_evidence(&f.evidence).is_empty() {
        return Some("investigation_only_source");
    }
    if f.confidence != "medium" {
        return Some("insufficient_confidence");
    }
    None
}

fn destination_ip(f: &NetworkFinding) -> &str {
    // `dns_then_connect` destinations read "name -> ip".
    f.destination
        .rsplit(" -> ")
        .next()
        .unwrap_or(&f.destination)
}

pub fn plan(findings: &[NetworkFinding], now: u64, expiry_secs: u64) -> Result<PolicyPlan> {
    if expiry_secs == 0 || expiry_secs > MAX_EXPIRY_SECS {
        return Err(
            format!("expiry must be between 1 second and {MAX_EXPIRY_SECS} seconds").into(),
        );
    }
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut rejected = Vec::new();
    for f in findings {
        let ip = destination_ip(f).to_owned();
        let reason =
            rejection(f).or_else(|| (!public_destination(&ip)).then_some("non_public_destination"));
        if let Some(reason) = reason {
            rejected.push(Rejected {
                process_guid: f.process_guid.clone(),
                application_path: f.image.clone(),
                destination: f.destination.clone(),
                reason: reason.into(),
            });
            continue;
        }
        let image = f.image.clone().unwrap_or_default();
        if let Some(existing) = candidates
            .iter_mut()
            .find(|c| c.application_path == image && c.destination_ip == ip)
        {
            existing
                .evidence_event_refs
                .extend(f.event_refs.iter().cloned());
            continue;
        }
        if candidates.len() >= MAX_RULES {
            rejected.push(Rejected {
                process_guid: f.process_guid.clone(),
                application_path: f.image.clone(),
                destination: f.destination.clone(),
                reason: "rule_limit".into(),
            });
            continue;
        }
        let key = hex::encode(&Sha256::digest(format!("{image}\u{1f}{ip}").as_bytes())[..6]);
        let rule_name = format!("{OWNER_NAMESPACE}-{key}");
        candidates.push(Candidate {
            expected_diff: format!(
                "add outbound block rule {rule_name}: {image} -> {ip} (any protocol), expires {}",
                now + expiry_secs
            ),
            rollback_id: format!("remove:{rule_name}"),
            rule_name,
            application_path: image,
            destination_ip: ip,
            protocol: "any".into(),
            direction: "outbound".into(),
            action: "block".into(),
            expires_at_unix: now + expiry_secs,
            ioc_sources: blocking_evidence(&f.evidence),
            evidence_event_refs: f.event_refs.clone(),
        });
    }
    let mut plan = PolicyPlan {
        schema: PLAN_SCHEMA.into(),
        plan_id: String::new(),
        created_at_unix: now,
        dry_run: true,
        owner_namespace: OWNER_NAMESPACE.into(),
        candidates,
        rejected,
        admin_approval: None,
    };
    plan.plan_id = hex::encode(&Sha256::digest(serde_json::to_vec(&plan)?)[..16]);
    Ok(plan)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create_new(path)
        .map_err(|e| format!("{}: {e} (plans are never overwritten)", path.display()))?;
    store::restrict_to_owner(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn save(plan: &PolicyPlan, path: &Path) -> Result<()> {
    write_new(path, &serde_json::to_vec_pretty(plan)?)
}

/// Record an approval of an unmodified plan and append it to the audit log.
/// The result is still a dry run: approval does not apply anything.
pub fn approve(
    plan_path: &Path,
    approver: &str,
    note: &str,
    out: &Path,
    audit_log: &Path,
) -> Result<PolicyPlan> {
    if approver.trim().is_empty() || note.trim().is_empty() {
        return Err("an approval needs an approver and a note".into());
    }
    let bytes = std::fs::read(plan_path)?;
    let mut plan: PolicyPlan = serde_json::from_slice(&bytes)?;
    if plan.schema != PLAN_SCHEMA || !plan.dry_run || plan.admin_approval.is_some() {
        return Err("not an unapproved dry-run plan".into());
    }
    let now = model::now_unix_ms() / 1000;
    if plan.candidates.iter().any(|c| c.expires_at_unix <= now) {
        return Err("the plan contains expired candidates; create a new plan".into());
    }
    let approval = Approval {
        approver: approver.into(),
        approved_at_unix: now,
        plan_sha256: hex::encode(Sha256::digest(&bytes)),
        note: note.into(),
    };
    plan.admin_approval = Some(approval.clone());
    write_new(out, &serde_json::to_vec_pretty(&plan)?)?;
    if let Some(parent) = audit_log.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let existed = audit_log.exists();
    let mut log = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(audit_log)?;
    if !existed {
        store::restrict_to_owner(audit_log)?;
    }
    let line = serde_json::json!({
        "event": "policy_plan_approved",
        "plan_id": plan.plan_id,
        "candidates": plan.candidates.len(),
        "approval": approval,
        "applied": false,
    });
    writeln!(log, "{line}")?;
    log.sync_all()?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_793_000_000;

    fn evidence(source: &str, stale: bool) -> IocEvidence {
        IocEvidence {
            indicator_type: "ip",
            normalized_value: "x".into(),
            source_id: source.into(),
            license_ref: "test".into(),
            observed_at_unix: NOW,
            expires_at_unix: NOW + 10,
            version: 1,
            confidence: "medium",
            stale,
            allowlist_reason: None,
        }
    }

    fn finding(
        image: Option<&str>,
        dest: &str,
        basis: &'static str,
        ev: Vec<IocEvidence>,
    ) -> NetworkFinding {
        NetworkFinding {
            process_guid: "{P}".into(),
            image: image.map(Into::into),
            basis,
            destination: dest.into(),
            at_unix_ms: Some(1),
            event_refs: vec!["uid1".into()],
            evidence: ev,
            shared_destination: false,
            verdict: "review",
            confidence: "medium",
        }
    }

    #[test]
    fn eligible_finding_becomes_an_expiring_namespaced_candidate() {
        let findings = vec![
            finding(
                Some("C:\\Tools\\agent.exe"),
                "8.8.4.4",
                "direct_ip",
                vec![evidence("feodo", false)],
            ),
            finding(
                Some("C:\\Tools\\agent.exe"),
                "x.example -> 8.8.4.4",
                "dns_then_connect",
                vec![evidence("local", false)],
            ),
        ];
        let p = plan(&findings, NOW, 3600).unwrap();
        assert!(p.dry_run);
        assert_eq!(p.candidates.len(), 1, "same app and destination are merged");
        let c = &p.candidates[0];
        assert!(c.rule_name.starts_with("AegisGuard-"));
        assert_eq!(
            (c.direction.as_str(), c.action.as_str()),
            ("outbound", "block")
        );
        assert_eq!(c.expires_at_unix, NOW + 3600);
        assert_eq!(c.evidence_event_refs.len(), 2);
        assert_eq!(p.plan_id, plan(&findings, NOW, 3600).unwrap().plan_id);
    }

    #[test]
    fn unsafe_findings_are_rejected_with_reasons() {
        let mut shared = finding(
            Some("C:\\a.exe"),
            "8.8.4.4",
            "direct_ip",
            vec![evidence("feodo", false)],
        );
        shared.shared_destination = true;
        let mut suppressed = finding(
            Some("C:\\a.exe"),
            "8.8.4.4",
            "direct_ip",
            vec![evidence("feodo", false)],
        );
        suppressed.verdict = "suppressed";
        let mut weak = finding(
            Some("C:\\a.exe"),
            "8.8.4.4",
            "direct_ip",
            vec![evidence("feodo", false)],
        );
        weak.confidence = "low";
        let cases = vec![
            (
                finding(None, "8.8.4.4", "direct_ip", vec![evidence("feodo", false)]),
                "unattributed_process",
            ),
            (
                finding(
                    Some("C:\\Windows\\System32\\svchost.exe"),
                    "8.8.4.4",
                    "direct_ip",
                    vec![evidence("feodo", false)],
                ),
                "shared_system_service",
            ),
            (
                finding(
                    Some("C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe"),
                    "8.8.4.4",
                    "direct_ip",
                    vec![evidence("feodo", false)],
                ),
                "shared_system_service",
            ),
            (
                finding(
                    Some("C:\\a.exe"),
                    "c2.example",
                    "dns_query",
                    vec![evidence("local", false)],
                ),
                "dns_name_is_not_a_destination",
            ),
            (
                finding(
                    Some("C:\\a.exe"),
                    "8.8.4.4",
                    "direct_ip",
                    vec![evidence("feodo", true)],
                ),
                "expired_evidence",
            ),
            (
                finding(
                    Some("C:\\a.exe"),
                    "8.8.4.4",
                    "direct_ip",
                    vec![evidence("c2intel_verified", false)],
                ),
                "investigation_only_source",
            ),
            (
                finding(
                    Some("C:\\a.exe"),
                    "192.168.1.10",
                    "direct_ip",
                    vec![evidence("local", false)],
                ),
                "non_public_destination",
            ),
            (shared, "shared_destination"),
            (suppressed, "user_exception"),
            (weak, "insufficient_confidence"),
        ];
        for (f, expected) in cases {
            let p = plan(&[f], NOW, 3600).unwrap();
            assert!(p.candidates.is_empty(), "{expected}");
            assert_eq!(p.rejected[0].reason, expected);
        }
    }

    #[test]
    fn rule_count_and_expiry_are_capped() {
        let findings: Vec<_> = (0..60)
            .map(|i| {
                finding(
                    Some("C:\\a.exe"),
                    &format!("8.8.{}.{}", i / 250, i % 250 + 1),
                    "direct_ip",
                    vec![evidence("feodo", false)],
                )
            })
            .collect();
        let p = plan(&findings, NOW, 3600).unwrap();
        assert_eq!(p.candidates.len(), MAX_RULES);
        assert_eq!(
            p.rejected
                .iter()
                .filter(|r| r.reason == "rule_limit")
                .count(),
            10
        );
        assert!(plan(&findings, NOW, 0).is_err());
        assert!(plan(&findings, NOW, MAX_EXPIRY_SECS + 1).is_err());
    }

    #[test]
    fn approval_is_audited_and_never_applies_or_overwrites() {
        let dir = std::env::temp_dir().join(format!("aegisguard-policy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let now = model::now_unix_ms() / 1000;
        let p = plan(
            &[finding(
                Some("C:\\a.exe"),
                "8.8.4.4",
                "direct_ip",
                vec![evidence("feodo", false)],
            )],
            now,
            3600,
        )
        .unwrap();
        let plan_path = dir.join("plan.json");
        save(&p, &plan_path).unwrap();
        assert!(save(&p, &plan_path).is_err(), "plans are never overwritten");
        let audit = dir.join("audit.jsonl");
        assert!(approve(&plan_path, "", "note", &dir.join("a.json"), &audit).is_err());
        let approved = approve(
            &plan_path,
            "admin",
            "ticket 7",
            &dir.join("approved.json"),
            &audit,
        )
        .unwrap();
        assert!(approved.dry_run);
        assert!(approved.admin_approval.is_some());
        let log = std::fs::read_to_string(&audit).unwrap();
        assert!(log.contains("\"applied\":false"));
        // An approved plan cannot be approved again.
        assert!(approve(
            &dir.join("approved.json"),
            "admin",
            "again",
            &dir.join("b.json"),
            &audit
        )
        .is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
