use crate::model::{
    normalize, valid_text, Advisory, AdvisoryBatch, AdvisoryMatch, Coverage, Evidence,
    InventoryReport, MatchReport, SoftwareEntry, VersionRange, MAX_ADVISORIES, MAX_ENTRIES,
    MAX_MATCHES, SCHEMA_VERSION,
};
use std::cmp::Ordering;
use std::time::{Duration, Instant};
const MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const MAX_FUTURE_MS: u64 = 5 * 60 * 1_000;

fn numeric_version(input: &str) -> Option<Vec<u32>> {
    if input.len() > 64 || input.is_empty() || input.split('.').count() > 4 {
        return None;
    }
    input
        .split('.')
        .map(|n| {
            if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) || n.len() > 9 {
                None
            } else {
                n.parse::<u32>().ok()
            }
        })
        .collect()
}
fn compare(a: &str, b: &str) -> Option<Ordering> {
    let aa = numeric_version(a)?;
    let bb = numeric_version(b)?;
    for i in 0..aa.len().max(bb.len()) {
        let order = aa
            .get(i)
            .copied()
            .unwrap_or(0)
            .cmp(&bb.get(i).copied().unwrap_or(0));
        if order != Ordering::Equal {
            return Some(order);
        }
    }
    Some(Ordering::Equal)
}
fn in_range(version: &str, range: &VersionRange) -> Option<bool> {
    let lower = match &range.start_inclusive {
        Some(s) => compare(version, s)? != Ordering::Less,
        None => true,
    };
    let upper = match &range.end_exclusive {
        Some(s) => compare(version, s)? == Ordering::Less,
        None => true,
    };
    Some(lower && upper)
}
fn valid_advisory(a: &Advisory) -> bool {
    let parts: Vec<_> = a.id.split('-').collect();
    if parts.len() != 3
        || parts[0] != "CVE"
        || parts[1].len() != 4
        || parts[2].len() < 4
        || !parts[1..]
            .iter()
            .all(|v| v.bytes().all(|b| b.is_ascii_digit()))
        || !valid_text(&a.vendor, 160)
        || !valid_text(&a.product, 256)
        || a.publisher_aliases.len() > 16
        || a.product_aliases.len() > 16
        || !a.publisher_aliases.iter().all(|v| valid_text(v, 160))
        || !a.product_aliases.iter().all(|v| valid_text(v, 256))
        || a.architectures.len() > 3
        || a.editions.len() > 16
        || !a
            .architectures
            .iter()
            .all(|v| matches!(v.as_str(), "x86" | "x64" | "arm64"))
        || !a.editions.iter().all(|v| valid_text(v, 64))
        || a.unaffected_versions.len() > 32
        || !a
            .unaffected_versions
            .iter()
            .all(|v| numeric_version(v).is_some())
        || a.version_ranges.is_empty()
        || a.version_ranges.len() > 16
        || !a.source_url.starts_with("https://")
        || a.source_url.len() > 256
        || a.source_url.contains(&['?', '#', '@'][..])
        || a.source_url.chars().any(char::is_control)
    {
        return false;
    }
    a.version_ranges.iter().all(|r| {
        let lower = r.start_inclusive.as_deref();
        let upper = r.end_exclusive.as_deref();
        if lower.is_none() && upper.is_none() {
            return false;
        }
        if !lower.is_none_or(|v| numeric_version(v).is_some())
            || !upper.is_none_or(|v| numeric_version(v).is_some())
        {
            return false;
        }
        match (lower, upper) {
            (Some(l), Some(u)) => compare(l, u) == Some(Ordering::Less),
            _ => true,
        }
    })
}
fn matches_name(value: &str, canonical: &str, aliases: &[String]) -> bool {
    let value = normalize(value);
    value == normalize(canonical) || aliases.iter().any(|a| normalize(a) == value)
}
fn matches_constraint(value: Option<&str>, options: &[String]) -> Option<bool> {
    if options.is_empty() {
        return Some(true);
    }
    value.map(|v| options.iter().any(|o| normalize(o) == normalize(v)))
}
fn evaluate_entry(
    app: &SoftwareEntry,
    advisory: &Advisory,
    checked: u64,
    stale: bool,
) -> Option<AdvisoryMatch> {
    if !matches_name(&app.name, &advisory.product, &advisory.product_aliases) {
        return None;
    }
    let mut evidence = vec![Evidence {
        kind: "product_name_exact_or_explicit_alias".into(),
        detail: advisory.product.clone(),
    }];
    let mut unknown = false;
    let vendors = [
        vec![advisory.vendor.clone()],
        advisory.publisher_aliases.clone(),
    ]
    .concat();
    match matches_constraint(app.publisher.as_deref(), &vendors) {
        Some(false) => return None,
        None => {
            unknown = true;
            evidence.push(Evidence {
                kind: "publisher_missing".into(),
                detail: "identity_unverified".into(),
            });
        }
        Some(true) => evidence.push(Evidence {
            kind: "publisher_exact_or_explicit_alias".into(),
            detail: advisory.vendor.clone(),
        }),
    }
    for (kind, known, allowed) in [
        (
            "architecture",
            app.architecture.as_deref(),
            &advisory.architectures,
        ),
        ("edition", app.edition.as_deref(), &advisory.editions),
    ] {
        match matches_constraint(known, allowed) {
            Some(false) => return None,
            None => {
                unknown = true;
                evidence.push(Evidence {
                    kind: format!("{kind}_unknown"),
                    detail: "constraint_not_evaluable".into(),
                });
            }
            Some(true) if !allowed.is_empty() => evidence.push(Evidence {
                kind: format!("{kind}_matches"),
                detail: known.unwrap_or_default().into(),
            }),
            Some(true) => {}
        }
    }
    match app.version.as_deref() {
        Some(version) if numeric_version(version).is_some() => {
            if advisory
                .unaffected_versions
                .iter()
                .any(|v| compare(version, v) == Some(Ordering::Equal))
            {
                return None;
            }
            if !advisory
                .version_ranges
                .iter()
                .any(|r| in_range(version, r) == Some(true))
            {
                return None;
            }
            evidence.push(Evidence {
                kind: "numeric_version_in_curated_range".into(),
                detail: version.into(),
            });
        }
        _ => {
            unknown = true;
            evidence.push(Evidence {
                kind: "version_unknown_or_unsupported".into(),
                detail: "no_numeric_comparison".into(),
            });
        }
    }
    if stale {
        unknown = true;
        evidence.push(Evidence {
            kind: "advisory_freshness_unverified".into(),
            detail: "stale_or_future_timestamp".into(),
        });
    }
    Some(AdvisoryMatch {
        software_name: app.name.clone(),
        installed_version: app.version.clone(),
        advisory_id: advisory.id.clone(),
        classification: if unknown { "unknown" } else { "candidate" }.into(),
        confidence: if unknown { "low" } else { "medium" }.into(),
        evidence,
        source_checked_at_unix_ms: checked,
        advisory_url: advisory.source_url.clone(),
    })
}

pub fn match_advisories(
    inventory: InventoryReport,
    batch: AdvisoryBatch,
    now: u64,
) -> Result<MatchReport, String> {
    if inventory.schema_version != SCHEMA_VERSION
        || inventory.module != "software-audit"
        || inventory.entries.len() > MAX_ENTRIES
        || batch.schema_version != SCHEMA_VERSION
        || batch.advisories.len() > MAX_ADVISORIES
    {
        return Err("unsupported schema or record limit exceeded".into());
    }
    if !matches!(
        inventory.status.as_str(),
        "complete" | "partial" | "permission_denied" | "unavailable" | "error"
    ) {
        return Err("invalid inventory status".into());
    }
    if inventory.entries.iter().any(|a| {
        !valid_text(&a.name, 256)
            || !a.version.as_deref().is_none_or(|v| valid_text(v, 64))
            || !a.publisher.as_deref().is_none_or(|v| valid_text(v, 160))
            || !a
                .architecture
                .as_deref()
                .is_none_or(|v| matches!(v, "x86" | "x64" | "arm64"))
            || !a.edition.as_deref().is_none_or(|v| valid_text(v, 64))
    }) {
        return Err("invalid inventory entry fields".into());
    }
    if !batch.advisories.iter().all(valid_advisory) {
        return Err("invalid or unsupported advisory fields".into());
    }
    let stale = batch.source_checked_at_unix_ms == 0
        || batch.source_checked_at_unix_ms > now.saturating_add(MAX_FUTURE_MS)
        || now.saturating_sub(batch.source_checked_at_unix_ms) > MAX_AGE_MS;
    let mut warnings = Vec::new();
    if stale {
        warnings.push("advisory_source_stale_or_clock_skew; matches_downgraded_to_unknown".into());
    }
    if inventory.status != "complete" {
        warnings.push("inventory_incomplete; unobserved_products_not_cleared".into());
    }
    if batch.advisories.is_empty() {
        warnings.push("no_local_advisories; no_vulnerability_clearance".into());
    }
    let mut coverage = Coverage {
        scope: "offline_local_advisories; no_cpe_or_vendor_attestation".into(),
        sources: inventory.coverage.sources.clone(),
        skipped: 0,
        truncated: false,
        evaluated: 0,
    };
    let mut entries = Vec::new();
    let started = Instant::now();
    'outer: for app in &inventory.entries {
        for advisory in &batch.advisories {
            if coverage.evaluated % 128 == 0 && started.elapsed() > Duration::from_secs(2) {
                coverage.truncated = true;
                warnings.push("match_time_budget_exceeded".into());
                break 'outer;
            }
            coverage.evaluated += 1;
            if let Some(matched) =
                evaluate_entry(app, advisory, batch.source_checked_at_unix_ms, stale)
            {
                if entries.len() >= MAX_MATCHES {
                    coverage.truncated = true;
                    warnings.push("match_count_limit_reached".into());
                    break 'outer;
                }
                entries.push(matched);
            }
        }
    }
    if entries.is_empty() {
        warnings.push("no_candidates_is_not_proof_of_safety".into());
    }
    let status = if coverage.truncated
        || inventory.status != "complete"
        || batch.advisories.is_empty()
        || stale
    {
        "partial"
    } else {
        "complete"
    };
    Ok(MatchReport {
        schema_version: SCHEMA_VERSION,
        module: "software-audit".into(),
        generated_at_unix_ms: now,
        status: status.into(),
        entries,
        warnings,
        coverage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numeric_comparison_and_boundaries() {
        assert_eq!(compare("1.9", "1.10"), Some(Ordering::Less));
        assert_eq!(compare("1.10.0", "1.10"), Some(Ordering::Equal));
        assert_eq!(compare("1.10-beta", "1.10"), None);
        assert_eq!(
            in_range(
                "1.9",
                &VersionRange {
                    start_inclusive: Some("1.9".into()),
                    end_exclusive: Some("1.10".into())
                }
            ),
            Some(true)
        );
        assert_eq!(
            in_range(
                "1.10",
                &VersionRange {
                    start_inclusive: Some("1.9".into()),
                    end_exclusive: Some("1.10".into())
                }
            ),
            Some(false)
        );
    }
}
