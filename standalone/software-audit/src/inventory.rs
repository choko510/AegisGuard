use std::collections::{BTreeMap, HashSet};
use crate::model::{
    now_ms, normalize, valid_text, Coverage, Fixture, InventoryReport, RawEntry, SoftwareEntry,
    SourceCoverage, SourceData, MAX_ENTRIES, SCHEMA_VERSION, SOURCES,
};

pub fn inspect_fixture(fixture: Fixture) -> Result<InventoryReport, String> {
    if fixture.schema_version != SCHEMA_VERSION { return Err("unsupported fixture schema_version".into()); }
    if fixture.sources.len() > SOURCES.len() { return Err("too many fixture sources".into()); }
    let mut ids = HashSet::new();
    for src in &fixture.sources {
        if !SOURCES.contains(&src.id.as_str()) || !ids.insert(src.id.as_str()) {
            return Err("invalid or duplicate fixture source id".into());
        }
        if !matches!(src.status.as_str(), "complete" | "partial" | "unavailable" | "permission_denied" | "error") {
            return Err("invalid fixture source status".into());
        }
        if !matches!(src.status.as_str(), "complete" | "partial") && !src.entries.is_empty() {
            return Err("failed source must not claim entries".into());
        }
        if src.entries.len() > MAX_ENTRIES { return Err("fixture entry count exceeds limit".into()); }
    }
    Ok(assemble(fixture.sources))
}

fn optional(value: Option<String>, max: usize) -> Result<Option<String>, ()> {
    match value {
        None => Ok(None),
        Some(v) if valid_text(&v, max) => Ok(Some(v.trim().to_owned())),
        Some(_) => Err(()),
    }
}
fn convert(raw: RawEntry, source: &str) -> Result<SoftwareEntry, ()> {
    if !valid_text(&raw.name, 256) { return Err(()); }
    let architecture = optional(raw.architecture, 16)?;
    if architecture.as_deref().is_some_and(|a| !matches!(a, "x86" | "x64" | "arm64")) {
        return Err(());
    }
    Ok(SoftwareEntry {
        name: raw.name.trim().to_owned(),
        version: optional(raw.version, 64)?,
        publisher: optional(raw.publisher, 160)?,
        architecture,
        edition: optional(raw.edition, 64)?,
        install_scope: if source.starts_with("hklm") { "machine" } else { "current_user" }.into(),
        sources: vec![source.to_owned()],
    })
}
pub fn assemble(sources: Vec<SourceData>) -> InventoryReport {
    let mut index = BTreeMap::<(String, String, String, String, String, String), SoftwareEntry>::new();
    let mut coverage = Coverage {
        scope: "uninstall_registry_only; current_user_and_machine; msix_not_included".into(),
        sources: Vec::new(), skipped: 0, truncated: false, evaluated: 0,
    };
    let mut warnings = vec!["msix_and_other_package_managers_not_covered".to_owned()];
    for id in SOURCES {
        let Some(source) = sources.iter().find(|s| s.id == id) else {
            coverage.sources.push(SourceCoverage { id: id.into(), status: "unavailable".into(), seen: 0 });
            warnings.push(format!("source_not_collected:{id}"));
            continue;
        };
        let mut status = source.status.clone();
        let mut seen = 0;
        for entry in source.entries.iter().cloned() {
            if coverage.evaluated >= MAX_ENTRIES {
                coverage.truncated = true;
                status = "partial".into();
                break;
            }
            coverage.evaluated += 1;
            seen += 1;
            if let Ok(app) = convert(entry, id) {
                let key = (
                    normalize(&app.name), app.version.clone().unwrap_or_default(),
                    app.publisher.as_deref().map(normalize).unwrap_or_default(),
                    app.architecture.clone().unwrap_or_default(),
                    app.edition.as_deref().map(normalize).unwrap_or_default(),
                    app.install_scope.clone(),
                );
                if let Some(previous) = index.get_mut(&key) {
                    if !previous.sources.contains(&id.to_string()) { previous.sources.push(id.to_owned()); }
                } else { index.insert(key, app); }
            } else {
                coverage.skipped += 1;
                status = "partial".into();
            }
        }
        if status != "complete" { warnings.push(format!("source_incomplete:{id}:{status}")); }
        coverage.sources.push(SourceCoverage { id: id.into(), status, seen });
    }
    if coverage.truncated { warnings.push("inventory_entry_limit_reached".into()); }
    if coverage.skipped > 0 { warnings.push("invalid_entries_omitted".into()); }
    let complete = coverage.sources.iter().filter(|s| s.status == "complete").count();
    let available = coverage.sources.iter().filter(|s| s.status == "complete" || s.status == "partial").count();
    let denied = coverage.sources.iter().filter(|s| s.status == "permission_denied").count();
    let error = coverage.sources.iter().filter(|s| s.status == "error").count();
    let status = if complete == SOURCES.len() && !coverage.truncated && coverage.skipped == 0 {
        "complete"
    } else if available > 0 { "partial" }
    else if denied > 0 { "permission_denied" }
    else if error > 0 { "error" }
    else { "unavailable" };
    InventoryReport {
        schema_version: SCHEMA_VERSION, module: "software-audit".into(),
        generated_at_unix_ms: now_ms(), status: status.into(),
        entries: index.into_values().collect(), warnings, coverage,
    }
}
pub fn inventory() -> InventoryReport {
    #[cfg(windows)]
    { assemble(crate::registry::collect()) }
    #[cfg(not(windows))]
    { assemble(Vec::new()) }
}
