//! IOC evidence with provenance, expiry and user exceptions (IocEvidence v1).
//! Sources: the C2 IP cache (registry in `c2.rs`), and optional user-owned
//! local IOC and allowlist files. Every local entry must expire; expired IOCs
//! are reported as stale and never as an active match, expired exceptions no
//! longer suppress anything. A DNS name is never treated as proof of the IP a
//! process connected to.
use crate::{c2, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

const MAX_LIST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LIST_ENTRIES: usize = 50_000;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IocEvidence {
    pub indicator_type: &'static str,
    pub normalized_value: String,
    pub source_id: String,
    pub license_ref: String,
    pub observed_at_unix: u64,
    pub expires_at_unix: u64,
    pub version: u32,
    pub confidence: &'static str,
    pub stale: bool,
    pub allowlist_reason: Option<String>,
}

impl IocEvidence {
    /// Fresh and not covered by an active user exception.
    pub fn active(&self) -> bool {
        !self.stale && self.allowlist_reason.is_none()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListEntry {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
    pub expires_at_unix: u64,
    /// Free text for the list owner; not interpreted.
    #[serde(default)]
    #[allow(dead_code)]
    pub note: Option<String>,
    /// Required for allowlist entries: why this is an accepted exception.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Canonical text of an IP; IPv4-mapped IPv6 becomes plain IPv4.
pub fn normalize_ip(text: &str) -> Option<String> {
    let ip: IpAddr = text.trim().trim_start_matches("::ffff:").parse().ok()?;
    Some(match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_else(|| v6.to_string()),
        IpAddr::V4(v4) => v4.to_string(),
    })
}

/// Lower-case ASCII host name without a trailing dot. Non-ASCII (un-encoded
/// IDN) and malformed names are rejected rather than guessed.
pub fn normalize_domain(text: &str) -> Option<String> {
    let name = text.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    valid.then_some(name)
}

/// `name` equals the indicator or is a subdomain of it on a label boundary
/// (`evil.example` matches `a.evil.example`, not `notevil.example`).
pub fn domain_matches(indicator: &str, name: &str) -> bool {
    name == indicator
        || name
            .strip_suffix(indicator)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn read_list(path: &Path, what: &str) -> Result<Vec<ListEntry>> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > MAX_LIST_BYTES {
        return Err(format!(
            "{what} {} is not a regular file within the size limit",
            path.display()
        )
        .into());
    }
    let entries: Vec<ListEntry> = serde_json::from_slice(&std::fs::read(path)?)?;
    if entries.len() > MAX_LIST_ENTRIES {
        return Err(format!("{what} has too many entries").into());
    }
    for e in &entries {
        let ok = match e.kind.as_str() {
            "ip" => normalize_ip(&e.value).is_some(),
            "domain" => normalize_domain(&e.value).is_some(),
            _ => false,
        };
        if !ok || e.expires_at_unix == 0 {
            return Err(format!("{what}: invalid entry {:?} (type ip|domain, valid value, expires_at_unix required)", e.value).into());
        }
    }
    Ok(entries)
}

pub struct IocSet {
    c2: Option<c2::IocLookup>,
    local: Vec<ListEntry>,
    allow: Vec<ListEntry>,
    now: u64,
}

impl IocSet {
    pub fn load(
        c2_cache: Option<&Path>,
        local_iocs: Option<&Path>,
        allowlist: Option<&Path>,
        now: u64,
    ) -> Result<Self> {
        let allow = allowlist
            .map(|p| read_list(p, "allowlist"))
            .transpose()?
            .unwrap_or_default();
        if let Some(e) = allow
            .iter()
            .find(|e| e.reason.as_deref().unwrap_or("").trim().is_empty())
        {
            return Err(format!("allowlist entry {:?} needs a reason", e.value).into());
        }
        Ok(Self {
            c2: c2_cache.map(c2::IocLookup::load).transpose()?,
            local: local_iocs
                .map(|p| read_list(p, "local IOC list"))
                .transpose()?
                .unwrap_or_default(),
            allow,
            now,
        })
    }

    #[cfg(test)]
    pub fn from_parts(local: Vec<ListEntry>, allow: Vec<ListEntry>, now: u64) -> Self {
        Self {
            c2: None,
            local,
            allow,
            now,
        }
    }

    fn allow_reason(&self, kind: &str, value: &str) -> Option<String> {
        self.allow
            .iter()
            .filter(|a| a.kind == kind && a.expires_at_unix > self.now)
            .find(|a| match kind {
                "ip" => normalize_ip(&a.value).as_deref() == Some(value),
                _ => normalize_domain(&a.value).is_some_and(|d| domain_matches(&d, value)),
            })
            .and_then(|a| a.reason.clone())
    }

    fn local_evidence(&self, kind: &'static str, value: &str) -> Vec<IocEvidence> {
        self.local
            .iter()
            .filter(|e| e.kind == kind)
            .filter(|e| match kind {
                "ip" => normalize_ip(&e.value).as_deref() == Some(value),
                _ => normalize_domain(&e.value).is_some_and(|d| domain_matches(&d, value)),
            })
            .map(|e| IocEvidence {
                indicator_type: kind,
                normalized_value: value.to_owned(),
                source_id: "local".into(),
                license_ref: "user-supplied".into(),
                observed_at_unix: 0,
                expires_at_unix: e.expires_at_unix,
                version: 1,
                confidence: "medium",
                stale: e.expires_at_unix <= self.now,
                allowlist_reason: self.allow_reason(kind, value),
            })
            .collect()
    }

    /// All IP evidence, stale entries included and flagged.
    pub fn ip(&self, text: &str) -> Vec<IocEvidence> {
        let Some(ip) = normalize_ip(text) else {
            return Vec::new();
        };
        let mut out = self
            .c2
            .as_ref()
            .map(|c| c.evidence(&ip, self.now))
            .unwrap_or_default();
        for e in &mut out {
            e.allowlist_reason = self.allow_reason("ip", &ip);
        }
        out.extend(self.local_evidence("ip", &ip));
        out
    }

    pub fn domain(&self, text: &str) -> Vec<IocEvidence> {
        normalize_domain(text)
            .map(|d| self.local_evidence("domain", &d))
            .unwrap_or_default()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn entry(kind: &str, value: &str, expires: u64, reason: Option<&str>) -> ListEntry {
        ListEntry {
            kind: kind.into(),
            value: value.into(),
            expires_at_unix: expires,
            note: None,
            reason: reason.map(Into::into),
        }
    }

    #[test]
    fn domain_matching_respects_label_boundaries() {
        assert!(domain_matches("evil.example", "evil.example"));
        assert!(domain_matches("evil.example", "a.b.evil.example"));
        assert!(!domain_matches("evil.example", "notevil.example"));
        assert!(!domain_matches("evil.example", "evil.example.org"));
        assert_eq!(
            normalize_domain("A.Evil.Example."),
            Some("a.evil.example".into())
        );
        assert_eq!(normalize_domain("bücher.example"), None);
        assert_eq!(normalize_domain("-bad.example"), None);
        assert_eq!(normalize_ip("::ffff:192.0.2.1"), Some("192.0.2.1".into()));
    }

    #[test]
    fn expired_iocs_are_stale_and_exceptions_expire() {
        let set = IocSet::from_parts(
            vec![
                entry("domain", "evil.example", 2_000, None),
                entry("ip", "192.0.2.7", 500, None),
            ],
            vec![entry(
                "domain",
                "cdn.evil.example",
                1_500,
                Some("vendor CDN, ticket 42"),
            )],
            1_000,
        );
        let fresh = set.domain("x.evil.example");
        assert!(fresh[0].active());
        let allowed = set.domain("a.cdn.evil.example");
        assert_eq!(
            allowed[0].allowlist_reason.as_deref(),
            Some("vendor CDN, ticket 42")
        );
        assert!(!allowed[0].active());
        let stale = set.ip("192.0.2.7");
        assert!(stale[0].stale && !stale[0].active());
        // After the exception expires it no longer suppresses.
        let later = IocSet::from_parts(
            vec![entry("domain", "evil.example", 9_000, None)],
            vec![entry(
                "domain",
                "cdn.evil.example",
                1_500,
                Some("vendor CDN"),
            )],
            2_000,
        );
        assert!(later.domain("a.cdn.evil.example")[0].active());
    }

    #[test]
    fn list_files_require_expiry_type_and_reasons() {
        let dir = std::env::temp_dir().join(format!("aegisguard-ioc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.json");
        std::fs::write(
            &bad,
            r#"[{"type":"domain","value":"evil.example","expires_at_unix":0}]"#,
        )
        .unwrap();
        assert!(IocSet::load(None, Some(&bad), None, 1).is_err());
        let allow = dir.join("allow.json");
        std::fs::write(
            &allow,
            r#"[{"type":"ip","value":"192.0.2.1","expires_at_unix":99}]"#,
        )
        .unwrap();
        assert!(IocSet::load(None, None, Some(&allow), 1).is_err());
        std::fs::write(&bad, r#"[{"type":"url","value":"x","expires_at_unix":9}]"#).unwrap();
        assert!(IocSet::load(None, Some(&bad), None, 1).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
