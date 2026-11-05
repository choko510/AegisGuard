use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_ENTRIES: usize = 2_048;
pub const MAX_ADVISORIES: usize = 1_024;
pub const MAX_MATCHES: usize = 1_024;
pub const SOURCES: [&str; 4] = ["hklm64", "hklm32", "hkcu64", "hkcu32"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEntry {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub edition: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceData {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub entries: Vec<RawEntry>,
    /// Subkeys that were present but could not be represented safely.
    #[serde(default)]
    pub skipped: usize,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub schema_version: u32,
    pub sources: Vec<SourceData>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareEntry {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub architecture: Option<String>,
    pub edition: Option<String>,
    pub install_scope: String,
    pub sources: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCoverage {
    pub id: String,
    pub status: String,
    pub seen: usize,
    #[serde(default)]
    pub skipped: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub scope: String,
    pub sources: Vec<SourceCoverage>,
    pub skipped: usize,
    pub truncated: bool,
    pub evaluated: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryReport {
    pub schema_version: u32,
    pub module: String,
    pub generated_at_unix_ms: u64,
    pub status: String,
    pub entries: Vec<SoftwareEntry>,
    pub warnings: Vec<String>,
    pub coverage: Coverage,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryBatch {
    pub schema_version: u32,
    pub source_checked_at_unix_ms: u64,
    pub advisories: Vec<Advisory>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    pub id: String,
    pub vendor: String,
    pub product: String,
    #[serde(default)]
    pub publisher_aliases: Vec<String>,
    #[serde(default)]
    pub product_aliases: Vec<String>,
    pub version_ranges: Vec<VersionRange>,
    #[serde(default)]
    pub unaffected_versions: Vec<String>,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub editions: Vec<String>,
    pub source_url: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    pub start_inclusive: Option<String>,
    pub end_exclusive: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub kind: String,
    pub detail: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct AdvisoryMatch {
    pub software_name: String,
    pub installed_version: Option<String>,
    pub advisory_id: String,
    pub classification: String,
    pub confidence: String,
    pub evidence: Vec<Evidence>,
    pub source_checked_at_unix_ms: u64,
    pub advisory_url: String,
}
#[derive(Debug, Serialize)]
pub struct MatchReport {
    pub schema_version: u32,
    pub module: String,
    pub generated_at_unix_ms: u64,
    pub status: String,
    pub entries: Vec<AdvisoryMatch>,
    pub warnings: Vec<String>,
    pub coverage: Coverage,
}
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| u64::try_from(t.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
pub fn valid_text(value: &str, max_bytes: usize) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed.len() <= max_bytes && !trimmed.chars().any(char::is_control)
}
pub fn normalize(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}
