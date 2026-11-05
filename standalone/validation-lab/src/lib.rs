//! Purely synthetic, non-executing Sysmon fixture generator and verifier.
//! No Windows API, registry, networking, process execution or malware samples.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const VERSION: u32 = 1;
const BASE_MS: u64 = 1_793_872_800_000; // 2026-11-05 10:00:00 UTC
const CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";
const PROVIDER: &str = "Microsoft-Windows-Sysmon";
const MAX_ARTIFACT: u64 = 1024 * 1024;
const MAX_MANIFEST: u64 = 512 * 1024;
const MAX_ACTUAL: u64 = 8 * 1024 * 1024;
const MAX_LINE: usize = 256 * 1024;
const MAX_CASES: usize = 16;
const MAX_EVENTS: usize = 128;
const LIMIT: Duration = Duration::from_secs(5);
const CASES: &[&str] = &[
    "browser-update", "benign-com", "k2f-analog-chain", "missing-log",
    "pid-reuse", "delayed-events", "duplicate-event", "lookalike-path",
    "stale-ioc", "admin-script",
];

type LabResult<T> = Result<T, String>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    pub rule_id: String,
    /// present / absent / unknown / planned; never imply malware or safety.
    pub outcome: String,
    pub event_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub case_id: String,
    pub events: Artifact,
    pub xml: Vec<Artifact>,
    pub extra: Vec<Artifact>,
    pub expected: Vec<Expectation>,
    pub missing_sources: Vec<String>,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub module: String,
    pub generated_at_unix_ms: u64,
    pub seed: u64,
    pub profile: String,
    pub cases: Vec<Case>,
}

#[derive(Clone)]
struct Event {
    event_id: u32,
    record: u64,
    sec: u8,
    fields: BTreeMap<String, String>,
}

impl Event {
    fn stamp(&self) -> String {
        format!("2026-11-05T10:00:{:02}Z", self.sec)
    }

    fn uid(&self) -> String {
        let source = format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            CHANNEL, self.record, PROVIDER, self.event_id, self.stamp()
        );
        sha256(source.as_bytes())[..32].to_string()
    }

    fn envelope(&self) -> Value {
        let mut payload = BTreeMap::new();
        let mut dropped = 0usize;
        for (key, value) in &self.fields {
            match key.as_str() {
                "CommandLine" | "ParentCommandLine" => {
                    payload.insert(format!("{key}_sha256"), sha256(value.as_bytes()));
                }
                "Details" => {
                    payload.insert("Details_sha256".to_owned(), sha256(value.as_bytes()));
                    let com = self.fields.get("TargetObject").is_some_and(|path| {
                        let lower = path.to_ascii_lowercase();
                        lower.contains(r"\clsid\") && lower.contains(r"\inprocserver32\")
                    });
                    if com && value.chars().count() <= 1024 {
                        payload.insert("Details_com_value".to_owned(), value.clone());
                    }
                }
                "User" | "Computer" | "CurrentDirectory" => dropped += 1,
                _ => {
                    payload.insert(key.clone(), value.clone());
                }
            }
        }
        let get = |name: &str| self.fields.get(name).cloned();
        json!({
            "schema_version": 1,
            "event_uid": self.uid(),
            "source": PROVIDER,
            "channel": CHANNEL,
            "source_record_id": self.record,
            "event_id": self.event_id,
            "occurred_at": self.stamp(),
            "occurred_at_unix_ms": BASE_MS + self.sec as u64 * 1000,
            "observed_at_unix_ms": BASE_MS + 60_000,
            "process_guid": get("ProcessGuid"),
            "pid": get("ProcessId").and_then(|v| v.parse::<u32>().ok()),
            "process_start": if self.event_id == 1 { get("UtcTime") } else { None },
            "parent_guid": get("ParentProcessGuid"),
            "artifact_hash": get("Hashes"),
            "ip": get("DestinationIp"),
            "port": get("DestinationPort").and_then(|v| v.parse::<u16>().ok()),
            "dns_name": get("QueryName").or_else(|| get("DestinationHostname")),
            "payload_redacted": payload,
            "completeness": if dropped > 0 { "redacted" } else { "complete" },
            "dropped_fields": dropped
        })
    }

    fn xml(&self) -> String {
        let mut data = String::new();
        for (key, value) in &self.fields {
            data.push_str(&format!(
                "<Data Name='{}'>{}</Data>",
                escape_xml(key), escape_xml(value)
            ));
        }
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\
             <System><Provider Name='{PROVIDER}'/><EventID>{}</EventID>\
             <Version>5</Version><TimeCreated SystemTime='{}'/>\
             <EventRecordID>{}</EventRecordID><Channel>{CHANNEL}</Channel>\
             <Computer>lab.example.invalid</Computer></System>\
             <EventData>{data}</EventData></Event>\n",
            self.event_id, self.stamp(), self.record
        )
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn guid(seed: u64, case: &str, role: &str) -> String {
    let digest = sha256(format!("{seed}:{case}:{role}").as_bytes());
    format!("{{00000000-0000-4000-8000-{}}}", &digest[..12])
}

fn ev(
    events: &mut Vec<Event>,
    serial: u64,
    id: u32,
    second: u8,
    guid: &str,
    pid: u32,
    fields: &[(&str, &str)],
) {
    let mut data: BTreeMap<String, String> = fields
        .iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect();
    data.insert("ProcessGuid".into(), guid.into());
    data.insert("ProcessId".into(), pid.to_string());
    data.insert("UtcTime".into(), format!("2026-11-05 10:00:{second:02}"));
    events.push(Event {
        event_id: id,
        record: serial + events.len() as u64 + 1,
        sec: second,
        fields: data,
    });
}

fn expectation(rule: &str, outcome: &str, events: &[Event], refs: &[usize]) -> Expectation {
    Expectation {
        rule_id: rule.into(),
        outcome: outcome.into(),
        event_refs: refs.iter().map(|i| events[*i].uid()).collect(),
    }
}

/// All paths and hosts are invented. No fixture is an executable or DLL.
fn scenario(seed: u64, name: &str, ordinal: usize) -> LabResult<(Vec<Event>, Vec<Expectation>, Vec<String>, String)> {
    let a = guid(seed, name, "writer");
    let b = guid(seed, name, "browser");
    let c = guid(seed, name, "secondary");
    let serial = (ordinal as u64 + 1) * 100;
    let clsid = r"HKCU\Software\Classes\CLSID\{00000000-0000-4000-8000-000000000123}\InprocServer32\(Default)";
    let dll = r"C:\Users\Lab\AppData\Local\Google\Chrome\User Data\Default\Cache\example-helper.dll";
    let chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    let helper = r"C:\Program Files\LabTools\installer.exe";
    let mut es = Vec::new();
    let mut missing = Vec::new();
    let note: String;
    let expected: Vec<Expectation>;
    match name {
        "browser-update" => {
            let update = r"C:\Users\Lab\AppData\Local\Google\Chrome\Application\131.0\Installer\setup.exe";
            let normal = r"C:\Users\Lab\AppData\Local\Google\Chrome\Application\131.0\chrome_elf.dll";
            ev(&mut es, serial, 1, 1, &a, 1001, &[("Image", update)]);
            ev(&mut es, serial, 11, 2, &a, 1001, &[("Image", update), ("TargetFilename", normal)]);
            ev(&mut es, serial, 1, 3, &b, 1002, &[("Image", chrome)]);
            ev(&mut es, serial, 7, 4, &b, 1002, &[("Image", chrome), ("ImageLoaded", normal)]);
            expected = vec![expectation("AG-B001", "absent", &es, &[]), expectation("AG-B003", "absent", &es, &[])];
            note = "Benign updater control; expected absence is scenario-scoped, not a safety verdict".into();
        }
        "benign-com" => {
            let reg = r"HKLM\Software\Classes\CLSID\{00000000-0000-4000-8000-000000000124}\InprocServer32\(Default)";
            let path = r"C:\Program Files\LabTools\shell-extension.dll";
            ev(&mut es, serial, 1, 1, &a, 1001, &[("Image", helper)]);
            ev(&mut es, serial, 12, 2, &a, 1001, &[("Image", helper), ("EventType", "CreateKey"), ("TargetObject", reg)]);
            ev(&mut es, serial, 13, 3, &a, 1001, &[("Image", helper), ("EventType", "SetValue"), ("TargetObject", reg), ("Details", path)]);
            ev(&mut es, serial, 14, 4, &a, 1001, &[("Image", helper), ("EventType", "RenameKey"), ("TargetObject", r"HKLM\Software\LabTools\OldName")]);
            expected = vec![expectation("AG-B002", "absent", &es, &[])];
            note = "Machine-wide COM registration in a protected installation directory".into();
        }
        "k2f-analog-chain" | "missing-log" | "delayed-events" => {
            ev(&mut es, serial, 1, 1, &a, 1001, &[("Image", helper)]);
            if name != "missing-log" {
                ev(&mut es, serial, 11, 2, &a, 1001, &[("Image", helper), ("TargetFilename", dll)]);
            }
            ev(&mut es, serial, 13, 3, &a, 1001, &[("Image", helper), ("EventType", "SetValue"), ("TargetObject", clsid), ("Details", dll)]);
            ev(&mut es, serial, 1, 4, &b, 1002, &[("Image", chrome)]);
            ev(&mut es, serial, 7, 5, &b, 1002, &[("Image", chrome), ("ImageLoaded", dll)]);
            if name == "delayed-events" {
                // Reorder delivery, without changing true event time.
                es.swap(1, 4);
                es.push(es[1].clone()); // duplicate delivery of the image load
            }
            if name == "missing-log" {
                // A real missing record is represented by a gap, not merely by absence of an ID 11.
                for event in es.iter_mut().skip(1) { event.record += 1; }
                missing.push("sysmon_file_create".into());
                expected = vec![
                    expectation("AG-B002", "present", &es, &[1]),
                    expectation("AG-B003", "unknown", &es, &[]),
                    expectation("AG-B004", "planned", &es, &[]),
                ];
                note = "Missing ID 11 is not evidence of no DLL write".into();
            } else {
                let reg_idx = es.iter().position(|e| e.event_id == 13).ok_or("missing synthetic registry event")?;
                let file_idx = es.iter().position(|e| e.event_id == 11).ok_or("missing synthetic file event")?;
                let load_idx = es.iter().position(|e| e.event_id == 7).ok_or("missing synthetic image load")?;
                expected = vec![
                    expectation("AG-B001", "present", &es, &[file_idx]),
                    expectation("AG-B002", "present", &es, &[reg_idx]),
                    expectation("AG-B003", "present", &es, &[file_idx, reg_idx, load_idx]),
                    expectation("AG-B005", "absent", &es, &[]),
                    expectation("AG-B004", "planned", &es, &[]),
                ];
                note = "Fictional browser DLL/COM chain, NOT a real K2F indicator".into();
            }
        }
        "pid-reuse" => {
            ev(&mut es, serial, 1, 1, &a, 7777, &[("Image", helper)]);
            ev(&mut es, serial, 5, 2, &a, 7777, &[("Image", helper)]);
            ev(&mut es, serial, 1, 3, &c, 7777, &[("Image", chrome)]);
            expected = vec![expectation("AG-PID-REUSE", "planned", &es, &[])];
            note = "Same numeric PID; distinct ProcessGuid and lifetimes".into();
        }
        "duplicate-event" => {
            ev(&mut es, serial, 1, 1, &a, 1001, &[("Image", helper)]);
            ev(&mut es, serial, 22, 2, &a, 1001, &[("Image", helper), ("QueryName", "updates.example.invalid")]);
            es.push(es[1].clone());
            expected = vec![expectation("AG-DEDUP", "planned", &es, &[])];
            note = "Repeated EventUID simulates bookmark replay; must not count twice".into();
        }
        "lookalike-path" => {
            let other = r"C:\Users\Lab\AppData\Local\Other\example-helper.dll";
            let different = r"C:\Users\Lab\AppData\Local\Google\Chrome\User Data\Profile2\example-helper.dll";
            ev(&mut es, serial, 1, 1, &a, 1001, &[("Image", helper)]);
            ev(&mut es, serial, 11, 2, &a, 1001, &[("TargetFilename", other)]);
            ev(&mut es, serial, 13, 3, &a, 1001, &[("EventType", "SetValue"), ("TargetObject", clsid), ("Details", dll)]);
            ev(&mut es, serial, 1, 4, &b, 1002, &[("Image", chrome)]);
            ev(&mut es, serial, 7, 5, &b, 1002, &[("Image", chrome), ("ImageLoaded", different)]);
            expected = vec![
                expectation("AG-B002", "present", &es, &[2]),
                expectation("AG-B003", "absent", &es, &[]),
            ];
            note = "Basename matches but normalized full paths must not be joined".into();
        }
        "stale-ioc" => {
            ev(&mut es, serial, 1, 1, &a, 1001, &[("Image", helper)]);
            ev(&mut es, serial, 3, 2, &a, 1001, &[("Image", helper), ("DestinationIp", "192.0.2.42"), ("DestinationPort", "443")]);
            ev(&mut es, serial, 22, 3, &a, 1001, &[("Image", helper), ("QueryName", "telemetry.example.invalid")]);
            missing.push("fresh_ioc_cache".into());
            expected = vec![expectation("AG-C002", "unknown", &es, &[])];
            note = "Reserved IP and invalid domain; no real IOC feed or network activity".into();
        }
        "admin-script" => {
            ev(&mut es, serial, 1, 1, &a, 1001, &[
                ("Image", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
                ("CommandLine", r"powershell.exe -NoProfile -File C:\Lab\maintenance.ps1"),
                ("ParentImage", helper),
            ]);
            expected = vec![expectation("AG-B004", "planned", &es, &[])];
            note = "Command line is hashed in JSON; no PowerShell code or script is created/executed".into();
        }
        _ => return Err("unsupported profile".into()),
    }
    Ok((es, expected, missing, note))
}

fn read_bounded(path: &Path, cap: u64) -> LabResult<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("cannot stat input: {:?}", e.kind()))?;
    if !meta.is_file() || meta.file_type().is_symlink() || is_reparse(&meta) || meta.len() > cap {
        return Err("input is not a regular, non-link, bounded file".into());
    }
    let input = File::open(path).map_err(|e| format!("cannot read input: {:?}", e.kind()))?;
    let mut bytes = Vec::new();
    input.take(cap + 1).read_to_end(&mut bytes).map_err(|e| format!("input read failed: {:?}", e.kind()))?;
    if bytes.len() as u64 > cap {
        return Err("input exceeds size limit".into());
    }
    Ok(bytes)
}

#[cfg(windows)]
fn is_reparse(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(_: &fs::Metadata) -> bool { false }

fn safe_rel(root: &Path, relative: &str) -> LabResult<std::path::PathBuf> {
    if relative.is_empty() || relative.contains('\\') || relative.len() > 200 {
        return Err("invalid fixture relative path".into());
    }
    let p = Path::new(relative);
    if !p.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err("unsafe fixture relative path".into());
    }
    let mut current = root.to_path_buf();
    for part in p.components() {
        current.push(part.as_os_str());
        let meta = fs::symlink_metadata(&current).map_err(|e| format!("fixture missing: {:?}", e.kind()))?;
        if meta.file_type().is_symlink() || is_reparse(&meta) {
            return Err("fixture includes link/reparse point".into());
        }
    }
    Ok(current)
}

fn new_file(path: &Path, bytes: &[u8]) -> LabResult<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| format!("cannot create fixture: {:?}", e.kind()))?;
    file.write_all(bytes).map_err(|e| format!("fixture write failed: {:?}", e.kind()))?;
    file.sync_all().map_err(|e| format!("fixture sync failed: {:?}", e.kind()))?;
    Ok(())
}

fn record(path: String, bytes: &[u8]) -> Artifact {
    Artifact { path, sha256: sha256(bytes), bytes: bytes.len() as u64 }
}

pub fn generate(out: &Path, seed: u64, profile: &str) -> LabResult<Value> {
    if profile != "all" && !CASES.contains(&profile) {
        return Err("unsupported profile".into());
    }
    // create_dir deliberately fails if output exists: no overwrites or cleanup.
    fs::create_dir(out).map_err(|e| format!("output directory must not exist: {:?}", e.kind()))?;
    let mut cases = Vec::new();
    let mut count = 0usize;
    for (ordinal, &name) in CASES.iter().enumerate() {
        if profile != "all" && profile != name { continue; }
        let case_dir = out.join(name);
        fs::create_dir(&case_dir).map_err(|e| format!("cannot create case directory: {:?}", e.kind()))?;
        let (events, expected, missing_sources, note) = scenario(seed, name, ordinal)?;
        let mut lines = Vec::new();
        let mut xml = Vec::new();
        for (idx, e) in events.iter().enumerate() {
            let mut line = serde_json::to_vec(&e.envelope()).map_err(|_| "cannot encode event")?;
            line.push(b'\n');
            if line.len() > MAX_LINE { return Err("synthetic event exceeds size cap".into()); }
            lines.extend_from_slice(&line);
            let rel = format!("{name}/event-{idx:03}.xml");
            let bytes = e.xml().into_bytes();
            new_file(&out.join(&rel), &bytes)?;
            xml.push(record(rel, &bytes));
        }
        let rel = format!("{name}/events.jsonl");
        new_file(&out.join(&rel), &lines)?;
        let mut extra = Vec::new();
        let marker = format!("AegisGuard synthetic fixture: {name} seed={seed}\nNothing in this directory should be executed.\n");
        let marker_rel = format!("{name}/inert.txt");
        new_file(&out.join(&marker_rel), marker.as_bytes())?;
        extra.push(record(marker_rel, marker.as_bytes()));
        if name == "stale-ioc" {
            let snapshot = serde_json::to_vec_pretty(&json!({
                "schema_version":1,
                "source":"offline_synthetic_only",
                "indicator":"192.0.2.42",
                "expires_at_unix_ms":BASE_MS - 86_400_000,
                "compatible_with_aegisguard_c2_cache":false
            })).map_err(|_| "cannot encode synthetic IOC")?;
            let ioc_rel = format!("{name}/expired-ioc.json");
            new_file(&out.join(&ioc_rel), &snapshot)?;
            extra.push(record(ioc_rel, &snapshot));
        }
        cases.push(Case {
            case_id: name.into(), events: record(rel, &lines), xml, extra,
            expected, missing_sources, note,
        });
        count += events.len();
    }
    let manifest = Manifest {
        schema_version: VERSION, module: "validation-lab".into(),
        generated_at_unix_ms: BASE_MS, seed, profile: profile.into(), cases,
    };
    let mut data = serde_json::to_vec_pretty(&manifest).map_err(|_| "cannot encode manifest")?;
    data.push(b'\n');
    if data.len() as u64 > MAX_MANIFEST { return Err("manifest too large".into()); }
    new_file(&out.join("manifest.json"), &data)?;
    Ok(output("complete", json!({"cases":manifest.cases.len(),"events":count}), vec![], json!({"manifest_sha256":sha256(&data)})))
}

fn load_manifest(path: &Path) -> LabResult<Manifest> {
    let bytes = read_bounded(path, MAX_MANIFEST)?;
    let man: Manifest = serde_json::from_slice(&bytes).map_err(|_| "invalid manifest JSON or unknown fields")?;
    if man.schema_version != VERSION || man.module != "validation-lab" {
        return Err("unknown manifest schema or module".into());
    }
    if man.cases.is_empty() || man.cases.len() > MAX_CASES {
        return Err("invalid number of cases".into());
    }
    let mut ids = BTreeSet::new();
    for c in &man.cases {
        if !CASES.contains(&c.case_id.as_str()) || !ids.insert(c.case_id.as_str()) {
            return Err("unknown or duplicate case".into());
        }
        if c.xml.len() > MAX_EVENTS { return Err("too many events".into()); }
        for e in &c.expected {
            if !["present","absent","unknown","planned"].contains(&e.outcome.as_str())
                || e.rule_id.len() > 64 || e.event_refs.len() > MAX_EVENTS {
                return Err("invalid expected rule".into());
            }
        }
    }
    Ok(man)
}

fn verify_artifact(root: &Path, artifact: &Artifact) -> LabResult<Vec<u8>> {
    if artifact.bytes > MAX_ARTIFACT || artifact.sha256.len() != 64 ||
        !artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid artifact metadata or size".into());
    }
    let path = safe_rel(root, &artifact.path)?;
    let bytes = read_bounded(&path, MAX_ARTIFACT)?;
    if bytes.len() as u64 != artifact.bytes || sha256(&bytes) != artifact.sha256 {
        return Err("artifact content hash/length mismatch".into());
    }
    Ok(bytes)
}

pub fn verify(dir: &Path) -> LabResult<Value> {
    let meta = fs::symlink_metadata(dir).map_err(|e| format!("fixture directory not accessible: {:?}",e.kind()))?;
    if !meta.is_dir() || meta.file_type().is_symlink() || is_reparse(&meta) {
        return Err("fixture root must be a real directory".into());
    }
    let started = Instant::now();
    let manifest = load_manifest(&dir.join("manifest.json"))?;
    let total_claimed: u64 = manifest.cases.iter().flat_map(|c| {
        c.xml.iter().chain(c.extra.iter()).chain(std::iter::once(&c.events))
    }).try_fold(0u64, |sum, a| sum.checked_add(a.bytes))
        .ok_or("manifest byte count overflow")?;
    if total_claimed > 16 * 1024 * 1024 {
        return Err("aggregate fixture size exceeds 16 MiB".into());
    }
    let mut num = 0usize;
    let mut errors = Vec::new();
    for case in &manifest.cases {
        let mut event_uids = BTreeSet::new();
        let mut event_lines = 0usize;
        if started.elapsed() > LIMIT { return Err("verification time budget exceeded".into()); }
        let mut all = case.xml.clone();
        all.push(case.events.clone());
        all.extend(case.extra.clone());
        let mut known = BTreeSet::new();
        for a in &all {
            if !known.insert(a.path.as_str()) { errors.push("duplicate artifact path".into()); continue; }
            if !a.path.starts_with(&format!("{}/",case.case_id)) {
                errors.push("artifact path is outside its case".into()); continue;
            }
            match verify_artifact(dir, a) {
                Ok(bytes) if a.path.ends_with("/events.jsonl") => {
                    if bytes.is_empty() { errors.push("empty event spool".into()); continue; }
                    if !bytes.ends_with(b"\n") || bytes.starts_with(b"\n") ||
                        bytes.windows(2).any(|w| w == b"\n\n") {
                        errors.push("incomplete or blank JSONL line".into());
                        continue;
                    }
                    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                        if line.len() > MAX_LINE { errors.push("oversized JSONL line".into()); break; }
                        match serde_json::from_slice::<Value>(line) {
                            Ok(v) if v["schema_version"] == 1 && v["event_uid"].as_str().is_some()
                                && v["source"] == PROVIDER => {
                                    num += 1;
                                    event_lines += 1;
                                    if let Some(uid) = v["event_uid"].as_str() { event_uids.insert(uid.to_owned()); }
                                }
                            _ => errors.push("malformed or incompatible event JSONL".into()),
                        }
                    }
                }
                Ok(bytes) if a.path == "stale-ioc/expired-ioc.json" => {
                    match serde_json::from_slice::<Value>(&bytes) {
                        Ok(v) if v["expires_at_unix_ms"].as_u64().is_some_and(|t| t < BASE_MS)
                            && v["indicator"] == "192.0.2.42"
                            && v["compatible_with_aegisguard_c2_cache"] == false => {}
                        _ => errors.push("invalid or non-expired synthetic IOC".into()),
                    }
                }
                Ok(_) => {}
                Err(e) => errors.push(e),
            }
        }
        if event_lines != case.xml.len() {
            errors.push(format!("event/XML count mismatch in {}",case.case_id));
        }
        if case.expected.iter().flat_map(|e| e.event_refs.iter()).any(|uid| !event_uids.contains(uid)) {
            errors.push(format!("unresolved expected event reference in {}",case.case_id));
        }
    }
    if num > MAX_CASES * MAX_EVENTS { errors.push("too many event lines".into()); }
    let status = if errors.is_empty() { "complete" } else { "partial" };
    Ok(output(status, json!({"cases":manifest.cases.len(),"events":num}), errors, json!({"verification":"hash_and_schema_only","malware_executed":false})))
}

pub fn summarize(expected: &Path, actual: &Path) -> LabResult<Value> {
    let started = Instant::now();
    let manifest = load_manifest(expected)?;
    let bytes = read_bounded(actual, MAX_ACTUAL)?;
    if !bytes.is_empty() && (!bytes.ends_with(b"\n") || bytes.starts_with(b"\n") ||
        bytes.windows(2).any(|w| w == b"\n\n")) {
        return Err("incomplete or blank report JSONL line".into());
    }
    let mut reports = BTreeMap::<String, Value>::new();
    let mut warnings = Vec::new();
    let mut lines = 0usize;
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        if started.elapsed() > LIMIT { return Err("summary time budget exceeded".into()); }
        lines += 1;
        if lines > MAX_CASES || line.len() > MAX_LINE { return Err("report count/line size exceeded".into()); }
        let v: Value = serde_json::from_slice(line).map_err(|_| "invalid report JSONL")?;
        if v.get("schema_version").is_some() && v["schema_version"] != VERSION {
            return Err("unknown actual report schema".into());
        }
        if v.get("ruleset_version").is_some() && v["ruleset_version"] != 2 {
            return Err("unknown AegisGuard correlation ruleset version".into());
        }
        let case_id = v["case_id"].as_str().or_else(|| {
            if manifest.cases.len() == 1 { Some(manifest.cases[0].case_id.as_str()) } else { None }
        }).ok_or("report lacks case_id for multi-case corpus")?;
        if !manifest.cases.iter().any(|c| c.case_id == case_id) ||
            reports.insert(case_id.to_owned(), v).is_some() {
            return Err("unknown or duplicate report case_id".into());
        }
    }
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut unknown = 0usize;
    let mut planned = 0usize;
    let mut entries = Vec::new();
    for case in &manifest.cases {
        let report = reports.get(&case.case_id);
        if report.is_none() { warnings.push(format!("missing report for {}",case.case_id)); }
        for rule in &case.expected {
            let assessment = match rule.outcome.as_str() {
                "planned" => { planned += 1; "planned" }
                "unknown" => { unknown += 1; "unknown" }
                _ => {
                    let report_complete = report.is_some_and(|v| {
                        v["rules"].is_array() && v["findings"].is_array()
                            && v.get("analysis_complete") != Some(&Value::Bool(false))
                            && (v.get("status").is_none() || v["status"] == "complete" || v["status"] == "ok")
                    });
                    let evaluable = if report_complete {
                        report.and_then(|v| v["rules"].as_array()).and_then(|rs| {
                            rs.iter().find(|r| r["rule_id"].as_str() == Some(rule.rule_id.as_str()))
                        }).and_then(|r| r["evaluable"].as_bool())
                    } else { None };
                    if evaluable != Some(true) { unknown += 1; "unknown" }
                    else {
                        let found = report.and_then(|v| v["findings"].as_array()).is_some_and(|fs| {
                            fs.iter().any(|f| {
                                if f["rule_id"].as_str() != Some(rule.rule_id.as_str()) { return false; }
                                let refs = f["event_refs"].as_array();
                                rule.event_refs.iter().all(|id| {
                                    refs.is_some_and(|arr| arr.iter().any(|x| x.as_str() == Some(id)))
                                })
                            })
                        });
                        if (rule.outcome == "present") == found { passed += 1; "pass" }
                        else { failed += 1; "fail" }
                    }
                }
            };
            entries.push(json!({
                "case_id":case.case_id,"rule_id":rule.rule_id,
                "expected":rule.outcome,"assessment":assessment
            }));
        }
    }
    let status = if failed > 0 || unknown > 0 || planned > 0 || !warnings.is_empty() { "partial" } else { "complete" };
    Ok(output(status, json!({
        "cases":manifest.cases.len(), "reports":reports.len(),
        "passed":passed, "failed":failed, "unknown":unknown, "planned":planned
    }), warnings, json!({"synthetic_only":true,"detection_rate_claimed":false,"evaluations":entries})))
}

fn output(status: &str, coverage: Value, warnings: Vec<String>, entries: Value) -> Value {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    json!({
        "schema_version":VERSION,"module":"validation-lab",
        "generated_at_unix_ms":now,"status":status,
        "entries":entries,"warnings":warnings,"coverage":coverage
    })
}

pub fn error_output(error: &str) -> Value {
    let status = if error.contains("PermissionDenied") { "permission_denied" }
        else if error.contains("NotFound") || error.contains("not accessible") { "unavailable" }
        else { "error" };
    output(status, json!({"cases":0,"events":0}), vec![error.into()], json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_seed_and_different_seed() {
        let a = scenario(42, "k2f-analog-chain", 2).unwrap().0;
        let b = scenario(42, "k2f-analog-chain", 2).unwrap().0;
        let c = scenario(43, "k2f-analog-chain", 2).unwrap().0;
        assert_eq!(a[0].envelope(), b[0].envelope());
        assert_ne!(a[0].envelope(), c[0].envelope());
        assert!(a.iter().all(|e| !e.xml().contains("AEGIS-SYNTHETIC-SECRET")));
    }
    #[test]
    fn every_scenario_is_safe_and_bounded() {
        for (i, name) in CASES.iter().enumerate() {
            let (events, expected, _, _) = scenario(42,name,i).unwrap();
            assert!(!events.is_empty() && events.len() < 64);
            assert!(events.iter().all(|e| [1,3,5,7,11,12,13,14,22].contains(&e.event_id)));
            assert!(expected.iter().all(|x| !x.rule_id.is_empty()));
            assert!(events.iter().all(|e| e.xml().len() < 64 * 1024));
        }
    }
}
