//! P6-03: browser-hijack correlation rules (AG-B001..AG-B005).
//!
//! They join Sysmon file creation (ID 11), COM registry changes (ID 13) and
//! module loads (ID 7) by ProcessGuid, time and normalized path. Each finding
//! is a reason to look, not a verdict: browsers and their updaters create
//! DLLs and register COM servers legitimately, so the rules suppress what is
//! explainable and say which event sources were missing.
use super::correlate::{Finding, RuleStatus};
use super::process::{
    path_key, ProcessRecord, ProcessTable, FILE_CREATE, IMAGE_LOAD, PROCESS_CREATE,
    REGISTRY_VALUE_SET,
};
use super::{ComScope, ComServerKind};
use std::collections::BTreeMap;

const RULE_VERSION: u32 = 1;
/// Ordering tolerance between the steps of a chain (clock skew, buffering).
const SKEW_MS: i64 = 2 * 60 * 1000;

/// Per-user data roots of browsers (lower-case, backslash form).
pub(crate) const USER_DATA_ROOTS: &[&str] = &[
    r"\google\chrome\user data\",
    r"\microsoft\edge\user data\",
    r"\bravesoftware\brave-browser\user data\",
    r"\vivaldi\user data\",
    r"\opera software\",
    r"\mozilla\firefox\profiles\",
];
/// Install/update locations of browsers (lower-case).
const BROWSER_INSTALL_DIRS: &[&str] = &[
    r"\google\chrome\application\",
    r"\google\update\",
    r"\google\googleupdater\",
    r"\microsoft\edge\application\",
    r"\microsoft\edgeupdate\",
    r"\microsoft\edgewebview\application\",
    r"\bravesoftware\",
    r"\mozilla firefox\",
    r"\mozilla maintenance service\",
    r"\vivaldi\application\",
    r"\programs\opera\",
];
const BROWSER_IMAGES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "firefox.exe",
    "opera.exe",
    "vivaldi.exe",
];

pub(crate) fn under(path_key: &str, roots: &[&str]) -> bool {
    roots.iter().any(|r| path_key.contains(r))
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// A browser itself (by name, from its install directory).
pub(crate) fn is_browser(p: &ProcessRecord) -> bool {
    p.image.as_deref().is_some_and(|i| {
        let key = path_key(i);
        BROWSER_IMAGES.contains(&basename(i).as_str()) && under(&key, BROWSER_INSTALL_DIRS)
    })
}

/// A browser or one of its installers/updaters, judged by install location.
pub(crate) fn is_browser_component(p: &ProcessRecord) -> bool {
    p.image
        .as_deref()
        .is_some_and(|i| under(&path_key(i), BROWSER_INSTALL_DIRS))
}

pub(crate) fn user_writable(key: &str) -> bool {
    key.contains(r"\appdata\")
        || key.contains(r"\users\public\")
        || key.contains(r"\temp\")
        || key.contains(r"\programdata\")
        || key.contains(r"\downloads\")
}

fn is_dll(key: &str) -> bool {
    key.ends_with(".dll")
}

/// A COM value names a module path; strip arguments/quotes conservatively.
pub(crate) fn com_value_path(value: &str) -> String {
    let v = value.trim();
    let v = if let Some(rest) = v.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest)
    } else {
        v
    };
    path_key(v)
}

fn observed(table: &ProcessTable, id: u32) -> bool {
    table.observed_event_ids.contains_key(&id)
}

fn missing(table: &ProcessTable, needs: &[(u32, &'static str)]) -> Vec<&'static str> {
    needs
        .iter()
        .filter(|(id, _)| !observed(table, *id))
        .map(|(_, name)| *name)
        .collect()
}

const NEED_FILE: (u32, &str) = (FILE_CREATE, "sysmon_file_create");
const NEED_REG: (u32, &str) = (REGISTRY_VALUE_SET, "sysmon_registry_value_set");
const NEED_LOAD: (u32, &str) = (IMAGE_LOAD, "sysmon_image_load");
const NEED_CREATE: (u32, &str) = (PROCESS_CREATE, "sysmon_process_create");

pub fn rule_status(table: &ProcessTable) -> Vec<RuleStatus> {
    let status = |rule_id, needs: &[(u32, &'static str)]| {
        let missing_sources = missing(table, needs);
        RuleStatus {
            rule_id,
            rule_version: RULE_VERSION,
            evaluable: missing_sources.is_empty(),
            missing_sources,
        }
    };
    vec![
        status("AG-B001", &[NEED_FILE, NEED_CREATE]),
        status("AG-B002", &[NEED_REG]),
        status("AG-B003", &[NEED_FILE, NEED_REG, NEED_LOAD]),
        // Reading credential files is only visible through Security 4663
        // object-access auditing that an administrator configured (P6-04).
        {
            let audit = table
                .observed_security_event_ids
                .contains_key(&super::process::OBJECT_ACCESS);
            let mut missing_sources = Vec::new();
            if !audit {
                missing_sources.push("credential_file_read_audit");
            }
            RuleStatus {
                rule_id: "AG-B004",
                rule_version: RULE_VERSION,
                evaluable: audit,
                missing_sources,
            }
        },
        // Partially evaluable with any one of the three sources.
        RuleStatus {
            rule_id: "AG-B005",
            rule_version: RULE_VERSION,
            evaluable: observed(table, FILE_CREATE)
                || observed(table, REGISTRY_VALUE_SET)
                || observed(table, IMAGE_LOAD),
            missing_sources: missing(table, &[NEED_FILE, NEED_REG, NEED_LOAD]),
        },
    ]
}

struct Created<'a> {
    by: &'a ProcessRecord,
    at: Option<i64>,
    uid: &'a str,
}

struct Registered<'a> {
    by: &'a ProcessRecord,
    clsid: &'a str,
    at: Option<i64>,
    uid: &'a str,
}

struct Loaded<'a> {
    by: &'a ProcessRecord,
    at: Option<i64>,
    uid: &'a str,
    signed: Option<bool>,
}

fn not_after(a: Option<i64>, b: Option<i64>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a <= b + SKEW_MS,
        // Unknown times cannot order the chain; do not claim it.
        _ => false,
    }
}

/// Events behind a finding and their times.
#[derive(Default)]
struct Evidence {
    refs: Vec<String>,
    times: Vec<Option<i64>>,
    /// AG-B005 only: which kinds of trace were seen.
    kinds: Vec<&'static str>,
    process: String,
}

fn finding(
    rule_id: &'static str,
    process_key: &str,
    evidence: Evidence,
    confidence: &'static str,
    missing_sources: Vec<&'static str>,
    verdict: &'static str,
    explanation: &'static str,
) -> Finding {
    let known: Vec<i64> = evidence.times.iter().flatten().copied().collect();
    Finding {
        rule_id,
        rule_version: RULE_VERSION,
        process_key: process_key.to_owned(),
        event_refs: evidence.refs,
        window_start_unix_ms: known.iter().min().copied(),
        window_end_unix_ms: known.iter().max().copied(),
        confidence,
        missing_sources,
        suppressed_reason: None,
        verdict,
        explanation,
    }
}

pub fn evaluate(table: &ProcessTable, findings: &mut Vec<Finding>) {
    // Index evidence by normalized path across all processes.
    let mut created: BTreeMap<&str, Vec<Created>> = BTreeMap::new();
    let mut registered: BTreeMap<String, Vec<Registered>> = BTreeMap::new();
    let mut loaded: BTreeMap<&str, Vec<Loaded>> = BTreeMap::new();
    for p in table.processes.values() {
        for f in &p.created_files {
            created
                .entry(f.path_key.as_str())
                .or_default()
                .push(Created {
                    by: p,
                    at: f.at_unix_ms,
                    uid: &f.event_uid,
                });
        }
        for r in &p.registry_changes {
            let (Some(com), Some(value)) = (&r.com, &r.com_value) else {
                continue;
            };
            if r.kind != "set_value"
                || com.scope != ComScope::PerUser
                || com.server != ComServerKind::InprocServer32
            {
                continue;
            }
            registered
                .entry(com_value_path(value))
                .or_default()
                .push(Registered {
                    by: p,
                    clsid: &com.clsid,
                    at: r.at_unix_ms,
                    uid: &r.event_uid,
                });
        }
        for l in &p.loaded_images {
            loaded.entry(l.path_key.as_str()).or_default().push(Loaded {
                by: p,
                at: l.at_unix_ms,
                uid: &l.event_uid,
                signed: l.signed,
            });
        }
    }

    // AG-B001: a DLL written into a browser's user data by something that is
    // neither the browser nor its installer/updater.
    for (path, events) in &created {
        if !(is_dll(path) && under(path, USER_DATA_ROOTS)) {
            continue;
        }
        for c in events.iter().filter(|c| !is_browser_component(c.by)) {
            let unknown_image = c.by.image.is_none();
            findings.push(finding(
                "AG-B001",
                &c.by.process_guid,
                Evidence {
                    refs: vec![c.uid.to_owned()],
                    times: vec![c.at],
                    ..Evidence::default()
                },
                "low",
                if unknown_image { vec!["sysmon_process_create"] } else { vec![] },
                "observed",
                "A process that is not a browser or browser updater created a DLL inside a browser's user data folder",
            ));
        }
    }

    // AG-B002: a per-user InprocServer32 that loads a DLL from a
    // user-writable location (per-user COM overrides machine-wide classes).
    for (path, regs) in &registered {
        if !user_writable(path) {
            continue;
        }
        for r in regs {
            let own_component = is_browser_component(r.by) && !under(path, USER_DATA_ROOTS);
            let mut f = finding(
                "AG-B002",
                &r.by.process_guid,
                Evidence {
                    refs: vec![r.uid.to_owned()],
                    times: vec![r.at],
                    ..Evidence::default()
                },
                if under(path, USER_DATA_ROOTS) { "medium" } else { "low" },
                vec![],
                "review",
                "A per-user COM InprocServer32 registration loads a DLL from a user-writable folder; per-user classes take precedence over machine-wide ones",
            );
            if own_component {
                f.suppressed_reason = Some(format!(
                    "registered by a browser component for a file outside browser user data ({})",
                    r.clsid
                ));
                f.verdict = "observed";
            }
            findings.push(f);
        }
    }

    // AG-B003: DLL created -> registered as per-user COM server -> loaded by
    // a browser, joined by path and ordered in time.
    for (path, regs) in &registered {
        let Some(loads) = loaded.get(path.as_str()) else {
            continue;
        };
        for r in regs {
            for l in loads.iter().filter(|l| is_browser(l.by)) {
                if !not_after(r.at, l.at) {
                    continue;
                }
                let creation = created.get(path.as_str()).and_then(|cs| {
                    cs.iter()
                        .filter(|c| !is_browser_component(c.by) && not_after(c.at, r.at))
                        .min_by_key(|c| c.at)
                });
                let mut refs = vec![r.uid.to_owned(), l.uid.to_owned()];
                let mut times = vec![r.at, l.at];
                let (confidence, missing_sources) = match creation {
                    Some(c) => {
                        refs.insert(0, c.uid.to_owned());
                        times.insert(0, c.at);
                        ("high", vec![])
                    }
                    None if !observed(table, FILE_CREATE) => ("medium", vec!["sysmon_file_create"]),
                    // Created before collection started, or by an unseen process.
                    None => ("medium", vec![]),
                };
                let mut f = finding(
                    "AG-B003",
                    &r.by.process_guid,
                    Evidence {
                        refs,
                        times,
                        ..Evidence::default()
                    },
                    confidence,
                    missing_sources,
                    "review",
                    "A DLL registered as a per-user COM server was then loaded by a browser (DLL/COM hijack pattern)",
                );
                if l.signed == Some(true) && is_browser_component(r.by) {
                    f.suppressed_reason =
                        Some("signed module registered by a browser component".into());
                    f.verdict = "observed";
                }
                findings.push(f);
            }
        }
    }

    credential_reads(table, findings);

    // AG-B005: the publicly reported k2f traces (path shape and CLSID).
    let k2f_clsid = crate::browser::CLSID;
    let mut by_path: BTreeMap<&str, Evidence> = BTreeMap::new();
    for (path, cs) in &created {
        if crate::browser::matches_trace_shape(path) {
            let e = by_path.entry(path).or_default();
            for c in cs {
                e.refs.push(c.uid.to_owned());
                e.times.push(c.at);
                e.process = c.by.process_guid.clone();
            }
            e.kinds.push("file_create");
        }
    }
    for (path, regs) in &registered {
        for r in regs {
            if r.clsid == k2f_clsid || crate::browser::matches_trace_shape(path) {
                let e = by_path.entry(path.as_str()).or_default();
                e.refs.push(r.uid.to_owned());
                e.times.push(r.at);
                e.kinds.push("com_registration");
                if e.process.is_empty() {
                    e.process = r.by.process_guid.clone();
                }
            }
        }
    }
    for (path, ls) in &loaded {
        if crate::browser::matches_trace_shape(path) {
            let e = by_path.entry(path).or_default();
            for l in ls {
                e.refs.push(l.uid.to_owned());
                e.times.push(l.at);
                if e.process.is_empty() {
                    e.process = l.by.process_guid.clone();
                }
            }
            e.kinds.push("image_load");
        }
    }
    for (_, mut e) in by_path {
        e.kinds.sort_unstable();
        e.kinds.dedup();
        let confidence = if e.kinds.len() >= 2 { "high" } else { "medium" };
        let process = std::mem::take(&mut e.process);
        findings.push(finding(
            "AG-B005",
            &process,
            e,
            confidence,
            missing(table, &[NEED_FILE, NEED_REG, NEED_LOAD]),
            "review",
            "Matches the publicly reported k2f traces (PlatformExperienceHelper\\<64 hex>\\platform_experience_helper.dll and/or CLSID {E77CC89B-7401-4C04-8CED-149DB35ADD04}); see browser k2f for the current state. A match is not proof of infection",
        ));
    }
}

/// Credential stores of browsers (file name, browser image that owns them).
const CREDENTIAL_FILES: &[&str] = &[
    "login data",
    "cookies",
    "web data",
    "local state",
    "key4.db",
    "logins.json",
    "cookies.sqlite",
];
/// Programs expected to read these files besides the browser itself.
const EXPECTED_READERS: &[&str] = &[
    "msmpeng.exe",
    "mpdefendercoreservice.exe",
    "searchprotocolhost.exe",
];
/// AG-B004: a read followed by contact with a fresh C2 IOC within this window.
const EXFIL_WINDOW_MS: i64 = 10 * 60 * 1000;

fn is_credential_store(path_key: &str) -> bool {
    under(path_key, USER_DATA_ROOTS) && CREDENTIAL_FILES.contains(&basename(path_key).as_str())
}

/// The browser that owns a store, read from its own install location.
fn owner_browser(path_key: &str, reader: &str) -> bool {
    let image = basename(reader);
    let data_dir = match image.as_str() {
        "chrome.exe" => r"\google\chrome\",
        "msedge.exe" => r"\microsoft\edge\",
        "brave.exe" => r"\bravesoftware\",
        "firefox.exe" => r"\mozilla\firefox\",
        "vivaldi.exe" => r"\vivaldi\",
        "opera.exe" => r"\opera software\",
        _ => return false,
    };
    under(&path_key_of(reader), BROWSER_INSTALL_DIRS) && path_key.contains(data_dir)
}

fn path_key_of(path: &str) -> String {
    super::process::path_key(path)
}

/// AG-B004: credential-store reads by programs other than the owning
/// browser, escalated when the same process then contacted a fresh C2 IOC.
fn credential_reads(table: &ProcessTable, findings: &mut Vec<Finding>) {
    for read in &table.file_reads {
        if !is_credential_store(&read.path_key) {
            continue;
        }
        let reader = read.process_name.clone().unwrap_or_default();
        if owner_browser(&read.path_key, &reader)
            || EXPECTED_READERS.contains(&basename(&reader).as_str())
        {
            continue;
        }
        // Link to a Sysmon process by image and PID alive at that time.
        let process = table.processes.values().find(|p| {
            p.pid == read.pid
                && p.image.as_deref().map(path_key_of) == Some(path_key_of(&reader))
                && match (p.started_at_unix_ms, read.at_unix_ms) {
                    (Some(s), Some(t)) => s <= t && p.ended_at_unix_ms.is_none_or(|e| t <= e),
                    _ => false,
                }
        });
        let contact = process.and_then(|p| {
            p.contacts
                .iter()
                .find(|c| match (c.at_unix_ms, read.at_unix_ms) {
                    (Some(c_at), Some(t)) => c_at >= t && c_at - t <= EXFIL_WINDOW_MS,
                    _ => false,
                })
        });
        let mut refs = vec![read.event_uid.clone()];
        let mut times = vec![read.at_unix_ms];
        if let Some(c) = contact {
            refs.push(c.event_uid.clone());
            times.push(c.at_unix_ms);
        }
        let process_key = process.map_or_else(
            || format!("pid:{}", read.pid.unwrap_or(0)),
            |p| p.process_guid.clone(),
        );
        let mut f = finding(
            "AG-B004",
            &process_key,
            Evidence {
                refs,
                times,
                ..Evidence::default()
            },
            if contact.is_some() { "medium" } else { "low" },
            if process.is_none() {
                vec!["sysmon_process_create"]
            } else {
                vec![]
            },
            if contact.is_some() {
                "review"
            } else {
                "observed"
            },
            if contact.is_some() {
                "A program other than the browser read a browser credential store and then connected out; check what it sent"
            } else {
                "A program other than the browser read a browser credential store (backup and security tools do this too)"
            },
        );
        f.suppressed_reason = None;
        findings.push(f);
    }
}

#[cfg(test)]
mod tests {
    use super::super::correlate::correlate;
    use super::super::process::tests::{create, ev};
    use super::super::process::{ProcessTable, FILE_CREATE, IMAGE_LOAD, REGISTRY_VALUE_SET};
    use super::super::EventEnvelope;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    const LAUNCHER: &str = r"C:\Games\launcher.exe";
    const K2F_CLSID: &str = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}";

    fn none(_: &str) -> Vec<String> {
        Vec::new()
    }

    fn k2f_dll() -> String {
        format!(
            r"C:\Users\u\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\{HEX}\platform_experience_helper.dll"
        )
    }

    fn file(record: u64, time: &str, guid: &str, path: &str) -> EventEnvelope {
        ev(
            FILE_CREATE,
            record,
            time,
            &[("ProcessGuid", guid), ("TargetFilename", path)],
        )
    }

    fn com(record: u64, time: &str, guid: &str, clsid: &str, value: &str) -> EventEnvelope {
        let target = format!(r"HKU\S-1-5-21-1_Classes\CLSID\{clsid}\InprocServer32\(Default)");
        ev(
            REGISTRY_VALUE_SET,
            record,
            time,
            &[
                ("ProcessGuid", guid),
                ("EventType", "SetValue"),
                ("TargetObject", &target),
                ("Details", value),
            ],
        )
    }

    fn load(record: u64, time: &str, guid: &str, path: &str, signed: &str) -> EventEnvelope {
        ev(
            IMAGE_LOAD,
            record,
            time,
            &[
                ("ProcessGuid", guid),
                ("ImageLoaded", path),
                ("Signed", signed),
            ],
        )
    }

    fn ids(events: &[EventEnvelope]) -> Vec<(&'static str, &'static str, &'static str)> {
        let table = ProcessTable::build(events);
        correlate(&table, &none)
            .findings
            .into_iter()
            .filter(|f| f.rule_id.starts_with("AG-B"))
            .map(|f| (f.rule_id, f.verdict, f.confidence))
            .collect()
    }

    // --- P6-04: credential-store reads from Security 4663 audit events ---

    fn security_read(
        record: u64,
        time: &str,
        object: &str,
        process: &str,
        pid: &str,
        mask: &str,
    ) -> EventEnvelope {
        let xml = format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4663</EventID>\
             <TimeCreated SystemTime='{time}'/><EventRecordID>{record}</EventRecordID>\
             <Channel>Security</Channel></System><EventData>\
             <Data Name='SubjectUserName'>someone</Data>\
             <Data Name='ObjectType'>File</Data><Data Name='ObjectName'>{object}</Data>\
             <Data Name='AccessMask'>{mask}</Data><Data Name='ProcessId'>{pid}</Data>\
             <Data Name='ProcessName'>{process}</Data></EventData></Event>"
        );
        super::super::parse_event_xml(&xml, "Security", 0).unwrap()
    }

    const LOGIN_DATA: &str = r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    const STEALER: &str = r"C:\Users\u\AppData\Local\Temp\x.exe";

    fn b004(events: &[EventEnvelope]) -> Vec<(&'static str, &'static str)> {
        let table = ProcessTable::build(events);
        correlate(&table, &none)
            .findings
            .into_iter()
            .filter(|f| f.rule_id == "AG-B004")
            .map(|f| (f.verdict, f.confidence))
            .collect()
    }

    #[test]
    fn credential_read_by_other_program_then_connect_is_review() {
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{S}",
                "4660",
                STEALER,
                "explorer.exe",
            ),
            security_read(
                2,
                "2026-11-05T10:00:05Z",
                LOGIN_DATA,
                STEALER,
                "0x1234",
                "0x1",
            ),
            ev(
                super::super::process::NETWORK_CONNECT,
                3,
                "2026-11-05T10:01:00Z",
                &[
                    ("ProcessGuid", "{S}"),
                    ("DestinationIp", "198.51.100.9"),
                    ("DestinationPort", "443"),
                ],
            ),
        ];
        assert_eq!(b004(&events), vec![("review", "medium")]);
        // The read alone (no outbound contact) is only observed.
        assert_eq!(b004(&events[..2]), vec![("observed", "low")]);
    }

    #[test]
    fn owner_browser_defender_writes_and_other_files_are_not_findings() {
        let chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
        let events = vec![
            security_read(1, "2026-11-05T10:00:00Z", LOGIN_DATA, chrome, "0x10", "0x1"),
            security_read(
                2,
                "2026-11-05T10:00:01Z",
                LOGIN_DATA,
                r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
                "0x11",
                "0x1",
            ),
            // Write-only access is not a read.
            security_read(
                3,
                "2026-11-05T10:00:02Z",
                LOGIN_DATA,
                STEALER,
                "0x12",
                "0x2",
            ),
            // Not a credential store.
            security_read(
                4,
                "2026-11-05T10:00:03Z",
                r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Preferences",
                STEALER,
                "0x13",
                "0x1",
            ),
            // Chrome reading Edge's store is not its own store.
        ];
        assert!(b004(&events).is_empty());
        let cross = vec![security_read(
            5,
            "2026-11-05T10:00:04Z",
            r"C:\Users\u\AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
            chrome,
            "0x10",
            "0x1",
        )];
        assert_eq!(b004(&cross), vec![("observed", "low")]);
    }

    #[test]
    fn without_audit_events_the_rule_is_not_evaluable_and_with_them_it_is() {
        let table = ProcessTable::build(&[]);
        let r = correlate(&table, &none);
        let s = r.rules.iter().find(|r| r.rule_id == "AG-B004").unwrap();
        assert!(!s.evaluable);
        assert_eq!(s.missing_sources, vec!["credential_file_read_audit"]);
        let table = ProcessTable::build(&[security_read(
            1,
            "2026-11-05T10:00:00Z",
            r"C:\x.txt",
            STEALER,
            "0x1",
            "0x1",
        )]);
        let r = correlate(&table, &none);
        assert!(
            r.rules
                .iter()
                .find(|r| r.rule_id == "AG-B004")
                .unwrap()
                .evaluable
        );
        // User names are not kept.
        assert!(!serde_json::to_string(&table).unwrap().contains("someone"));
    }

    fn hijack_chain() -> Vec<EventEnvelope> {
        let dll = k2f_dll();
        vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{L}",
                "10",
                LAUNCHER,
                "explorer.exe",
            ),
            file(2, "2026-11-05T10:00:01Z", "{L}", &dll),
            com(3, "2026-11-05T10:00:02Z", "{L}", K2F_CLSID, &dll),
            create(
                4,
                "2026-11-05T10:05:00Z",
                "{B}",
                "20",
                CHROME,
                "explorer.exe",
            ),
            load(
                5,
                "2026-11-05T10:05:01Z",
                "{B}",
                &dll.to_uppercase(),
                "false",
            ),
        ]
    }

    #[test]
    fn full_hijack_chain_is_correlated_with_high_confidence() {
        let found = ids(&hijack_chain());
        assert!(found.contains(&("AG-B001", "observed", "low")));
        assert!(found.contains(&("AG-B002", "review", "medium")));
        assert!(found.contains(&("AG-B003", "review", "high")));
        assert!(found.contains(&("AG-B005", "review", "high")));
    }

    #[test]
    fn generic_hijack_with_other_names_is_found_without_k2f_rule() {
        let dll = r"C:\Users\u\AppData\Local\Microsoft\Edge\User Data\x\helper.dll";
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{L}",
                "10",
                LAUNCHER,
                "explorer.exe",
            ),
            file(2, "2026-11-05T10:00:01Z", "{L}", dll),
            com(
                3,
                "2026-11-05T10:00:02Z",
                "{L}",
                "{11111111-2222-3333-4444-555555555555}",
                dll,
            ),
            create(
                4,
                "2026-11-05T10:05:00Z",
                "{B}",
                "20",
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                "explorer.exe",
            ),
            load(5, "2026-11-05T10:05:01Z", "{B}", dll, "false"),
        ];
        let found = ids(&events);
        assert!(found.iter().any(|f| f.0 == "AG-B003" && f.2 == "high"));
        assert!(!found.iter().any(|f| f.0 == "AG-B005"));
    }

    #[test]
    fn browser_updates_are_not_hijacks() {
        let dll = r"C:\Users\u\AppData\Local\Google\Chrome\Application\131.0.0.0\chrome_elf.dll";
        let updater =
            r"C:\Users\u\AppData\Local\Google\Chrome\Application\131.0.0.0\Installer\setup.exe";
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{U}",
                "10",
                updater,
                "explorer.exe",
            ),
            file(2, "2026-11-05T10:00:01Z", "{U}", dll),
            com(
                3,
                "2026-11-05T10:00:02Z",
                "{U}",
                "{11111111-2222-3333-4444-555555555555}",
                dll,
            ),
            create(
                4,
                "2026-11-05T10:05:00Z",
                "{B}",
                "20",
                r"C:\Users\u\AppData\Local\Google\Chrome\Application\chrome.exe",
                "explorer.exe",
            ),
            load(5, "2026-11-05T10:05:01Z", "{B}", dll, "true"),
            // The browser writing into its own user data is normal.
            file(
                6,
                "2026-11-05T10:06:00Z",
                "{B}",
                r"C:\Users\u\AppData\Local\Google\Chrome\User Data\WidevineCdm\x.dll",
            ),
        ];
        let found = ids(&events);
        assert!(!found.iter().any(|f| f.1 == "review"), "{found:?}");
        assert!(!found.iter().any(|f| f.0 == "AG-B001"));
    }

    #[test]
    fn same_name_in_another_folder_does_not_chain() {
        let dll = k2f_dll();
        let other = r"C:\Users\u\AppData\Local\Other\platform_experience_helper.dll";
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{L}",
                "10",
                LAUNCHER,
                "explorer.exe",
            ),
            com(
                2,
                "2026-11-05T10:00:02Z",
                "{L}",
                "{11111111-2222-3333-4444-555555555555}",
                other,
            ),
            create(
                3,
                "2026-11-05T10:05:00Z",
                "{B}",
                "20",
                CHROME,
                "explorer.exe",
            ),
            load(4, "2026-11-05T10:05:01Z", "{B}", &dll, "false"),
        ];
        let found = ids(&events);
        assert!(!found.iter().any(|f| f.0 == "AG-B003"));
        // The lone load of the k2f-shaped path is still worth a look.
        assert!(found.contains(&("AG-B005", "review", "medium")));
    }

    #[test]
    fn load_before_registration_is_not_a_chain() {
        let dll = r"C:\Users\u\AppData\Roaming\x\helper.dll";
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{B}",
                "20",
                CHROME,
                "explorer.exe",
            ),
            load(2, "2026-11-05T10:00:01Z", "{B}", dll, "false"),
            create(
                3,
                "2026-11-05T10:30:00Z",
                "{L}",
                "10",
                LAUNCHER,
                "explorer.exe",
            ),
            com(
                4,
                "2026-11-05T10:30:02Z",
                "{L}",
                "{11111111-2222-3333-4444-555555555555}",
                dll,
            ),
        ];
        let found = ids(&events);
        assert!(!found.iter().any(|f| f.0 == "AG-B003"));
        assert!(found.contains(&("AG-B002", "review", "low")));
    }

    #[test]
    fn missing_sources_make_rules_not_evaluable() {
        let events = vec![create(
            1,
            "2026-11-05T10:00:00Z",
            "{L}",
            "10",
            LAUNCHER,
            "explorer.exe",
        )];
        let table = ProcessTable::build(&events);
        let result = correlate(&table, &none);
        let status = |id: &str| result.rules.iter().find(|r| r.rule_id == id).unwrap();
        assert!(!status("AG-B001").evaluable);
        assert!(!status("AG-B003").evaluable);
        assert_eq!(
            status("AG-B003").missing_sources,
            vec![
                "sysmon_file_create",
                "sysmon_registry_value_set",
                "sysmon_image_load"
            ]
        );
        assert!(!status("AG-B004").evaluable);
        assert!(!status("AG-B005").evaluable);
        assert!(result
            .findings
            .iter()
            .all(|f| !f.rule_id.starts_with("AG-B")));
    }

    #[test]
    fn chain_without_file_events_is_medium_and_says_why() {
        let mut events = hijack_chain();
        events.remove(1);
        let table = ProcessTable::build(&events);
        let result = correlate(&table, &none);
        let b003 = result
            .findings
            .iter()
            .find(|f| f.rule_id == "AG-B003")
            .unwrap();
        assert_eq!(b003.confidence, "medium");
        assert_eq!(b003.missing_sources, vec!["sysmon_file_create"]);
    }

    #[test]
    fn replay_is_order_and_duplicate_independent() {
        let events = hijack_chain();
        let mut shuffled: Vec<_> = events.iter().rev().cloned().collect();
        shuffled.extend(events.iter().cloned());
        assert_eq!(ids(&events), ids(&shuffled));
    }

    #[test]
    fn machine_wide_registration_is_not_a_per_user_hijack() {
        let dll = r"C:\Users\u\AppData\Local\x\helper.dll";
        let target = r"HKLM\SOFTWARE\Classes\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32\(Default)";
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{L}",
                "10",
                LAUNCHER,
                "explorer.exe",
            ),
            ev(
                REGISTRY_VALUE_SET,
                2,
                "2026-11-05T10:00:01Z",
                &[
                    ("ProcessGuid", "{L}"),
                    ("EventType", "SetValue"),
                    ("TargetObject", target),
                    ("Details", dll),
                ],
            ),
        ];
        assert!(ids(&events).is_empty());
    }
}
