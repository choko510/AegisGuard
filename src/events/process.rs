//! Sysmon process lifetimes keyed by ProcessGuid (never by PID alone, since
//! PIDs are reused). Built offline from spooled envelopes; tolerant of
//! duplicates and out-of-order input, explicit about what was not observed.
use super::{EventEnvelope, SYSMON_PROVIDER};
use crate::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

/// Sysmon event ids this model understands.
pub const PROCESS_CREATE: u32 = 1;
pub const NETWORK_CONNECT: u32 = 3;
pub const PROCESS_TERMINATE: u32 = 5;
pub const IMAGE_LOAD: u32 = 7;
pub const PROCESS_ACCESS: u32 = 10;
pub const FILE_CREATE: u32 = 11;
pub const REGISTRY_OBJECT: u32 = 12;
pub const REGISTRY_VALUE_SET: u32 = 13;
pub const REGISTRY_RENAME: u32 = 14;
pub const DNS_QUERY: u32 = 22;
pub const DEFENDER_PROVIDER: &str = "Microsoft-Windows-Windows Defender";
/// Defender Operational: malware detected / action taken.
pub const DEFENDER_DETECTIONS: [u32; 2] = [1116, 1117];
/// Per-process evidence lists are capped; the rest is only counted.
const MAX_REFS: usize = 64;
const MAX_SPOOL_EVENTS: usize = 2_000_000;
const MAX_LINE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Contact {
    pub at_unix_ms: Option<i64>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub dns_name: Option<String>,
    /// Addresses a DNS query (Sysmon ID 22) answered with, normalized.
    pub resolved_ips: Vec<String>,
    pub event_uid: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ProcessRecord {
    pub process_guid: String,
    pub pid: Option<u32>,
    pub image: Option<String>,
    pub parent_guid: Option<String>,
    pub parent_image: Option<String>,
    pub hashes: Option<String>,
    pub started_at_unix_ms: Option<i64>,
    pub ended_at_unix_ms: Option<i64>,
    /// False when the create event (Sysmon ID 1) was never seen; the process
    /// then only appears through later events and its origin is unknown.
    pub start_observed: bool,
    pub end_observed: bool,
    pub contacts: Vec<Contact>,
    pub omitted_contacts: usize,
    pub image_loads: u64,
    /// Sysmon ID 7 details (capped at MAX_REFS; `image_loads` counts all).
    pub loaded_images: Vec<ImageLoad>,
    pub accesses: Vec<Access>,
    pub created_files: Vec<FileCreate>,
    pub omitted_created_files: usize,
    /// Sysmon ID 12/13/14 changes made by this process (capped).
    pub registry_changes: Vec<RegistryChange>,
    pub omitted_registry_changes: usize,
    pub event_uids: Vec<String>,
}

/// Sysmon ID 7: this process loaded a module.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImageLoad {
    pub path: String,
    /// Lower-case path for joins with file and registry evidence.
    pub path_key: String,
    pub signed: Option<bool>,
    pub signature: Option<String>,
    pub signature_status: Option<String>,
    pub hashes: Option<String>,
    pub at_unix_ms: Option<i64>,
    pub event_uid: String,
}

/// Sysmon ID 12/13/14: a registry change. Values are never stored except a
/// COM server path (`com_value`); other values are only a digest.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RegistryChange {
    /// `create_key`, `delete_key`, `set_value`, `delete_value` or `rename`.
    pub kind: String,
    pub target_object: String,
    pub com: Option<super::ComKey>,
    pub com_value: Option<String>,
    pub details_sha256: Option<String>,
    pub new_name: Option<String>,
    pub at_unix_ms: Option<i64>,
    pub event_uid: String,
}

/// Lower-case, `\\?\`-free, backslash path used to join evidence by path.
pub fn path_key(path: &str) -> String {
    let p = path.trim().trim_matches('"');
    let p = p.strip_prefix(r"\\?\").unwrap_or(p);
    p.replace('/', "\\").to_lowercase()
}

/// Sysmon ID 10: this process opened another process.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Access {
    pub target_image: String,
    pub granted_access: Option<u32>,
    pub at_unix_ms: Option<i64>,
    pub event_uid: String,
}

/// Sysmon ID 11: this process created a file.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FileCreate {
    pub path: String,
    pub path_key: String,
    pub at_unix_ms: Option<i64>,
    pub event_uid: String,
}

/// Microsoft Defender detection (Operational 1116/1117), keyed by file path.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DefenderDetection {
    /// Lower-case path without the `file:_` prefix.
    pub path: String,
    pub threat_name: Option<String>,
    pub at_unix_ms: Option<i64>,
    pub event_uid: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Anomaly {
    pub kind: &'static str,
    pub process_guid: String,
    pub event_uid: String,
}

#[derive(Debug, Default, Serialize)]
pub struct ProcessTable {
    pub processes: BTreeMap<String, ProcessRecord>,
    /// Sysmon event counts per id. Zero for 3/7/22 means "not observed"
    /// (often disabled by configuration), never "no activity".
    pub observed_event_ids: BTreeMap<u32, u64>,
    pub duplicates: u64,
    pub skipped_without_guid: u64,
    pub anomalies: Vec<Anomaly>,
    pub defender_detections: Vec<DefenderDetection>,
    pub observed_defender_event_ids: BTreeMap<u32, u64>,
    #[serde(skip)]
    seen: BTreeSet<String>,
}

impl ProcessTable {
    /// Ingest events in any order; they are sorted by time and record id first.
    pub fn build(events: &[EventEnvelope]) -> Self {
        let mut sorted: Vec<&EventEnvelope> = events
            .iter()
            .filter(|e| e.source == SYSMON_PROVIDER)
            .collect();
        sorted.sort_by_key(|e| {
            (
                e.occurred_at_unix_ms.unwrap_or(i64::MAX),
                e.source_record_id,
            )
        });
        let mut table = Self::default();
        for e in sorted {
            table.ingest(e);
        }
        table.ingest_defender(events);
        table.check_pid_overlaps();
        table
    }

    fn ingest(&mut self, e: &EventEnvelope) {
        if !self.seen.insert(e.event_uid.clone()) {
            self.duplicates += 1;
            return;
        }
        *self.observed_event_ids.entry(e.event_id).or_default() += 1;
        let Some(guid) = e.process_guid.clone() else {
            self.skipped_without_guid += 1;
            return;
        };
        let record = self
            .processes
            .entry(guid.clone())
            .or_insert_with(|| ProcessRecord {
                process_guid: guid.clone(),
                ..Default::default()
            });
        if record.event_uids.len() < MAX_REFS {
            record.event_uids.push(e.event_uid.clone());
        }
        let anomaly = |kind| Anomaly {
            kind,
            process_guid: guid.clone(),
            event_uid: e.event_uid.clone(),
        };
        match e.event_id {
            PROCESS_CREATE => {
                if record.start_observed {
                    self.anomalies.push(anomaly("duplicate_create"));
                    return;
                }
                record.start_observed = true;
                record.pid = e.pid;
                record.image = e.field_owned("Image");
                record.parent_guid = e.parent_guid.clone();
                record.parent_image = e.field_owned("ParentImage");
                record.hashes = e.artifact_hash.clone();
                record.started_at_unix_ms = e
                    .process_start
                    .as_deref()
                    .and_then(super::parse_utc_ms)
                    .or(e.occurred_at_unix_ms);
                // Events attributed before the create was seen indicate clock skew.
                if record.contacts.iter().any(|c| {
                    c.at_unix_ms
                        .zip(record.started_at_unix_ms)
                        .is_some_and(|(at, start)| at < start)
                }) {
                    self.anomalies.push(anomaly("event_before_start"));
                }
            }
            PROCESS_TERMINATE => {
                record.end_observed = true;
                record.ended_at_unix_ms = e.occurred_at_unix_ms;
                record.pid = record.pid.or(e.pid);
                if record.image.is_none() {
                    record.image = e.field_owned("Image");
                }
            }
            NETWORK_CONNECT | DNS_QUERY => {
                let at = e
                    .field_owned("UtcTime")
                    .as_deref()
                    .and_then(super::parse_utc_ms)
                    .or(e.occurred_at_unix_ms);
                if record
                    .ended_at_unix_ms
                    .is_some_and(|end| at.is_some_and(|t| t > end))
                {
                    self.anomalies.push(anomaly("event_after_end"));
                }
                if record.contacts.len() < MAX_REFS {
                    record.contacts.push(Contact {
                        at_unix_ms: at,
                        ip: e.ip.clone(),
                        port: e.port,
                        dns_name: e.dns_name.clone(),
                        resolved_ips: e
                            .field_owned("QueryResults")
                            .map(|r| parse_query_results(&r))
                            .unwrap_or_default(),
                        event_uid: e.event_uid.clone(),
                    });
                } else {
                    record.omitted_contacts += 1;
                }
            }
            IMAGE_LOAD => {
                record.image_loads += 1;
                if let Some(path) = e.field_owned("ImageLoaded") {
                    if record.loaded_images.len() < MAX_REFS {
                        record.loaded_images.push(ImageLoad {
                            path_key: path_key(&path),
                            path,
                            signed: e
                                .field_owned("Signed")
                                .map(|s| s.eq_ignore_ascii_case("true")),
                            signature: e.field_owned("Signature"),
                            signature_status: e.field_owned("SignatureStatus"),
                            hashes: e.artifact_hash.clone(),
                            at_unix_ms: e.occurred_at_unix_ms,
                            event_uid: e.event_uid.clone(),
                        });
                    }
                }
            }
            REGISTRY_OBJECT | REGISTRY_VALUE_SET | REGISTRY_RENAME => {
                let Some(target) = e.field_owned("TargetObject") else {
                    return;
                };
                if record.registry_changes.len() >= MAX_REFS {
                    record.omitted_registry_changes += 1;
                    return;
                }
                let event_type = e.field_owned("EventType").unwrap_or_default();
                let kind = match (e.event_id, event_type.as_str()) {
                    (REGISTRY_OBJECT, "DeleteKey") => "delete_key",
                    (REGISTRY_OBJECT, "DeleteValue") => "delete_value",
                    (REGISTRY_OBJECT, _) => "create_key",
                    (REGISTRY_VALUE_SET, _) => "set_value",
                    _ => "rename",
                };
                record.registry_changes.push(RegistryChange {
                    kind: kind.into(),
                    com: super::com_key(&target),
                    target_object: target,
                    com_value: e.field_owned("Details_com_value"),
                    details_sha256: e.field_owned("Details_sha256"),
                    new_name: e.field_owned("NewName"),
                    at_unix_ms: e.occurred_at_unix_ms,
                    event_uid: e.event_uid.clone(),
                });
            }
            PROCESS_ACCESS => {
                if let Some(target) = e.field_owned("TargetImage") {
                    if record.accesses.len() < MAX_REFS {
                        record.accesses.push(Access {
                            target_image: target,
                            granted_access: e.field_owned("GrantedAccess").and_then(|g| {
                                u32::from_str_radix(g.trim_start_matches("0x"), 16).ok()
                            }),
                            at_unix_ms: e.occurred_at_unix_ms,
                            event_uid: e.event_uid.clone(),
                        });
                    }
                }
            }
            FILE_CREATE => {
                if let Some(path) = e.field_owned("TargetFilename") {
                    if record.created_files.len() < MAX_REFS {
                        record.created_files.push(FileCreate {
                            path_key: path_key(&path),
                            path,
                            at_unix_ms: e.occurred_at_unix_ms,
                            event_uid: e.event_uid.clone(),
                        });
                    } else {
                        record.omitted_created_files += 1;
                    }
                }
            }
            _ => {}
        }
    }

    fn ingest_defender(&mut self, events: &[EventEnvelope]) {
        for e in events
            .iter()
            .filter(|e| e.source == DEFENDER_PROVIDER && DEFENDER_DETECTIONS.contains(&e.event_id))
        {
            if !self.seen.insert(e.event_uid.clone()) {
                self.duplicates += 1;
                continue;
            }
            *self
                .observed_defender_event_ids
                .entry(e.event_id)
                .or_default() += 1;
            let Some(paths) = e.field_owned("Path") else {
                continue;
            };
            for path in paths.split(';').filter(|p| !p.trim().is_empty()) {
                let path = path.trim();
                let path = path
                    .split_once('_')
                    .filter(|(scheme, _)| scheme.ends_with(':'))
                    .map_or(path, |(_, rest)| rest);
                if self.defender_detections.len() < MAX_REFS {
                    self.defender_detections.push(DefenderDetection {
                        path: path.to_ascii_lowercase(),
                        threat_name: e.field_owned("Threat Name"),
                        at_unix_ms: e.occurred_at_unix_ms,
                        event_uid: e.event_uid.clone(),
                    });
                }
            }
        }
    }

    /// Two different GUIDs alive with the same PID at the same time cannot both
    /// be right; flag it instead of guessing which one an event belongs to.
    fn check_pid_overlaps(&mut self) {
        let mut by_pid: BTreeMap<u32, Vec<&ProcessRecord>> = BTreeMap::new();
        for p in self.processes.values().filter(|p| p.start_observed) {
            if let Some(pid) = p.pid {
                by_pid.entry(pid).or_default().push(p);
            }
        }
        let mut found = Vec::new();
        for records in by_pid.values() {
            for (i, a) in records.iter().enumerate() {
                for b in &records[i + 1..] {
                    let overlap = |x: &ProcessRecord, y: &ProcessRecord| {
                        let (Some(xs), Some(ys)) = (x.started_at_unix_ms, y.started_at_unix_ms)
                        else {
                            return false;
                        };
                        let xe = x.ended_at_unix_ms.unwrap_or(i64::MAX);
                        let ye = y.ended_at_unix_ms.unwrap_or(i64::MAX);
                        xs < ye && ys < xe
                    };
                    if overlap(a, b) {
                        found.push(Anomaly {
                            kind: "pid_reused_while_alive",
                            process_guid: b.process_guid.clone(),
                            event_uid: b.event_uids.first().cloned().unwrap_or_default(),
                        });
                    }
                }
            }
        }
        self.anomalies.extend(found);
    }

    /// Event ids that were never seen and whose absence must be read as unknown.
    pub fn unobserved(&self) -> Vec<&'static str> {
        [
            (PROCESS_CREATE, "process_create"),
            (NETWORK_CONNECT, "network_connect"),
            (PROCESS_TERMINATE, "process_terminate"),
            (IMAGE_LOAD, "image_load"),
            (PROCESS_ACCESS, "process_access"),
            (FILE_CREATE, "file_create"),
            (REGISTRY_OBJECT, "registry_object"),
            (REGISTRY_VALUE_SET, "registry_value_set"),
            (DNS_QUERY, "dns_query"),
        ]
        .into_iter()
        .filter(|(id, _)| !self.observed_event_ids.contains_key(id))
        .map(|(_, name)| name)
        .collect()
    }
}

impl EventEnvelope {
    fn field_owned(&self, name: &str) -> Option<String> {
        self.payload_redacted
            .get(name)
            .cloned()
            .filter(|v| !v.is_empty())
    }
}

/// Sysmon `QueryResults` look like `type:  5 cdn.example;::ffff:192.0.2.1;192.0.2.2;`.
pub fn parse_query_results(text: &str) -> Vec<String> {
    text.split(';')
        .filter_map(crate::ioc::normalize_ip)
        .take(MAX_REFS)
        .collect()
}

/// Read and concatenate several spools; bad lines are summed.
pub fn read_spools(paths: &[std::path::PathBuf]) -> Result<(Vec<EventEnvelope>, u64)> {
    let mut events = Vec::new();
    let mut bad = 0;
    for path in paths {
        let (mut more, more_bad) = read_spool(path)?;
        events.append(&mut more);
        bad += more_bad;
        if events.len() > MAX_SPOOL_EVENTS {
            return Err("spools exceed the event limit".into());
        }
    }
    Ok((events, bad))
}

/// Read a spool written by `events collect`. Malformed or oversized lines are
/// counted, not silently skipped.
pub fn read_spool(path: &Path) -> Result<(Vec<EventEnvelope>, u64)> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut bad = 0u64;
    let mut line = String::new();
    loop {
        line.clear();
        let n = (&mut reader)
            .take(MAX_LINE_BYTES + 1)
            .read_line(&mut line)?;
        if n == 0 {
            break;
        }
        if n as u64 > MAX_LINE_BYTES && !line.ends_with('\n') {
            bad += 1;
            // Skip the rest of the oversized line.
            let mut rest = Vec::new();
            reader.read_until(b'\n', &mut rest)?;
            continue;
        }
        match serde_json::from_str::<EventEnvelope>(line.trim_end()) {
            Ok(e) => events.push(e),
            Err(_) => bad += 1,
        }
        if events.len() > MAX_SPOOL_EVENTS {
            return Err("spool exceeds the event limit; split it before replaying".into());
        }
    }
    Ok((events, bad))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixtures::sysmon;
    use super::super::parse_event_xml;
    use super::*;

    pub fn ev(id: u32, record: u64, time: &str, data: &[(&str, &str)]) -> EventEnvelope {
        parse_event_xml(&sysmon(id, record, time, data), "x", 0).unwrap()
    }

    pub fn create(
        record: u64,
        time: &str,
        guid: &str,
        pid: &str,
        image: &str,
        parent: &str,
    ) -> EventEnvelope {
        ev(
            PROCESS_CREATE,
            record,
            time,
            &[
                ("UtcTime", time),
                ("ProcessGuid", guid),
                ("ProcessId", pid),
                ("Image", image),
                ("ParentImage", parent),
            ],
        )
    }

    #[test]
    fn lifetime_is_keyed_by_guid_and_order_independent() {
        let events = vec![
            ev(
                PROCESS_TERMINATE,
                4,
                "2026-11-05T10:00:09Z",
                &[("ProcessGuid", "{A}"), ("ProcessId", "100")],
            ),
            ev(
                NETWORK_CONNECT,
                3,
                "2026-11-05T10:00:05Z",
                &[
                    ("ProcessGuid", "{A}"),
                    ("DestinationIp", "192.0.2.1"),
                    ("DestinationPort", "443"),
                ],
            ),
            create(
                2,
                "2026-11-05T10:00:01Z",
                "{A}",
                "100",
                "C:\\a.exe",
                "C:\\p.exe",
            ),
        ];
        let mut reversed = events.clone();
        reversed.reverse();
        for input in [events, reversed] {
            let table = ProcessTable::build(&input);
            let p = &table.processes["{A}"];
            assert!(p.start_observed && p.end_observed);
            assert_eq!(p.contacts.len(), 1);
            assert!(table.anomalies.is_empty(), "{:?}", table.anomalies);
        }
    }

    #[test]
    fn pid_reuse_does_not_merge_processes() {
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{A}",
                "100",
                "C:\\a.exe",
                "C:\\p.exe",
            ),
            ev(
                PROCESS_TERMINATE,
                2,
                "2026-11-05T10:00:10Z",
                &[("ProcessGuid", "{A}"), ("ProcessId", "100")],
            ),
            create(
                3,
                "2026-11-05T10:00:20Z",
                "{B}",
                "100",
                "C:\\b.exe",
                "C:\\p.exe",
            ),
        ];
        let table = ProcessTable::build(&events);
        assert_eq!(table.processes.len(), 2);
        assert!(table.anomalies.is_empty());
        // Two live processes claiming the same PID is flagged.
        let conflicting = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{A}",
                "100",
                "C:\\a.exe",
                "C:\\p.exe",
            ),
            create(
                2,
                "2026-11-05T10:00:05Z",
                "{B}",
                "100",
                "C:\\b.exe",
                "C:\\p.exe",
            ),
        ];
        let table = ProcessTable::build(&conflicting);
        assert!(table
            .anomalies
            .iter()
            .any(|a| a.kind == "pid_reused_while_alive"));
    }

    #[test]
    fn duplicates_missing_creates_and_skew_are_explicit() {
        let net = ev(
            NETWORK_CONNECT,
            5,
            "2026-11-05T10:00:00Z",
            &[("ProcessGuid", "{C}"), ("DestinationIp", "192.0.2.9")],
        );
        let table = ProcessTable::build(&[net.clone(), net.clone()]);
        assert_eq!(table.duplicates, 1);
        assert!(!table.processes["{C}"].start_observed);
        assert!(table.unobserved().contains(&"process_create"));

        // A network event earlier than the create time (clock skew).
        let skewed = vec![
            ev(
                NETWORK_CONNECT,
                6,
                "2026-11-05T09:59:00Z",
                &[("ProcessGuid", "{D}")],
            ),
            create(
                7,
                "2026-11-05T10:00:00Z",
                "{D}",
                "7",
                "C:\\d.exe",
                "C:\\p.exe",
            ),
        ];
        let table = ProcessTable::build(&skewed);
        assert!(table
            .anomalies
            .iter()
            .any(|a| a.kind == "event_before_start"));
    }

    #[test]
    fn dll_loads_and_com_registry_changes_keep_their_meaning() {
        let dll = r"C:\Users\u\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\ab\platform_experience_helper.dll";
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{L}",
                "10",
                r"C:\Games\launcher.exe",
                "explorer.exe",
            ),
            ev(
                FILE_CREATE,
                2,
                "2026-11-05T10:00:01Z",
                &[("ProcessGuid", "{L}"), ("TargetFilename", dll)],
            ),
            ev(
                REGISTRY_VALUE_SET,
                3,
                "2026-11-05T10:00:02Z",
                &[
                    ("ProcessGuid", "{L}"),
                    ("EventType", "SetValue"),
                    (
                        "TargetObject",
                        r"HKU\S-1-5-21-1_Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32\(Default)",
                    ),
                    ("Details", dll),
                ],
            ),
            ev(
                REGISTRY_OBJECT,
                4,
                "2026-11-05T10:00:02Z",
                &[
                    ("ProcessGuid", "{L}"),
                    ("EventType", "DeleteKey"),
                    ("TargetObject", r"HKU\S-1-5-21-1\Software\Old"),
                ],
            ),
            create(
                5,
                "2026-11-05T10:00:03Z",
                "{B}",
                "20",
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "explorer.exe",
            ),
            ev(
                IMAGE_LOAD,
                6,
                "2026-11-05T10:00:04Z",
                &[
                    ("ProcessGuid", "{B}"),
                    ("ImageLoaded", &dll.to_uppercase()),
                    ("Signed", "false"),
                    ("SignatureStatus", "Unavailable"),
                ],
            ),
        ];
        let table = ProcessTable::build(&events);
        let launcher = &table.processes["{L}"];
        assert_eq!(launcher.created_files[0].path_key, path_key(dll));
        let set = &launcher.registry_changes[0];
        assert_eq!(set.kind, "set_value");
        assert_eq!(
            set.com.as_ref().unwrap().scope,
            crate::events::ComScope::PerUser
        );
        assert_eq!(set.com_value.as_deref(), Some(dll));
        assert_eq!(launcher.registry_changes[1].kind, "delete_key");
        assert!(launcher.registry_changes[1].com.is_none());
        let browser = &table.processes["{B}"];
        assert_eq!(browser.image_loads, 1);
        assert_eq!(browser.loaded_images[0].path_key, path_key(dll));
        assert_eq!(browser.loaded_images[0].signed, Some(false));
        assert!(!table.unobserved().contains(&"image_load"));
        assert!(table.unobserved().contains(&"process_access"));
    }

    #[test]
    fn no_events_means_everything_is_unobserved() {
        let table = ProcessTable::build(&[]);
        assert!(table.processes.is_empty());
        assert_eq!(table.unobserved().len(), 9);
    }

    #[test]
    fn spool_reader_counts_bad_lines() {
        let dir = std::env::temp_dir().join(format!("aegisguard-spool-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.jsonl");
        let good = serde_json::to_string(&create(1, "2026-11-05T10:00:00Z", "{A}", "1", "a", "p"))
            .unwrap();
        std::fs::write(
            &path,
            format!("{good}\nnot json\n{}\n", "x".repeat(300_000)),
        )
        .unwrap();
        let (events, bad) = read_spool(&path).unwrap();
        assert_eq!((events.len(), bad), (1, 2));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
