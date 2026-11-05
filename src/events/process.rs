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
pub const DNS_QUERY: u32 = 22;
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
    pub accessed_targets: Vec<String>,
    pub event_uids: Vec<String>,
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
                        event_uid: e.event_uid.clone(),
                    });
                } else {
                    record.omitted_contacts += 1;
                }
            }
            IMAGE_LOAD => record.image_loads += 1,
            PROCESS_ACCESS => {
                if let Some(target) = e.field_owned("TargetImage") {
                    if record.accessed_targets.len() < MAX_REFS
                        && !record.accessed_targets.contains(&target)
                    {
                        record.accessed_targets.push(target);
                    }
                }
            }
            _ => {}
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
    fn no_events_means_everything_is_unobserved() {
        let table = ProcessTable::build(&[]);
        assert!(table.processes.is_empty());
        assert_eq!(table.unobserved().len(), 6);
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
