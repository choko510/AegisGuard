//! Collection loop shared by the Windows Event Log source and test sources.
//!
//! Order per batch: render/normalize → append to the spool → fsync the spool →
//! only then persist the source cursor (two-generation store). A crash between
//! the spool flush and the checkpoint re-reads events on restart (duplicates are
//! allowed and carry the same `event_uid`); nothing is acknowledged before it is
//! durable. Unreadable history (log overwritten, bookmark lost, record ids
//! skipping) is recorded as a gap in `SensorHealth` instead of being ignored.
use super::{parse_event_xml, EventEnvelope};
use crate::{model, store, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_BATCH: usize = 64;
const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024;

pub struct RawEvent {
    pub xml: String,
}

/// Where reading resumed relative to the saved cursor.
#[derive(Debug, PartialEq, Eq)]
pub enum Resume {
    /// No cursor existed; reading starts at the oldest retained event.
    FromOldest,
    /// Reading continues right after the saved cursor.
    AfterCursor,
    /// The saved cursor no longer exists (e.g. log overwritten); reading
    /// restarts at the oldest retained event and a gap is reported.
    CursorLost,
}

pub trait EventSource {
    fn channel(&self) -> &str;
    fn open(&mut self, cursor: Option<&str>) -> Result<Resume>;
    /// Up to `max` events; an empty batch means no more events right now.
    fn next_batch(&mut self, max: usize) -> Result<Vec<RawEvent>>;
    /// Opaque cursor positioned after the last event returned.
    fn cursor(&mut self) -> Result<String>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub channel: String,
    pub cursor: String,
    pub last_record_id: u64,
    pub saved_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Gap {
    pub reason: &'static str,
    pub after_record_id: u64,
    pub next_record_id: Option<u64>,
}

/// SensorHealth for one collection run.
#[derive(Debug, Serialize)]
pub struct SensorHealth {
    pub source: String,
    pub channel_available: bool,
    pub resumed_from: Option<&'static str>,
    pub received: u64,
    pub persisted: u64,
    pub parse_errors: u64,
    pub oversized: u64,
    pub drops: u64,
    pub queue_depth: u64,
    pub durable_cursor: Option<u64>,
    pub gap_detected: bool,
    pub gaps: Vec<Gap>,
    pub access_error: Option<String>,
    pub last_success_at_unix_ms: Option<u64>,
    pub status: &'static str,
}

pub struct Paths {
    pub spool: PathBuf,
    pub checkpoint: PathBuf,
}

fn load_checkpoint(path: &Path) -> Result<Option<Checkpoint>> {
    let parse = |b: &[u8]| -> Result<Checkpoint> { Ok(serde_json::from_slice(b)?) };
    Ok(store::load(path, MAX_CHECKPOINT_BYTES, parse)?.map(|(c, _)| c))
}

fn save_checkpoint(path: &Path, checkpoint: &Checkpoint) -> Result<()> {
    let bytes = serde_json::to_vec(checkpoint)?;
    store::store(path, &bytes, |b| {
        serde_json::from_slice::<Checkpoint>(b)
            .map(|_| ())
            .map_err(Into::into)
    })
}

fn open_spool(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let existed = path.exists();
    let file = OpenOptions::new().append(true).create(true).open(path)?;
    if !existed {
        store::restrict_to_owner(path)?;
    }
    Ok(file)
}

/// Read up to `max_events` new events from `source` into the spool.
pub fn collect(source: &mut dyn EventSource, paths: &Paths, max_events: u64) -> SensorHealth {
    let mut health = SensorHealth {
        source: "windows_event_log".into(),
        channel_available: false,
        resumed_from: None,
        received: 0,
        persisted: 0,
        parse_errors: 0,
        oversized: 0,
        drops: 0,
        queue_depth: 0,
        durable_cursor: None,
        gap_detected: false,
        gaps: Vec::new(),
        access_error: None,
        last_success_at_unix_ms: None,
        status: "ok",
    };
    if let Err(e) = run(source, paths, max_events, &mut health) {
        health.access_error = Some(e.to_string());
        health.status = "degraded";
    }
    if health.gap_detected && health.status == "ok" {
        health.status = "gap";
    }
    health
}

fn run(
    source: &mut dyn EventSource,
    paths: &Paths,
    max_events: u64,
    health: &mut SensorHealth,
) -> Result<()> {
    let checkpoint = load_checkpoint(&paths.checkpoint)?;
    let mut last_record = checkpoint.as_ref().map(|c| c.last_record_id);
    health.durable_cursor = last_record;
    let resume = source.open(checkpoint.as_ref().map(|c| c.cursor.as_str()))?;
    health.channel_available = true;
    health.resumed_from = Some(match resume {
        Resume::FromOldest => "oldest",
        Resume::AfterCursor => "cursor",
        Resume::CursorLost => "oldest_after_cursor_lost",
    });
    if resume == Resume::CursorLost {
        health.gap_detected = true;
        health.gaps.push(Gap {
            reason: "cursor_not_found",
            after_record_id: last_record.unwrap_or(0),
            next_record_id: None,
        });
    }
    let mut spool = open_spool(&paths.spool)?;
    let mut first_after_resume = true;
    while health.received < max_events {
        let want = MAX_BATCH.min((max_events - health.received) as usize);
        let batch = source.next_batch(want)?;
        if batch.is_empty() {
            break;
        }
        let now = model::now_unix_ms();
        let mut lines = Vec::new();
        let mut written = 0u64;
        for raw in &batch {
            health.received += 1;
            let envelope: EventEnvelope = match parse_event_xml(&raw.xml, source.channel(), now) {
                Ok(e) => e,
                Err(e) => {
                    // The event existed but could not be normalized: count it, keep going.
                    health.parse_errors += 1;
                    eprintln!("event parse error: {e}");
                    continue;
                }
            };
            if envelope.completeness == "oversized" {
                health.oversized += 1;
            } else {
                let record = envelope.source_record_id;
                if let Some(previous) = last_record {
                    // Event Log record ids grow by one per channel. A jump means
                    // events were overwritten or skipped; a step back is a reset.
                    let expected = previous + 1;
                    let resumed_duplicate = first_after_resume && record <= previous;
                    if record != expected && !resumed_duplicate {
                        health.gap_detected = true;
                        health.gaps.push(Gap {
                            reason: if record > expected {
                                "record_id_skipped"
                            } else {
                                "record_id_reset"
                            },
                            after_record_id: previous,
                            next_record_id: Some(record),
                        });
                    }
                }
                first_after_resume = false;
                last_record = Some(last_record.map_or(record, |p| p.max(record)));
            }
            lines.extend_from_slice(serde_json::to_string(&envelope)?.as_bytes());
            lines.push(b'\n');
            written += 1;
        }
        spool.write_all(&lines)?;
        spool.sync_all()?;
        health.persisted += written;
        // Only now is the batch durable; advance the cursor.
        let checkpoint = Checkpoint {
            channel: source.channel().to_owned(),
            cursor: source.cursor()?,
            last_record_id: last_record.unwrap_or(0),
            saved_at_unix_ms: model::now_unix_ms(),
        };
        save_checkpoint(&paths.checkpoint, &checkpoint)?;
        health.durable_cursor = last_record;
        health.last_success_at_unix_ms = Some(checkpoint.saved_at_unix_ms);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::fixtures::sysmon;
    use super::*;
    use std::fs;

    /// In-memory channel. The cursor is the index of the next event.
    pub struct FakeSource {
        pub events: Vec<(u64, String)>,
        pub next: usize,
        pub fail_open: bool,
        pub fail_after_batches: Option<usize>,
        pub batches: usize,
        /// Records older than this were "overwritten" and cannot be resumed from.
        pub oldest_retained: u64,
    }

    impl FakeSource {
        pub fn with_records(records: &[u64]) -> Self {
            let events = records
                .iter()
                .map(|r| {
                    (
                        *r,
                        sysmon(1, *r, "2026-11-05T08:40:07Z", &[("ProcessGuid", "{P}")]),
                    )
                })
                .collect();
            Self {
                events,
                next: 0,
                fail_open: false,
                fail_after_batches: None,
                batches: 0,
                oldest_retained: 0,
            }
        }
    }

    impl EventSource for FakeSource {
        fn channel(&self) -> &str {
            "Microsoft-Windows-Sysmon/Operational"
        }
        fn open(&mut self, cursor: Option<&str>) -> Result<Resume> {
            if self.fail_open {
                return Err("access denied".into());
            }
            self.events.retain(|(r, _)| *r >= self.oldest_retained);
            let Some(cursor) = cursor else {
                self.next = 0;
                return Ok(Resume::FromOldest);
            };
            let after: u64 = cursor.parse()?;
            match self.events.iter().position(|(r, _)| *r == after) {
                Some(i) => {
                    self.next = i + 1;
                    Ok(Resume::AfterCursor)
                }
                None => {
                    self.next = 0;
                    Ok(Resume::CursorLost)
                }
            }
        }
        fn next_batch(&mut self, max: usize) -> Result<Vec<RawEvent>> {
            if self.fail_after_batches == Some(self.batches) {
                return Err("subscription failed".into());
            }
            self.batches += 1;
            let end = (self.next + max).min(self.events.len());
            let batch = self.events[self.next..end]
                .iter()
                .map(|(_, xml)| RawEvent { xml: xml.clone() })
                .collect();
            self.next = end;
            Ok(batch)
        }
        fn cursor(&mut self) -> Result<String> {
            Ok(self.events[self.next - 1].0.to_string())
        }
    }

    pub fn temp_paths(name: &str) -> (PathBuf, Paths) {
        let dir =
            std::env::temp_dir().join(format!("aegisguard-evt-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let paths = Paths {
            spool: dir.join("events.jsonl"),
            checkpoint: dir.join("checkpoint.json"),
        };
        (dir, paths)
    }

    fn spooled_records(paths: &Paths) -> Vec<u64> {
        fs::read_to_string(&paths.spool)
            .unwrap_or_default()
            .lines()
            .map(|l| {
                serde_json::from_str::<EventEnvelope>(l)
                    .unwrap()
                    .source_record_id
            })
            .collect()
    }

    #[test]
    fn resumes_after_the_durable_cursor_without_loss() {
        let (dir, paths) = temp_paths("resume");
        let mut source = FakeSource::with_records(&(1..=100).collect::<Vec<_>>());
        let first = collect(&mut source, &paths, 70);
        assert_eq!((first.received, first.status), (70, "ok"));
        let mut source = FakeSource::with_records(&(1..=150).collect::<Vec<_>>());
        let second = collect(&mut source, &paths, 1_000);
        assert_eq!(second.resumed_from, Some("cursor"));
        assert_eq!(second.received, 80);
        assert_eq!(spooled_records(&paths), (1..=150).collect::<Vec<_>>());
        assert!(!second.gap_detected);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failure_before_checkpoint_rereads_instead_of_losing_events() {
        let (dir, paths) = temp_paths("failure");
        let mut source = FakeSource::with_records(&(1..=200).collect::<Vec<_>>());
        source.fail_after_batches = Some(2);
        let health = collect(&mut source, &paths, 1_000);
        assert_eq!(health.status, "degraded");
        assert_eq!(health.durable_cursor, Some(128));
        let mut source = FakeSource::with_records(&(1..=200).collect::<Vec<_>>());
        let health = collect(&mut source, &paths, 1_000);
        assert_eq!(health.status, "ok");
        let records = spooled_records(&paths);
        assert_eq!(records.len(), 200);
        assert_eq!(records, (1..=200).collect::<Vec<_>>());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn crash_between_spool_and_checkpoint_only_duplicates() {
        let (dir, paths) = temp_paths("duplicate");
        let mut source = FakeSource::with_records(&(1..=10).collect::<Vec<_>>());
        collect(&mut source, &paths, 5);
        // Simulate events 6..8 reaching the spool while the checkpoint stayed at 5.
        let extra: String = (6..=8)
            .map(|r| {
                let xml = sysmon(1, r, "2026-11-05T08:40:07Z", &[("ProcessGuid", "{P}")]);
                serde_json::to_string(&parse_event_xml(&xml, "x", 0).unwrap()).unwrap() + "\n"
            })
            .collect();
        fs::OpenOptions::new()
            .append(true)
            .open(&paths.spool)
            .unwrap()
            .write_all(extra.as_bytes())
            .unwrap();
        let mut source = FakeSource::with_records(&(1..=10).collect::<Vec<_>>());
        let health = collect(&mut source, &paths, 100);
        assert!(!health.gap_detected);
        let records = spooled_records(&paths);
        assert_eq!(records.len(), 13);
        let unique: std::collections::BTreeSet<_> = records.into_iter().collect();
        assert_eq!(unique.len(), 10);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn overwritten_history_is_reported_as_a_gap_not_skipped_silently() {
        let (dir, paths) = temp_paths("gap");
        let mut source = FakeSource::with_records(&(1..=10).collect::<Vec<_>>());
        collect(&mut source, &paths, 10);
        // The log wrapped: records 1..=50 are gone, the cursor (10) no longer exists.
        let mut source = FakeSource::with_records(&(1..=80).collect::<Vec<_>>());
        source.oldest_retained = 51;
        let health = collect(&mut source, &paths, 1_000);
        assert_eq!(health.status, "gap");
        assert_eq!(health.resumed_from, Some("oldest_after_cursor_lost"));
        assert!(health.gaps.iter().any(|g| g.reason == "cursor_not_found"));
        assert!(health
            .gaps
            .iter()
            .any(|g| g.reason == "record_id_skipped" && g.next_record_id == Some(51)));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn record_id_jumps_inside_a_read_are_gaps() {
        let (dir, paths) = temp_paths("jump");
        let mut source = FakeSource::with_records(&[1, 2, 3, 7, 8]);
        let health = collect(&mut source, &paths, 100);
        assert_eq!(health.gaps.len(), 1);
        assert_eq!(health.gaps[0].after_record_id, 3);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn access_errors_are_degraded_and_keep_the_cursor() {
        let (dir, paths) = temp_paths("denied");
        let mut source = FakeSource::with_records(&[1, 2, 3]);
        collect(&mut source, &paths, 100);
        let mut denied = FakeSource::with_records(&[1, 2, 3, 4]);
        denied.fail_open = true;
        let health = collect(&mut denied, &paths, 100);
        assert_eq!(health.status, "degraded");
        assert!(!health.channel_available);
        assert!(health.access_error.is_some());
        assert_eq!(
            load_checkpoint(&paths.checkpoint)
                .unwrap()
                .unwrap()
                .last_record_id,
            3
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unparseable_events_are_counted() {
        let (dir, paths) = temp_paths("parse");
        let mut source = FakeSource::with_records(&[1, 2]);
        source.events[1].1 = "<Event><broken".into();
        let health = collect(&mut source, &paths, 100);
        assert_eq!((health.received, health.parse_errors), (2, 1));
        fs::remove_dir_all(dir).unwrap();
    }
}
