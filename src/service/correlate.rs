//! Incremental, bounded correlation for the service (P8-04).
//!
//! Every tick reads only the spool lines appended since the last tick
//! (following rotation), keeps a de-duplicated window of recent events
//! (bounded by age and count), and runs the *same* engine as the offline
//! CLI (`events correlate / iocs / timeline`) over that window. For the same
//! set of events the result is therefore identical to an offline replay;
//! events that left the window (age or count cap) are reported as such.
//! New findings are recorded once for notification (deduplicated).
use super::collect::{channel_paths, spool_generations};
use super::findings::{self, FindingsDoc};
use super::{Layout, ServiceState, TickWork};
use crate::events::{correlate, network, process::ProcessTable, timeline, EventEnvelope};
use crate::{ioc, model};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Events older than this (by occurrence time) leave the window.
pub const WINDOW_MS: i64 = 6 * 3600 * 1000;
/// At most this many events are held; the oldest are dropped first.
pub const MAX_WINDOW_EVENTS: usize = 200_000;
/// At most this many bytes are read from one spool per tick.
const MAX_READ_PER_TICK: u64 = 64 * 1024 * 1024;
const MAX_LINE: usize = 256 * 1024;
const MAX_NOTIFIED: usize = 20_000;

#[derive(Default)]
struct Tail {
    path: PathBuf,
    offset: u64,
}

pub struct CorrelationWork {
    tails: HashMap<String, Tail>,
    window: VecDeque<EventEnvelope>,
    seen: HashSet<String>,
    notified: BTreeSet<String>,
    window_ms: i64,
    max_events: usize,
    dropped_by_count: u64,
    bad_lines: u64,
    c2_cache: Option<PathBuf>,
}

impl CorrelationWork {
    pub fn new(window_ms: i64, max_events: usize) -> Self {
        Self {
            tails: HashMap::new(),
            window: VecDeque::new(),
            seen: HashSet::new(),
            notified: BTreeSet::new(),
            window_ms,
            max_events,
            dropped_by_count: 0,
            bad_lines: 0,
            c2_cache: None,
        }
    }

    /// Use this C2 cache (only fresh indicators count, as offline).
    pub fn with_c2_cache(mut self, path: PathBuf) -> Self {
        self.c2_cache = Some(path);
        self
    }

    fn read_new(&mut self, channel: &str, data_dir: &Path, generations: u32) {
        let spool = channel_paths(data_dir, channel).spool;
        let tail = self.tails.entry(channel.to_string()).or_default();
        if tail.path != spool {
            *tail = Tail {
                path: spool.clone(),
                offset: 0,
            };
        }
        let size = std::fs::metadata(&spool).map_or(0, |m| m.len());
        let mut sources: Vec<(PathBuf, u64)> = Vec::new();
        if size < tail.offset {
            // Rotated since the last tick: finish the previous file (now .1)
            // from where we stopped, then read the new file from the start.
            if let Some(prev) = spool_generations(&spool, generations.max(1)).get(1) {
                sources.push((prev.clone(), tail.offset));
            }
            tail.offset = 0;
        }
        sources.push((spool.clone(), tail.offset));
        let mut events = Vec::new();
        let mut bad = 0;
        let mut new_offset = tail.offset;
        for (i, (path, from)) in sources.iter().enumerate() {
            let last = i + 1 == sources.len();
            match read_from(path, *from) {
                Ok((mut ev, b, end)) => {
                    events.append(&mut ev);
                    bad += b;
                    if last {
                        new_offset = end;
                    }
                }
                Err(_) => bad += 1,
            }
        }
        tail.offset = new_offset;
        self.bad_lines += bad;
        for e in events {
            if self.seen.insert(e.event_uid.clone()) {
                self.window.push_back(e);
            }
        }
    }

    fn trim(&mut self, now_ms: i64) {
        let cutoff = now_ms - self.window_ms;
        let before = self.window.len();
        self.window
            .retain(|e| e.occurred_at_unix_ms.is_none_or(|t| t >= cutoff));
        while self.window.len() > self.max_events {
            self.window.pop_front();
            self.dropped_by_count += 1;
        }
        if self.window.len() != before {
            self.seen = self.window.iter().map(|e| e.event_uid.clone()).collect();
        }
    }

    /// IOC set and a description of its source (or why it is unavailable).
    fn iocs(&self) -> (ioc::IocSet, String) {
        let now = model::now_unix_ms() / 1000;
        match self.c2_cache.as_deref() {
            None => (ioc::IocSet::empty(now), "no C2 cache configured".into()),
            Some(p) if !p.exists() => (
                ioc::IocSet::empty(now),
                format!("no C2 cache at {} (no IP IOC matching)", p.display()),
            ),
            Some(p) => match ioc::IocSet::load(Some(p), None, None, now) {
                Ok(set) => (set, format!("C2 cache {}", p.display())),
                Err(e) => (
                    ioc::IocSet::empty(now),
                    format!("C2 cache unreadable, no IP IOC matching: {e}"),
                ),
            },
        }
    }

    /// Run the engine over the current window and return the document.
    pub fn evaluate(&mut self) -> (FindingsDoc, usize) {
        let events: Vec<EventEnvelope> = self.window.iter().cloned().collect();
        let table = ProcessTable::build(&events);
        let (iocs, ioc_source) = self.iocs();
        let active = |ip: &str| {
            iocs.ip(ip)
                .into_iter()
                .filter(ioc::IocEvidence::active)
                .map(|e| e.source_id)
                .collect()
        };
        let result = correlate::correlate(&table, &active);
        let net = network::attribute(&table, &iocs);
        let timelines = timeline::build(&table, &active);
        let mut new = 0;
        let findings: Vec<serde_json::Value> = result
            .findings
            .iter()
            .map(|f| {
                let key = format!(
                    "{}|{}|{}",
                    f.rule_id,
                    f.process_key,
                    f.event_refs.first().map_or("", String::as_str)
                );
                let fresh = self.notified.insert(key);
                if fresh {
                    new += 1;
                }
                let mut v = serde_json::to_value(f).unwrap_or_default();
                v["new"] = serde_json::Value::Bool(fresh);
                v
            })
            .collect();
        while self.notified.len() > MAX_NOTIFIED {
            let first = self.notified.iter().next().cloned();
            if let Some(k) = first {
                self.notified.remove(&k);
            }
        }
        let oldest = self
            .window
            .iter()
            .filter_map(|e| e.occurred_at_unix_ms)
            .min();
        let newest = self
            .window
            .iter()
            .filter_map(|e| e.occurred_at_unix_ms)
            .max();
        let doc = FindingsDoc {
            schema: 1,
            updated_at_unix_ms: model::now_unix_ms(),
            window: serde_json::json!({
                "events": self.window.len(),
                "oldest_unix_ms": oldest,
                "newest_unix_ms": newest,
                "max_age_ms": self.window_ms,
                "dropped_by_count_cap": self.dropped_by_count,
                "bad_lines": self.bad_lines,
                "unobserved": table.unobserved(),
                "ioc_source": ioc_source,
                "note": "Findings cover only the events in this window; older or dropped events are not evaluated.",
            }),
            rules: result
                .rules
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .collect(),
            findings,
            network: serde_json::to_value(&net).ok(),
            timelines: serde_json::to_value(&timelines).ok(),
            new_findings: new,
        };
        (doc, new)
    }
}

/// Parse JSONL envelopes from `offset` to the current end (bounded). Returns
/// (events, bad lines, offset after the last complete line).
fn read_from(path: &Path, offset: u64) -> std::io::Result<(Vec<EventEnvelope>, u64, u64)> {
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(file.take(MAX_READ_PER_TICK));
    let mut events = Vec::new();
    let mut bad = 0;
    let mut pos = offset;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = (&mut reader)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        if buf.last() != Some(&b'\n') {
            if n > MAX_LINE {
                // Over-long line: skip it entirely.
                bad += 1;
                let mut rest = Vec::new();
                let m = reader.read_until(b'\n', &mut rest)?;
                pos += (n + m) as u64;
                continue;
            }
            // A partial last line is still being written: read it next tick.
            break;
        }
        pos += n as u64;
        match serde_json::from_slice::<EventEnvelope>(&buf) {
            Ok(e) => events.push(e),
            Err(_) => bad += 1,
        }
    }
    Ok((events, bad, pos))
}

impl TickWork for CorrelationWork {
    fn tick(&mut self, state: &mut ServiceState, data_dir: &Path) {
        if self.c2_cache.is_none() {
            // `aegisguard c2 update --cache <data dir>\c2-cache.json`
            self.c2_cache = Some(data_dir.join("c2-cache.json"));
        }
        let generations = state.config.spool_generations;
        let channels: Vec<String> = state.channels.iter().map(|c| c.channel.clone()).collect();
        for channel in &channels {
            self.read_new(channel, data_dir, generations);
        }
        self.trim(model::now_unix_ms() as i64);
        let (doc, _) = self.evaluate();
        let layout = Layout::new(data_dir.to_path_buf());
        state
            .problems
            .retain(|p| !p.starts_with("findings not saved"));
        if let Err(e) = findings::save(&layout, &doc) {
            state.problems.push(format!("findings not saved: {e}"));
        }
    }
}

/// Collection followed by correlation, as one tick.
pub struct Pipeline(pub Vec<Box<dyn TickWork + Send>>);

impl TickWork for Pipeline {
    fn tick(&mut self, state: &mut ServiceState, data_dir: &Path) {
        for w in &mut self.0 {
            w.tick(state, data_dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::process::tests::{create, ev};
    use crate::events::process::NETWORK_CONNECT;
    use crate::service::{RunMode, ServiceConfig};
    use std::io::Write;

    const CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-incr-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("spool")).unwrap();
        d
    }

    fn state() -> ServiceState {
        ServiceState::new(
            RunMode::Console,
            ServiceConfig {
                channels: vec![CHANNEL.into()],
                ..ServiceConfig::default()
            },
            None,
        )
    }

    fn append(d: &Path, events: &[EventEnvelope]) {
        let spool = channel_paths(d, CHANNEL).spool;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(spool)
            .unwrap();
        for e in events {
            writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
        }
    }

    /// Office -> PowerShell -> burst of children: AG-C001 and AG-C003.
    fn scenario() -> Vec<EventEnvelope> {
        let mut events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{O}",
                "10",
                r"C:\Office\WINWORD.EXE",
                r"C:\Windows\explorer.exe",
            ),
            create(
                2,
                "2026-11-05T10:00:05Z",
                "{P}",
                "11",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                r"C:\Office\WINWORD.EXE",
            ),
        ];
        events[1].parent_guid = Some("{O}".into());
        for i in 0..12u64 {
            let mut c = create(
                10 + i,
                &format!("2026-11-05T10:00:{:02}Z", 10 + i),
                &format!("{{C{i}}}"),
                &format!("{}", 100 + i),
                r"C:\Windows\System32\cmd.exe",
                "powershell.exe",
            );
            c.parent_guid = Some("{P}".into());
            events.push(c);
        }
        events.push(ev(
            NETWORK_CONNECT,
            40,
            "2026-11-05T10:00:30Z",
            &[
                ("ProcessGuid", "{P}"),
                ("DestinationIp", "192.0.2.66"),
                ("DestinationPort", "443"),
            ],
        ));
        events
    }

    fn ids(doc: &FindingsDoc) -> Vec<String> {
        let mut v: Vec<String> = doc
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{}|{}",
                    f["rule_id"].as_str().unwrap(),
                    f["process_key"].as_str().unwrap()
                )
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn chunked_ticks_match_the_offline_replay() {
        let events = scenario();
        let offline = correlate::correlate(&ProcessTable::build(&events), &|_| Vec::new());
        let mut expected: Vec<String> = offline
            .findings
            .iter()
            .map(|f| format!("{}|{}", f.rule_id, f.process_key))
            .collect();
        expected.sort();
        assert!(!expected.is_empty());

        let d = dir("chunks");
        let mut work = CorrelationWork::new(i64::MAX / 4, MAX_WINDOW_EVENTS);
        let mut s = state();
        // Deliver out of order, in three chunks, with a duplicate.
        let mut shuffled = events.clone();
        shuffled.reverse();
        append(&d, &shuffled[..5]);
        work.tick(&mut s, &d);
        append(&d, &shuffled[5..]);
        append(&d, &shuffled[..2]);
        work.tick(&mut s, &d);
        let doc = findings::load(&Layout::new(d.clone())).unwrap().unwrap();
        assert_eq!(ids(&doc), expected);
        // A further tick with nothing new reports nothing new.
        work.tick(&mut s, &d);
        let doc = findings::load(&Layout::new(d)).unwrap().unwrap();
        assert_eq!(doc.new_findings, 0);
        assert!(doc.findings.iter().all(|f| f["new"] == false));
    }

    #[test]
    fn rotation_does_not_lose_or_duplicate_events() {
        let d = dir("rotate");
        let events = scenario();
        let mut work = CorrelationWork::new(i64::MAX / 4, MAX_WINDOW_EVENTS);
        let mut s = state();
        append(&d, &events[..8]);
        work.tick(&mut s, &d);
        // Rotate: spool -> spool.1, then more events land in a new spool.
        append(&d, &events[8..10]);
        let spool = channel_paths(&d, CHANNEL).spool;
        let mut rotated = spool.clone().into_os_string();
        rotated.push(".1");
        std::fs::rename(&spool, &rotated).unwrap();
        append(&d, &events[10..]);
        work.tick(&mut s, &d);
        assert_eq!(work.window.len(), events.len());
    }

    #[test]
    fn partial_last_line_waits_and_bad_lines_are_counted() {
        let d = dir("partial");
        let spool = channel_paths(&d, CHANNEL).spool;
        let line = serde_json::to_string(&scenario()[0]).unwrap();
        std::fs::write(&spool, format!("{{broken\n{}", &line[..20])).unwrap();
        let mut work = CorrelationWork::new(i64::MAX / 4, MAX_WINDOW_EVENTS);
        let mut s = state();
        work.tick(&mut s, &d);
        assert_eq!(work.window.len(), 0);
        assert_eq!(work.bad_lines, 1);
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&spool)
            .unwrap();
        writeln!(f, "{}", &line[20..]).unwrap();
        work.tick(&mut s, &d);
        assert_eq!(work.window.len(), 1);
    }

    #[test]
    fn window_is_bounded_by_count_and_reports_drops() {
        let d = dir("cap");
        let mut work = CorrelationWork::new(i64::MAX / 4, 5);
        let mut s = state();
        append(&d, &scenario());
        work.tick(&mut s, &d);
        assert_eq!(work.window.len(), 5);
        let doc = findings::load(&Layout::new(d)).unwrap().unwrap();
        assert!(doc.window["dropped_by_count_cap"].as_u64().unwrap() > 0);
    }

    #[test]
    fn old_events_leave_the_window() {
        let d = dir("age");
        let mut work = CorrelationWork::new(60_000, MAX_WINDOW_EVENTS);
        let mut s = state();
        // The scenario is dated 2026-11-05 10:00; "now" is later than a minute after.
        append(&d, &scenario());
        work.tick(&mut s, &d);
        assert_eq!(work.window.len(), 0);
    }
}
