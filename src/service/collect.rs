//! Continuous, bounded Event Log collection for the service (P8-02).
//!
//! Each tick reads new events of every configured channel into a per-channel
//! JSONL spool with the existing collector, which advances its bookmark only
//! after the spool is flushed and reports gaps. Polling with bookmarks was
//! kept instead of `EvtSubscribe` push subscriptions: it has the same
//! durability rules, is replayable in tests, and an interrupted subscription
//! cannot silently lose events (the next poll resumes from the durable
//! cursor or reports the gap).
//!
//! Bounds: events per tick, spool size with rotation, and a free-disk floor
//! below which collection pauses without advancing the cursor (events stay
//! in the Event Log until it wraps, which is then reported as a gap).
use super::{ChannelState, ServiceState, TickWork};
use crate::events::collector::{self, EventSource, Paths};
use crate::model;
use std::path::{Path, PathBuf};

/// File-name-safe form of a channel name.
pub fn channel_file_stem(channel: &str) -> String {
    channel
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

pub fn spool_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("spool")
}

pub fn channel_paths(data_dir: &Path, channel: &str) -> Paths {
    let stem = channel_file_stem(channel);
    let dir = spool_dir(data_dir);
    Paths {
        spool: dir.join(format!("{stem}.jsonl")),
        checkpoint: dir.join(format!("{stem}.checkpoint.json")),
    }
}

/// Current spool plus rotated generations, newest first.
pub fn spool_generations(spool: &Path, generations: u32) -> Vec<PathBuf> {
    let mut out = vec![spool.to_path_buf()];
    for i in 1..=generations {
        out.push(rotated(spool, i));
    }
    out.into_iter().filter(|p| p.exists()).collect()
}

fn rotated(spool: &Path, n: u32) -> PathBuf {
    let mut name = spool.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{n}"));
    spool.with_file_name(name)
}

/// Rotate a spool that reached `max_bytes`. Returns false when the spool is
/// full and cannot rotate (no generations allowed).
fn rotate_if_needed(spool: &Path, max_bytes: u64, generations: u32) -> std::io::Result<bool> {
    let size = match std::fs::metadata(spool) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
    };
    if size < max_bytes {
        return Ok(true);
    }
    if generations == 0 {
        return Ok(false);
    }
    let oldest = rotated(spool, generations);
    if oldest.exists() {
        std::fs::remove_file(&oldest)?;
    }
    for i in (1..generations).rev() {
        let from = rotated(spool, i);
        if from.exists() {
            std::fs::rename(&from, rotated(spool, i + 1))?;
        }
    }
    std::fs::rename(spool, rotated(spool, 1))?;
    Ok(true)
}

type SourceFactory = Box<dyn FnMut(&str) -> Box<dyn EventSource> + Send>;
type FreeSpace = Box<dyn Fn(&Path) -> Option<u64> + Send>;

pub struct CollectionWork {
    sources: SourceFactory,
    free_space: FreeSpace,
}

impl CollectionWork {
    pub fn new(sources: SourceFactory, free_space: FreeSpace) -> Self {
        Self {
            sources,
            free_space,
        }
    }

    /// Real Windows Event Log channels.
    #[cfg(windows)]
    pub fn windows() -> Self {
        Self::new(
            Box::new(|channel| {
                Box::new(crate::events::winevt::WinEventSource::new(channel))
                    as Box<dyn EventSource>
            }),
            Box::new(free_space),
        )
    }
}

/// Free bytes available to the caller on the volume of `path`.
#[cfg(windows)]
pub fn free_space(path: &Path) -> Option<u64> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut free: u64 = 0;
    // SAFETY: NUL-terminated path; out pointers are valid or null.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(free)
}

impl TickWork for CollectionWork {
    fn tick(&mut self, state: &mut ServiceState, data_dir: &Path) {
        let config = state.config.clone();
        if let Err(e) = std::fs::create_dir_all(spool_dir(data_dir)) {
            for ch in &mut state.channels {
                ch.status = "degraded".into();
                ch.access_error = Some(format!("spool directory: {e}"));
            }
            return;
        }
        let free = (self.free_space)(data_dir);
        for ch in &mut state.channels {
            ch.last_tick_persisted = 0;
            if free.is_some_and(|f| f < config.min_free_bytes) {
                ch.status = "paused_low_disk".into();
                continue;
            }
            let paths = channel_paths(data_dir, &ch.channel);
            match rotate_if_needed(
                &paths.spool,
                config.spool_max_bytes,
                config.spool_generations,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    ch.status = "paused_spool_full".into();
                    continue;
                }
                Err(e) => {
                    ch.status = "degraded".into();
                    ch.access_error = Some(format!("spool rotation: {e}"));
                    continue;
                }
            }
            let mut source = (self.sources)(&ch.channel);
            let health = collector::collect(source.as_mut(), &paths, config.max_events_per_tick);
            apply(ch, &health);
        }
    }
}

fn apply(ch: &mut ChannelState, health: &collector::SensorHealth) {
    ch.status = match health.access_error.as_deref() {
        // ERROR_EVT_CHANNEL_NOT_FOUND: e.g. Sysmon is not installed.
        Some(e) if e.contains("15007") => "channel_not_found".into(),
        Some(e)
            if e.to_ascii_lowercase().contains("access")
                || e.contains("(5)")
                || e.contains("os error 5") =>
        {
            "access_denied".into()
        }
        _ => health.status.to_string(),
    };
    ch.persisted_total += health.persisted;
    ch.last_tick_persisted = health.persisted;
    ch.gap_detected |= health.gap_detected;
    ch.access_error = health.access_error.clone();
    if health.last_success_at_unix_ms.is_some() {
        ch.last_success_at_unix_ms = health.last_success_at_unix_ms;
    } else if health.status == "ok" && health.persisted == 0 {
        // A successful poll with nothing new is still a success.
        ch.last_success_at_unix_ms = Some(model::now_unix_ms());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::collector::tests::FakeSource;
    use crate::service::{RunMode, ServiceConfig};
    use std::sync::{Arc, Mutex};

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-collect-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn state(config: ServiceConfig) -> ServiceState {
        ServiceState::new(RunMode::Console, config, None)
    }

    fn config() -> ServiceConfig {
        ServiceConfig {
            channels: vec!["Microsoft-Windows-Sysmon/Operational".into()],
            ..ServiceConfig::default()
        }
    }

    /// The fake log grows between ticks like a real channel.
    fn work_over(log: Arc<Mutex<Vec<u64>>>, free: Option<u64>) -> CollectionWork {
        CollectionWork::new(
            Box::new(move |_| {
                Box::new(FakeSource::with_records(&log.lock().unwrap())) as Box<dyn EventSource>
            }),
            Box::new(move |_| free),
        )
    }

    fn lines(path: &Path) -> usize {
        std::fs::read_to_string(path).map_or(0, |t| t.lines().count())
    }

    #[test]
    fn consecutive_ticks_collect_only_new_events() {
        let d = dir("ticks");
        let log = Arc::new(Mutex::new(vec![1, 2, 3]));
        let mut work = work_over(log.clone(), None);
        let mut s = state(config());
        work.tick(&mut s, &d);
        assert_eq!(s.channels[0].status, "ok");
        assert_eq!(s.channels[0].last_tick_persisted, 3);
        log.lock().unwrap().extend([4, 5]);
        work.tick(&mut s, &d);
        assert_eq!(s.channels[0].last_tick_persisted, 2);
        work.tick(&mut s, &d);
        assert_eq!(s.channels[0].last_tick_persisted, 0);
        assert_eq!(s.channels[0].persisted_total, 5);
        assert!(s.channels[0].last_success_at_unix_ms.is_some());
        let paths = channel_paths(&d, &s.channels[0].channel);
        assert_eq!(lines(&paths.spool), 5);
    }

    #[test]
    fn low_disk_pauses_without_advancing_the_cursor() {
        let d = dir("disk");
        let log = Arc::new(Mutex::new(vec![1, 2]));
        let mut s = state(config());
        let mut low = work_over(log.clone(), Some(10));
        low.tick(&mut s, &d);
        assert_eq!(s.channels[0].status, "paused_low_disk");
        let paths = channel_paths(&d, &s.channels[0].channel);
        assert!(!paths.checkpoint.exists());
        // Once space is back nothing was skipped.
        let mut ok = work_over(log, Some(u64::MAX));
        ok.tick(&mut s, &d);
        assert_eq!(s.channels[0].last_tick_persisted, 2);
    }

    #[test]
    fn full_spools_rotate_and_keep_bounded_generations() {
        let d = dir("rotate");
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut cfg = config();
        cfg.spool_max_bytes = 1; // rotate on every tick that finds data
        cfg.spool_generations = 2;
        let mut s = state(cfg);
        let mut work = work_over(log.clone(), None);
        for batch in 0..5u64 {
            log.lock().unwrap().push(batch + 1);
            work.tick(&mut s, &d);
        }
        let paths = channel_paths(&d, &s.channels[0].channel);
        let gens = spool_generations(&paths.spool, 2);
        assert_eq!(gens.len(), 3);
        assert!(!rotated(&paths.spool, 3).exists());
        assert_eq!(s.channels[0].persisted_total, 5);
    }

    #[test]
    fn full_spool_without_generations_pauses() {
        let d = dir("full");
        let log = Arc::new(Mutex::new(vec![1]));
        let mut cfg = config();
        cfg.spool_max_bytes = 1;
        cfg.spool_generations = 0;
        let mut s = state(cfg);
        let mut work = work_over(log.clone(), None);
        work.tick(&mut s, &d);
        log.lock().unwrap().push(2);
        work.tick(&mut s, &d);
        assert_eq!(s.channels[0].status, "paused_spool_full");
    }

    #[test]
    fn access_denied_is_reported_as_such() {
        let d = dir("denied");
        let mut work = CollectionWork::new(
            Box::new(|_| {
                let mut f = FakeSource::with_records(&[1]);
                f.fail_open = true;
                Box::new(f) as Box<dyn EventSource>
            }),
            Box::new(|_| None),
        );
        let mut s = state(config());
        work.tick(&mut s, &d);
        assert_eq!(s.channels[0].status, "access_denied");
        assert!(s.channels[0].last_success_at_unix_ms.is_none());
    }

    #[test]
    fn channel_names_become_safe_file_names() {
        assert_eq!(
            channel_file_stem("Microsoft-Windows-Windows Defender/Operational"),
            "Microsoft_Windows_Windows_Defender_Operational"
        );
    }
}
