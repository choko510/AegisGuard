//! AegisGuard Windows service core (P8): configuration, persisted state and
//! the run loop, independent of how the process was started (SCM or console).
//!
//! The service only observes. It never changes Microsoft Defender, Windows
//! Firewall, Sysmon or any other OS setting, never deletes or quarantines,
//! and never acts on requests to scan arbitrary paths (a normal user must not
//! be able to read files through the service's privileges).
use crate::{model, store, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(windows)]
pub mod scm;

pub const SERVICE_NAME: &str = "AegisGuard";
pub const DISPLAY_NAME: &str = "AegisGuard (read-only monitoring)";
pub const STATE_SCHEMA: u32 = 1;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;

/// Service configuration (`config.json` in the data directory).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Seconds between collection/correlation ticks (5..=3600).
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Event Log channels to collect (read-only).
    #[serde(default = "default_channels")]
    pub channels: Vec<String>,
    /// Upper bound of events read per channel per tick.
    #[serde(default = "default_max_events")]
    pub max_events_per_tick: u64,
    /// Per-channel spool size before rotation.
    #[serde(default = "default_spool_max")]
    pub spool_max_bytes: u64,
    /// Rotated spool generations kept per channel.
    #[serde(default = "default_spool_generations")]
    pub spool_generations: u32,
    /// Collection pauses (cursor not advanced) below this much free disk.
    #[serde(default = "default_min_free")]
    pub min_free_bytes: u64,
}

fn default_interval() -> u64 {
    30
}
fn default_channels() -> Vec<String> {
    vec![
        "Microsoft-Windows-Sysmon/Operational".into(),
        "Microsoft-Windows-Windows Defender/Operational".into(),
    ]
}
fn default_max_events() -> u64 {
    20_000
}
fn default_spool_max() -> u64 {
    64 * 1024 * 1024
}
fn default_spool_generations() -> u32 {
    3
}
fn default_min_free() -> u64 {
    512 * 1024 * 1024
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_interval(),
            channels: default_channels(),
            max_events_per_tick: default_max_events(),
            spool_max_bytes: default_spool_max(),
            spool_generations: default_spool_generations(),
            min_free_bytes: default_min_free(),
        }
    }
}

impl ServiceConfig {
    fn validate(&self) -> std::result::Result<(), String> {
        if !(5..=3600).contains(&self.interval_secs) {
            return Err("interval_secs must be 5..=3600".into());
        }
        if self.channels.is_empty() || self.channels.len() > 16 {
            return Err("channels must list 1..=16 channels".into());
        }
        if self
            .channels
            .iter()
            .any(|c| c.is_empty() || c.len() > 256 || c.contains(['\\', '\0']))
        {
            return Err("invalid channel name".into());
        }
        if !(1..=1_000_000).contains(&self.max_events_per_tick) {
            return Err("max_events_per_tick must be 1..=1000000".into());
        }
        if !(1024 * 1024..=4 * 1024 * 1024 * 1024).contains(&self.spool_max_bytes) {
            return Err("spool_max_bytes must be 1 MiB..=4 GiB".into());
        }
        if self.spool_generations > 20 {
            return Err("spool_generations must be <= 20".into());
        }
        Ok(())
    }

    /// Load `config.json`. A missing file means defaults; an unreadable or
    /// invalid one also means defaults, but the error is returned so it is
    /// recorded in the state instead of being ignored.
    pub fn load(path: &Path) -> (Self, Option<String>) {
        let read = || -> std::result::Result<Option<Self>, String> {
            match std::fs::metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.to_string()),
                Ok(m) if m.len() > MAX_CONFIG_BYTES => return Err("config file too large".into()),
                Ok(_) => {}
            }
            let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
            let config: Self = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            config.validate()?;
            Ok(Some(config))
        };
        match read() {
            Ok(Some(c)) => (c, None),
            Ok(None) => (Self::default(), None),
            Err(e) => (
                Self::default(),
                Some(format!("config.json rejected, defaults in use: {e}")),
            ),
        }
    }
}

/// How the process was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Service,
    Console,
}

/// One channel's last collection result, as written to the state file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelState {
    pub channel: String,
    /// `ok`, `gap`, `degraded`, `paused_low_disk`, `not_collected`.
    pub status: String,
    pub persisted_total: u64,
    pub last_tick_persisted: u64,
    pub gap_detected: bool,
    pub access_error: Option<String>,
    pub last_success_at_unix_ms: Option<u64>,
}

/// Persisted service state; the GUI reads it through IPC (P8-03).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceState {
    pub schema: u32,
    pub mode: RunMode,
    /// `starting`, `running`, `stopping`, `stopped`.
    pub status: String,
    pub pid: u32,
    pub version: String,
    pub started_at_unix_ms: u64,
    pub last_tick_at_unix_ms: Option<u64>,
    pub ticks: u64,
    pub config: ServiceConfig,
    pub config_error: Option<String>,
    pub channels: Vec<ChannelState>,
    /// Problems of the service itself (state not writable, disk low, ...).
    pub problems: Vec<String>,
    pub note: String,
}

impl ServiceState {
    pub fn new(mode: RunMode, config: ServiceConfig, config_error: Option<String>) -> Self {
        Self {
            schema: STATE_SCHEMA,
            mode,
            status: "starting".into(),
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").into(),
            started_at_unix_ms: model::now_unix_ms(),
            last_tick_at_unix_ms: None,
            ticks: 0,
            channels: config
                .channels
                .iter()
                .map(|c| ChannelState {
                    channel: c.clone(),
                    status: "not_collected".into(),
                    persisted_total: 0,
                    last_tick_persisted: 0,
                    gap_detected: false,
                    access_error: None,
                    last_success_at_unix_ms: None,
                })
                .collect(),
            config,
            config_error,
            problems: Vec::new(),
            note: "Observation only: no OS, Defender or Firewall setting is changed. A stopped or stale service means nothing is being monitored.".into(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec(self)?;
        store::store(path, &bytes, |b| {
            serde_json::from_slice::<ServiceState>(b)
                .map(|_| ())
                .map_err(Into::into)
        })
    }

    pub fn load(path: &Path) -> Result<Option<Self>> {
        let parse = |b: &[u8]| -> Result<Self> { Ok(serde_json::from_slice(b)?) };
        Ok(store::load(path, MAX_STATE_BYTES, parse)?.map(|(s, _)| s))
    }

    /// Whether this state is too old to describe a running service.
    pub fn is_stale(&self, now_ms: u64) -> bool {
        let interval = self.config.interval_secs.saturating_mul(1000);
        match self.last_tick_at_unix_ms {
            None => true,
            Some(t) => t > now_ms + 60_000 || now_ms.saturating_sub(t) > interval * 3 + 60_000,
        }
    }
}

/// Work done on every tick (collection and correlation are added by later
/// steps). It must update `state` truthfully and never panic.
pub trait TickWork {
    fn tick(&mut self, state: &mut ServiceState, data_dir: &Path);
}

/// Heartbeat only.
pub struct NoWork;

impl TickWork for NoWork {
    fn tick(&mut self, _state: &mut ServiceState, _data_dir: &Path) {}
}

/// Paths used by the service under its data directory.
pub struct Layout {
    pub data_dir: PathBuf,
}

impl Layout {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }
    pub fn config(&self) -> PathBuf {
        self.data_dir.join("config.json")
    }
    pub fn state(&self) -> PathBuf {
        self.data_dir.join("state.json")
    }
}

/// Default data directory: `%ProgramData%\AegisGuard` for the service.
pub fn default_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data"))
        .join("AegisGuard")
}

/// Run until `stop` is set. The state file is written at start, after every
/// tick and at stop, so a crash leaves at most one interval of staleness,
/// which readers detect with [`ServiceState::is_stale`].
pub fn run(
    layout: &Layout,
    mode: RunMode,
    stop: &AtomicBool,
    work: &mut dyn TickWork,
    on_running: &mut dyn FnMut(),
) -> Result<ServiceState> {
    std::fs::create_dir_all(&layout.data_dir)?;
    let (config, config_error) = ServiceConfig::load(&layout.config());
    let interval = Duration::from_secs(config.interval_secs);
    let mut state = ServiceState::new(mode, config, config_error);
    state.status = "running".into();
    let state_path = layout.state();
    let save = |state: &mut ServiceState| {
        if let Err(e) = state.save(&state_path) {
            let msg = format!("state not saved: {e}");
            if !state.problems.contains(&msg) {
                state.problems.push(msg);
            }
        }
    };
    save(&mut state);
    on_running();
    while !stop.load(Ordering::SeqCst) {
        state.problems.retain(|p| !p.starts_with("state not saved"));
        work.tick(&mut state, &layout.data_dir);
        state.ticks += 1;
        state.last_tick_at_unix_ms = Some(model::now_unix_ms());
        save(&mut state);
        let until = Instant::now() + interval;
        while !stop.load(Ordering::SeqCst) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    state.status = "stopped".into();
    save(&mut state);
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-svc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn missing_config_uses_defaults_and_bad_config_is_reported() {
        let d = dir("config");
        let (c, err) = ServiceConfig::load(&d.join("config.json"));
        assert_eq!(c, ServiceConfig::default());
        assert!(err.is_none());
        for bad in [
            "{not json",
            r#"{"interval_secs": 1}"#,
            r#"{"channels": []}"#,
            r#"{"surprise": true}"#,
            r#"{"channels": ["a\\b"]}"#,
        ] {
            std::fs::write(d.join("config.json"), bad).unwrap();
            let (c, err) = ServiceConfig::load(&d.join("config.json"));
            assert_eq!(c, ServiceConfig::default(), "{bad}");
            assert!(err.unwrap().contains("defaults in use"), "{bad}");
        }
        std::fs::write(d.join("config.json"), r#"{"interval_secs": 60}"#).unwrap();
        assert_eq!(
            ServiceConfig::load(&d.join("config.json")).0.interval_secs,
            60
        );
    }

    struct Counting(u64);
    impl TickWork for Counting {
        fn tick(&mut self, state: &mut ServiceState, _: &Path) {
            self.0 += 1;
            state.channels[0].status = "ok".into();
        }
    }

    #[test]
    fn run_ticks_writes_state_and_stops_cleanly() {
        let d = dir("run");
        std::fs::write(d.join("config.json"), r#"{"interval_secs": 5}"#).unwrap();
        let layout = Layout::new(d.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let mut started = false;
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(600));
            flag.store(true, Ordering::SeqCst);
        });
        let mut work = Counting(0);
        let state = run(&layout, RunMode::Console, &stop, &mut work, &mut || {
            started = true
        })
        .unwrap();
        handle.join().unwrap();
        assert!(started);
        assert_eq!(work.0, 1);
        assert_eq!(state.status, "stopped");
        let saved = ServiceState::load(&layout.state()).unwrap().unwrap();
        assert_eq!(saved.status, "stopped");
        assert_eq!(saved.ticks, 1);
        assert_eq!(saved.channels[0].status, "ok");
        assert_eq!(saved.config.interval_secs, 5);
    }

    #[test]
    fn stale_or_future_state_is_detected() {
        let mut s = ServiceState::new(RunMode::Service, ServiceConfig::default(), None);
        let now = 10_000_000;
        assert!(s.is_stale(now));
        s.last_tick_at_unix_ms = Some(now - 5_000);
        assert!(!s.is_stale(now));
        s.last_tick_at_unix_ms = Some(now - 10 * 60_000);
        assert!(s.is_stale(now));
        s.last_tick_at_unix_ms = Some(now + 10 * 60_000);
        assert!(s.is_stale(now));
    }

    #[test]
    fn corrupt_state_file_is_an_error_not_a_healthy_state() {
        let d = dir("state");
        let layout = Layout::new(d);
        std::fs::write(layout.state(), b"garbage").unwrap();
        assert!(ServiceState::load(&layout.state()).is_err());
    }
}
