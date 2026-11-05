//! AegisGuard engine library.
//!
//! The `aegisguard` CLI, the read-only GUI and the future Windows service all
//! use this crate. Front ends get typed results from [`api`] and [`engine`]
//! instead of parsing CLI stdout or starting privileged child processes.
//!
//! Every analyzer here is read-only: it inspects files, event logs and local
//! caches, and never changes Microsoft Defender, Windows Firewall or other
//! OS settings.
pub mod api;
pub mod browser;
pub mod budget;
pub mod c2;
pub mod defender;
pub mod engine;
// Some collector internals only have production callers on Windows.
#[cfg_attr(not(windows), allow(dead_code))]
pub mod events;
pub mod fim;
#[cfg(windows)]
pub mod fimwatch;
pub mod fsafe;
pub mod ioc;
pub mod jsonl;
pub mod model;
pub mod pe;
pub mod policy;
pub mod report;
pub mod rulepack;
pub mod rules;
pub mod scan;
pub mod script;
pub mod store;
#[cfg(feature = "yara")]
pub mod yara;

/// Error type shared by the engine and its front ends.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
/// Result type shared by the engine and its front ends.
pub type Result<T> = std::result::Result<T, Error>;
