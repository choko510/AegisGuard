//! Notification decisions and persisted UI settings (P9-04).
//!
//! A finding is notified at most once (keyed by rule, process and first
//! event), only when it is new and not suppressed, and only if the user left
//! notifications on. Settings live in `%APPDATA%\AegisGuard\ui-settings.json`
//! (per user, no secrets).
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

const MAX_REMEMBERED: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UiSettings {
    #[serde(default = "yes")]
    pub notifications: bool,
    /// "system", "light" or "dark".
    #[serde(default = "system")]
    pub theme: String,
}

fn yes() -> bool {
    true
}
fn system() -> String {
    "system".into()
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            notifications: true,
            theme: system(),
        }
    }
}

pub fn settings_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(|a| PathBuf::from(a).join("AegisGuard").join("ui-settings.json"))
}

impl UiSettings {
    pub fn load() -> Self {
        settings_path()
            .and_then(|p| std::fs::read(p).ok())
            .filter(|b| b.len() < 64 * 1024)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = settings_path() else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)
    }
}

/// Remembers which findings were already notified in this session.
#[derive(Default)]
pub struct Notifier {
    seen: BTreeSet<String>,
}

fn key(f: &Value) -> String {
    format!(
        "{}|{}|{}",
        f["rule_id"].as_str().unwrap_or(""),
        f["process_key"].as_str().unwrap_or(""),
        f["event_refs"][0].as_str().unwrap_or("")
    )
}

impl Notifier {
    /// New, unsuppressed `review` findings not notified before.
    pub fn fresh(&mut self, findings: &[Value]) -> Vec<Value> {
        let mut out = Vec::new();
        for f in findings {
            if f["verdict"] != "review" || !f["suppressed_reason"].is_null() {
                continue;
            }
            if self.seen.insert(key(f)) {
                out.push(f.clone());
            }
        }
        while self.seen.len() > MAX_REMEMBERED {
            let first = self.seen.iter().next().cloned();
            if let Some(k) = first {
                self.seen.remove(&k);
            }
        }
        out
    }
}

/// Balloon text for a batch of new findings.
pub fn message(new: &[Value]) -> (String, String) {
    let title = format!("AegisGuard：要確認の所見 {} 件", new.len());
    let rules: Vec<&str> = new
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .take(3)
        .collect();
    let text = format!(
        "{}。確認のための根拠で、悪性の判定ではありません。AegisGuardを開いて詳細を確認してください。",
        rules.join("、")
    );
    (title, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(rule: &str, verdict: &str, suppressed: bool) -> Value {
        serde_json::json!({"rule_id": rule, "process_key": "{P}", "event_refs": ["e1"], "verdict": verdict,
            "suppressed_reason": if suppressed { Value::String("x".into()) } else { Value::Null }})
    }

    #[test]
    fn each_review_finding_is_notified_once() {
        let mut n = Notifier::default();
        let batch = vec![
            f("AG-B003", "review", false),
            f("AG-C003", "observed", false),
            f("AG-B002", "review", true),
        ];
        let fresh = n.fresh(&batch);
        assert_eq!(fresh.len(), 1);
        assert!(n.fresh(&batch).is_empty());
        let (title, text) = message(&fresh);
        assert!(title.contains("1 件"));
        assert!(text.contains("悪性の判定ではありません"));
    }

    #[test]
    fn settings_default_and_parse_leniently() {
        let s: UiSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, UiSettings::default());
        assert!(s.notifications);
    }
}
