//! Live connection to the AegisGuard service over its read-only pipe (P9-01).
//!
//! A background thread polls `status` and `findings` every few seconds while
//! the GUI is open; the UI thread never blocks on the pipe. The connection
//! state is always shown: not running, refused (pipe server is neither a
//! service nor this session), or connected to a service vs a console run.
use crate::data::{Dataset, Document};
use aegisguard::api::DocumentKind;
use serde_json::Value;
use std::sync::mpsc;
use std::time::Duration;

pub const POLL: Duration = Duration::from_secs(5);

// The pipe client only exists on Windows; elsewhere some states are unused.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, PartialEq)]
pub enum Connection {
    /// Not attempted yet.
    Unknown,
    /// Answered by a Session 0 service.
    Service,
    /// Answered by `aegisguard service console` in this session.
    Console,
    /// No pipe: the service is not running (or not installed).
    NotRunning(String),
    /// Something answered that is not trusted, or the request failed.
    Error(String),
}

#[derive(Debug, Clone)]
pub struct Live {
    pub connection: Connection,
    /// `status` result: {"state": ServiceState, "stale": bool}.
    pub status: Option<Value>,
    /// `findings` result, or why it is unavailable.
    pub findings: Option<Value>,
    pub findings_error: Option<String>,
    pub polled_at_unix: u64,
}

impl Default for Live {
    fn default() -> Self {
        Self {
            connection: Connection::Unknown,
            status: None,
            findings: None,
            findings_error: None,
            polled_at_unix: 0,
        }
    }
}

impl Live {
    pub fn stale(&self) -> bool {
        self.status
            .as_ref()
            .is_none_or(|s| s["stale"] != Value::Bool(false))
    }

    pub fn state(&self) -> Option<&Value> {
        self.status.as_ref().map(|s| &s["state"])
    }

    /// Turn live findings into documents the existing views understand.
    pub fn documents(&self) -> Vec<Document> {
        let Some(f) = &self.findings else {
            return Vec::new();
        };
        let now = self.polled_at_unix;
        let path = std::path::PathBuf::from("（サービスのライブ結果）");
        let mut docs = vec![Document {
            path: path.clone(),
            kind: DocumentKind::Correlation,
            value: serde_json::json!({
                "correlation": {"rules": f["rules"], "findings": f["findings"]},
                "unobserved": f["window"]["unobserved"],
            }),
            saved_at_unix: Some(now),
        }];
        if !f["network"].is_null() {
            docs.push(Document {
                path: path.clone(),
                kind: DocumentKind::IocAttribution,
                value: serde_json::json!({"report": f["network"]}),
                saved_at_unix: Some(now),
            });
        }
        if !f["timelines"].is_null() {
            docs.push(Document {
                path,
                kind: DocumentKind::Timeline,
                value: f["timelines"].clone(),
                saved_at_unix: Some(now),
            });
        }
        docs
    }
}

/// Replace previous live documents in the dataset with the latest ones.
pub fn merge_into(data: &mut Dataset, live: &Live) {
    data.documents
        .retain(|d| d.path.to_string_lossy() != "（サービスのライブ結果）");
    data.documents.extend(live.documents());
}

#[cfg(windows)]
fn poll_once() -> Live {
    use aegisguard::service::ipc::{request, ServerIdentity, PIPE_NAME};
    let now = crate::data::now_unix();
    let timeout = Duration::from_secs(3);
    let mut live = Live {
        polled_at_unix: now,
        ..Live::default()
    };
    match request(PIPE_NAME, "status", serde_json::json!({}), timeout) {
        Err(e) => {
            let text = e.to_string();
            live.connection = if text.contains("(os error 2)") || text.contains("os error 2)") {
                Connection::NotRunning(text)
            } else {
                Connection::Error(text)
            };
            return live;
        }
        Ok((response, identity)) => {
            live.connection = match identity {
                ServerIdentity::Service => Connection::Service,
                ServerIdentity::ConsoleSameSession => Connection::Console,
            };
            if response.ok {
                live.status = Some(response.result);
            } else {
                live.connection = Connection::Error(response.error.unwrap_or_default());
                return live;
            }
        }
    }
    match request(
        PIPE_NAME,
        "findings",
        serde_json::json!({"offset": 0, "limit": 500}),
        timeout,
    ) {
        Ok((r, _)) if r.ok && r.result["available"] == Value::Bool(true) => {
            live.findings = Some(r.result)
        }
        Ok((r, _)) if r.ok => {
            live.findings_error = Some("サービスはまだ相関結果を書いていません".into())
        }
        Ok((r, _)) => live.findings_error = r.error,
        Err(e) => live.findings_error = Some(e.to_string()),
    }
    live
}

#[cfg(not(windows))]
fn poll_once() -> Live {
    Live {
        connection: Connection::NotRunning("the service only exists on Windows".into()),
        polled_at_unix: crate::data::now_unix(),
        ..Live::default()
    }
}

/// Start polling in the background; each result is sent and a repaint is
/// requested. The thread ends when the receiver is dropped.
pub fn start(repaint: impl Fn() + Send + 'static) -> mpsc::Receiver<Live> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || loop {
        if tx.send(poll_once()).is_err() {
            break;
        }
        repaint();
        std::thread::sleep(POLL);
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Live {
        Live {
            connection: Connection::Service,
            status: Some(serde_json::json!({"stale": false, "state": {"status": "running"}})),
            findings: Some(serde_json::json!({
                "rules": [{"rule_id": "AG-B003", "evaluable": true}],
                "findings": [{"rule_id": "AG-B003", "verdict": "review", "suppressed_reason": null}],
                "window": {"unobserved": ["dns_query"]},
                "network": {"findings": [], "visibility": ["dns_over_https"]},
                "timelines": {"timelines": [], "omitted": 0},
            })),
            findings_error: None,
            polled_at_unix: 100,
        }
    }

    #[test]
    fn live_results_become_documents_and_replace_older_ones() {
        let mut data = Dataset::default();
        merge_into(&mut data, &sample());
        merge_into(&mut data, &sample());
        assert_eq!(data.documents.len(), 3);
        let kinds: Vec<DocumentKind> = data.documents.iter().map(|d| d.kind).collect();
        assert!(kinds.contains(&DocumentKind::Correlation));
        assert!(kinds.contains(&DocumentKind::IocAttribution));
        assert!(kinds.contains(&DocumentKind::Timeline));
        merge_into(&mut data, &Live::default());
        assert!(data.documents.is_empty());
    }

    #[test]
    fn missing_or_stale_status_is_stale() {
        assert!(Live::default().stale());
        assert!(!sample().stale());
        let mut s = sample();
        s.status = Some(serde_json::json!({"stale": true}));
        assert!(s.stale());
    }
}
