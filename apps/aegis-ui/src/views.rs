//! Pure view models: loaded data -> status rows. Kept free of egui so the
//! "never claim more than the data shows" rules can be unit tested.
use crate::data::{now_unix, Dataset, STALE_AFTER_SECS};
use crate::live::{Connection, Live};
use crate::status::Status;
use aegisguard::api::{Assessment, DocumentKind, SignalLevel};
use serde_json::Value;

pub struct StatusRow {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

fn row(name: impl Into<String>, status: Status, detail: impl Into<String>) -> StatusRow {
    StatusRow {
        name: name.into(),
        status,
        detail: detail.into(),
    }
}

/// Age classification of a saved time.
pub fn age_status(saved: Option<u64>, now: u64) -> (Status, String) {
    match saved {
        None => (Status::NoData, "保存時刻が不明です".into()),
        Some(t) if t > now + 300 => (
            Status::Stale,
            "保存時刻が未来です（時計のずれ）。新しい情報として扱いません".into(),
        ),
        Some(t) if now - t > STALE_AFTER_SECS => (
            Status::Stale,
            format!("{} 日前の結果です", (now - t) / 86_400),
        ),
        Some(t) => (
            Status::Observed,
            format!("{} 時間前に保存", (now - t) / 3600),
        ),
    }
}

fn control_state<'a>(audit: &'a Value, name: &str) -> Option<&'a str> {
    audit["controls"]
        .as_array()?
        .iter()
        .find(|c| c["name"] == name)?["state"]
        .as_str()
}

pub fn defender_row(data: &Dataset, now: u64) -> StatusRow {
    let Some(doc) = data.latest(DocumentKind::DefenderAudit) else {
        return row(
            "Microsoft Defender",
            Status::NoData,
            "`aegisguard defender audit > defender.json` の結果を読み込むと表示します。Defenderの代わりにはなりません。",
        );
    };
    let (age, age_text) = age_status(doc.saved_at_unix, now);
    if doc.value["available"] != Value::Bool(true) {
        return row(
            "Microsoft Defender",
            Status::NoData,
            format!("状態を読み取れませんでした（不明）。{age_text}"),
        );
    }
    let rtp = control_state(&doc.value, "real_time_protection").unwrap_or("unknown");
    let status = match (rtp, age) {
        (_, Status::Stale) => Status::Stale,
        ("enabled", _) => Status::Running,
        ("disabled", _) => Status::Stopped,
        _ => Status::Incomplete,
    };
    let management = doc.value["management"].as_str().unwrap_or("unknown");
    row(
        "Microsoft Defender",
        status,
        format!("リアルタイム保護: {rtp}（Defenderの自己申告）。管理: {management}。{age_text}"),
    )
}

pub fn sensor_row(data: &Dataset, now: u64) -> StatusRow {
    let name = "センサー（Sysmon / イベントログ）";
    if let Some(doc) = data.latest(DocumentKind::SensorHealth) {
        let (age, age_text) = age_status(doc.saved_at_unix, now);
        let st = doc.value["status"].as_str().unwrap_or("unknown");
        let persisted = doc.value["persisted"].as_u64().unwrap_or(0);
        let status = match (st, age) {
            (_, Status::Stale) => Status::Stale,
            ("ok", _) => Status::Observed,
            _ => Status::Incomplete,
        };
        let gap = if doc.value["gap_detected"] == Value::Bool(true) {
            "欠損あり。"
        } else {
            ""
        };
        return row(
            name,
            status,
            format!("前回の収集: {st}、{persisted} 件保存。{gap}{age_text}"),
        );
    }
    if let Some(doc) = data.latest(DocumentKind::Correlation) {
        let unobserved: Vec<&str> = doc.value["unobserved"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        return row(
            name,
            if unobserved.is_empty() {
                Status::Observed
            } else {
                Status::Incomplete
            },
            if unobserved.is_empty() {
                "相関結果の範囲では全種類のイベントが観測されています。".to_string()
            } else {
                format!(
                    "観測されていないイベント: {}（活動が無いという意味ではありません）",
                    unobserved.join(", ")
                )
            },
        );
    }
    row(
        name,
        Status::NoData,
        "収集結果が無いため、どのイベントが見えているか不明です。",
    )
}

pub struct ScanCounts {
    pub total: usize,
    pub high: usize,
    pub review: usize,
    pub incomplete: usize,
    pub not_assessed: usize,
    pub nothing_found: usize,
    pub stopped_runs: usize,
}

pub fn scan_counts(data: &Dataset) -> ScanCounts {
    let mut c = ScanCounts {
        total: 0,
        high: 0,
        review: 0,
        incomplete: 0,
        not_assessed: 0,
        nothing_found: 0,
        stopped_runs: 0,
    };
    for r in &data.scans {
        if r.is_scan_stopped() {
            c.stopped_runs += 1;
            continue;
        }
        c.total += 1;
        match r.signal_level() {
            SignalLevel::High => c.high += 1,
            SignalLevel::Review => c.review += 1,
            _ => {}
        }
        match r.assessment() {
            Assessment::Incomplete => c.incomplete += 1,
            Assessment::NotAssessed | Assessment::Unknown => c.not_assessed += 1,
            Assessment::Analyzed => {}
        }
        if r.nothing_found() {
            c.nothing_found += 1;
        }
    }
    c
}

fn review_findings(data: &Dataset) -> usize {
    data.documents
        .iter()
        .filter(|d| d.kind == DocumentKind::Correlation)
        .filter_map(|d| d.value["correlation"]["findings"].as_array())
        .flatten()
        .filter(|f| f["verdict"] == "review" && f["suppressed_reason"].is_null())
        .count()
}

/// The service's own state, as seen over IPC (P9-01).
pub fn service_row(live: &Live) -> StatusRow {
    let name = "AegisGuard 常駐監視";
    match &live.connection {
        Connection::Unknown => row(name, Status::NoData, "サービスへの接続を確認中です。"),
        Connection::NotRunning(_) => row(
            name,
            Status::Stopped,
            "サービスに接続できません（停止中または未登録）。現在は常駐監視していません。`aegisguard service install` は管理者が実行します。",
        ),
        Connection::Error(e) => row(
            name,
            Status::Incomplete,
            format!("サービスの状態を確認できません：{e}"),
        ),
        Connection::Service | Connection::Console => {
            let console = live.connection == Connection::Console;
            let state = live.state();
            let ticks = state.and_then(|s| s["ticks"].as_u64()).unwrap_or(0);
            let problems: Vec<&str> = state
                .and_then(|s| s["problems"].as_array())
                .map(|p| p.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let status = if live.stale() {
                Status::Stale
            } else if !problems.is_empty() {
                Status::Incomplete
            } else {
                Status::Running
            };
            let mode = if console {
                "コンソール実行（サービスではありません。このウィンドウやコマンドを閉じると止まります）"
            } else {
                "Windowsサービス（このGUIを閉じても監視は続きます）"
            };
            let stale = if live.stale() {
                "最終更新が古く、停止している可能性があります。"
            } else {
                ""
            };
            row(
                name,
                status,
                format!(
                    "{mode}。処理回数 {ticks}。{stale}{}",
                    if problems.is_empty() {
                        String::new()
                    } else {
                        format!("問題：{}", problems.join(" / "))
                    }
                ),
            )
        }
    }
}

/// Per-channel collection rows from the live service state.
pub fn channel_rows(live: &Live) -> Vec<StatusRow> {
    let Some(channels) = live.state().and_then(|s| s["channels"].as_array()) else {
        return Vec::new();
    };
    channels
        .iter()
        .map(|c| {
            let st = c["status"].as_str().unwrap_or("unknown");
            let status = match st {
                _ if live.stale() => Status::Stale,
                "ok" => Status::Observed,
                "not_collected" => Status::NoData,
                _ => Status::Incomplete,
            };
            let reason = match st {
                "ok" => "収集できています".to_string(),
                "gap" => "ログの一部が失われました（gap）".into(),
                "access_denied" => {
                    "読み取り権限がありません（Event Log Readers または LocalSystem が必要）".into()
                }
                "channel_not_found" => "チャネルがありません（例：Sysmon 未導入）".into(),
                "paused_low_disk" => {
                    "空き容量不足のため一時停止中（取りこぼしはログ側に残ります）".into()
                }
                "paused_spool_full" => "スプールが満杯のため一時停止中".into(),
                "not_collected" => "まだ収集していません".into(),
                other => format!("状態：{other}"),
            };
            row(
                c["channel"].as_str().unwrap_or("?").to_string(),
                status,
                format!(
                    "{reason}。累計 {} 件、直近 {} 件。{}",
                    c["persisted_total"].as_u64().unwrap_or(0),
                    c["last_tick_persisted"].as_u64().unwrap_or(0),
                    c["access_error"]
                        .as_str()
                        .map(|e| format!("詳細：{e}"))
                        .unwrap_or_default()
                ),
            )
        })
        .collect()
}

pub fn home_rows(data: &Dataset, live: &Live, now: u64) -> Vec<StatusRow> {
    let counts = scan_counts(data);
    let findings = review_findings(data);
    let partial_files = data.scan_files.iter().filter(|f| !f.complete()).count();
    let (updated, updated_text) = if data.is_empty() {
        (Status::NoData, "読み込んだ結果がありません。".to_string())
    } else {
        age_status(data.last_saved(), now)
    };
    let attention = counts.high + counts.review + findings;
    let unknown = counts.incomplete + counts.not_assessed + counts.stopped_runs + partial_files;
    let attention_status = if data.is_empty() {
        Status::NoData
    } else if counts.high > 0 {
        Status::High
    } else if attention > 0 {
        Status::Review
    } else if unknown > 0 {
        Status::Incomplete
    } else {
        Status::NothingFound
    };
    vec![
        defender_row(data, now),
        service_row(live),
        sensor_row(data, now),
        row("最終更新", updated, updated_text),
        row(
            "要確認の件数",
            attention_status,
            if data.is_empty() {
                "結果が無いことは「問題が無い」ことを意味しません。".to_string()
            } else {
                format!(
                    "強い兆候 {} 件・要確認 {} 件（スキャン）、相関の要確認 {} 件。未検査・一部未検査 {} 件、停止した走査 {} 回、読み取りに問題のあったファイル {} 件。",
                    counts.high, counts.review, findings, counts.incomplete + counts.not_assessed, counts.stopped_runs, partial_files
                )
            },
        ),
    ]
}

pub fn browser_rows(data: &Dataset, now: u64) -> Vec<StatusRow> {
    let k2f = match data.latest(DocumentKind::BrowserCheck) {
        None => row(
            "Chrome：k2f既知痕跡",
            Status::NoData,
            "`aegisguard browser k2f > k2f.json` の結果を読み込むと表示します。",
        ),
        Some(doc) => {
            let (age, age_text) = age_status(doc.saved_at_unix, now);
            let verdict = doc.value["verdict"].as_str().unwrap_or("unknown");
            let status = match verdict {
                _ if age == Status::Stale => Status::Stale,
                "correlated_suspicion" => Status::High,
                "indicator_present" => Status::Review,
                "not_observed" => Status::NothingFound,
                _ => Status::Incomplete,
            };
            let missing = doc.value["not_assessed"].as_array().map_or(0, Vec::len);
            row(
                "Chrome：k2f既知痕跡",
                status,
                format!("判定: {verdict}。未検査の項目 {missing} 件（他ユーザー・署名など）。{age_text}"),
            )
        }
    };
    let rules = match data.latest(DocumentKind::Correlation) {
        None => row(
            "DLL・COM乗っ取りの相関（AG-B001〜005）",
            Status::NoData,
            "`events correlate` の結果を読み込むと表示します。Sysmon ID 7/11/13 が必要です。",
        ),
        Some(doc) => {
            let rules: Vec<&Value> = doc.value["correlation"]["rules"]
                .as_array()
                .map(|r| {
                    r.iter()
                        .filter(|r| {
                            r["rule_id"]
                                .as_str()
                                .is_some_and(|id| id.starts_with("AG-B"))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let not_evaluable = rules
                .iter()
                .filter(|r| r["evaluable"] != Value::Bool(true))
                .count();
            let findings: Vec<&Value> = doc.value["correlation"]["findings"]
                .as_array()
                .map(|f| {
                    f.iter()
                        .filter(|f| {
                            f["rule_id"]
                                .as_str()
                                .is_some_and(|id| id.starts_with("AG-B"))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let review = findings.iter().filter(|f| f["verdict"] == "review").count();
            let status = if rules.is_empty() {
                Status::NoData
            } else if review > 0 {
                Status::Review
            } else if !findings.is_empty() {
                Status::Observed
            } else if not_evaluable > 0 {
                Status::Incomplete
            } else {
                Status::NothingFound
            };
            row(
                "DLL・COM乗っ取りの相関（AG-B001〜005）",
                status,
                format!(
                    "所見 {} 件（要確認 {review} 件）。評価できなかったルール {not_evaluable} / {} 件。",
                    findings.len(),
                    rules.len()
                ),
            )
        }
    };
    vec![
        k2f,
        rules,
        row(
            "認証情報ファイルの読み取り",
            Status::NotAvailable,
            "読み取り監査（P6-04）は未実装です。FIMでは読み取りは見えません。",
        ),
        row(
            "Edge / Brave / Firefox 固有の確認",
            Status::NotAvailable,
            "ブラウザー別の確認（P6-05）は未実装です。",
        ),
    ]
}

pub fn network_rows(data: &Dataset, now: u64) -> Vec<StatusRow> {
    let c2 = match data.latest(DocumentKind::C2Status) {
        None => row(
            "C2 IOCキャッシュ",
            Status::NoData,
            "`aegisguard c2 status > c2.json` の結果を読み込むと鮮度を表示します。",
        ),
        Some(doc) => {
            let stale = doc.value["stale"] != Value::Bool(false);
            let (age, age_text) = age_status(doc.saved_at_unix, now);
            row(
                "C2 IOCキャッシュ",
                if stale || age == Status::Stale {
                    Status::Stale
                } else {
                    Status::Observed
                },
                format!(
                    "指標 {} 件。{}{}",
                    doc.value["indicators"].as_u64().unwrap_or(0),
                    if stale {
                        "古いフィードがあります（古い指標は照合に使いません）。"
                    } else {
                        ""
                    },
                    age_text
                ),
            )
        }
    };
    let iocs = match data.latest(DocumentKind::IocAttribution) {
        None => row(
            "IOCとプロセスの帰属",
            Status::NoData,
            "`events iocs` の結果を読み込むと表示します。",
        ),
        Some(doc) => {
            let findings = doc.value["report"]["findings"]
                .as_array()
                .map_or(0, Vec::len);
            let invisible: Vec<String> = doc.value["report"]["visibility"]
                .as_array()
                .map(|v| {
                    v.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            row(
                "IOCとプロセスの帰属",
                if findings > 0 {
                    Status::Review
                } else {
                    Status::Incomplete
                },
                format!(
                    "一致 {findings} 件。見えていないもの: {}",
                    if invisible.is_empty() {
                        "記録なし".into()
                    } else {
                        invisible.join(", ")
                    }
                ),
            )
        }
    };
    vec![
        c2,
        iocs,
        row(
            "通信のライブ監査",
            Status::NotAvailable,
            "常駐サービス（P8）の後に対応します。",
        ),
    ]
}

pub fn rules_row(data: &Dataset, now: u64) -> StatusRow {
    match data.latest(DocumentKind::RulePack) {
        None => row(
            "ルールパック",
            Status::NoData,
            "`aegisguard rules status --trusted-key ... > rules.json` の結果を読み込むと表示します。",
        ),
        Some(doc) => {
            let expires = doc.value["expires_at_unix"].as_u64().unwrap_or(0);
            let status = if expires <= now {
                Status::Stale
            } else if doc.value["generation"] == "current" {
                Status::Observed
            } else {
                Status::Incomplete
            };
            row(
                "ルールパック",
                status,
                format!(
                    "状態: {}、世代: {}、連番: {}、{}",
                    doc.value["status"].as_str().unwrap_or("?"),
                    doc.value["generation"].as_str().unwrap_or("?"),
                    doc.value["sequence"],
                    if expires <= now { "期限切れ" } else { "期限内" }
                ),
            )
        }
    }
}

pub fn now() -> u64 {
    now_unix()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Document;
    use std::path::PathBuf;

    fn doc(kind: DocumentKind, value: Value, saved: u64) -> Document {
        Document {
            path: PathBuf::from(format!("{kind:?}.json")),
            kind,
            value,
            saved_at_unix: Some(saved),
        }
    }

    const NOW: u64 = 2_000_000_000;

    #[test]
    fn empty_dataset_claims_nothing() {
        let rows = home_rows(&Dataset::default(), &Live::default(), NOW);
        assert!(rows
            .iter()
            .all(|r| matches!(r.status, Status::NoData | Status::NotAvailable)));
    }

    #[test]
    fn service_row_never_claims_monitoring_without_a_fresh_service() {
        let mut live = Live::default();
        assert_eq!(service_row(&live).status, Status::NoData);
        live.connection = Connection::NotRunning("x".into());
        assert_eq!(service_row(&live).status, Status::Stopped);
        live.connection = Connection::Service;
        live.status =
            Some(serde_json::json!({"stale": true, "state": {"ticks": 3, "problems": []}}));
        assert_eq!(service_row(&live).status, Status::Stale);
        live.status = Some(
            serde_json::json!({"stale": false, "state": {"ticks": 3, "problems": ["ipc: x"]}}),
        );
        assert_eq!(service_row(&live).status, Status::Incomplete);
        live.status = Some(
            serde_json::json!({"stale": false, "state": {"ticks": 3, "problems": [], "channels": [
            {"channel": "Sysmon", "status": "channel_not_found"},
            {"channel": "Defender", "status": "ok", "persisted_total": 5}]}}),
        );
        assert_eq!(service_row(&live).status, Status::Running);
        assert!(service_row(&live).detail.contains("GUIを閉じても"));
        live.connection = Connection::Console;
        assert!(service_row(&live).detail.contains("サービスではありません"));
        let ch = channel_rows(&live);
        assert_eq!(ch[0].status, Status::Incomplete);
        assert!(ch[0].detail.contains("Sysmon 未導入"));
        assert_eq!(ch[1].status, Status::Observed);
    }

    #[test]
    fn unreadable_or_stale_defender_is_not_running() {
        let mut d = Dataset::default();
        d.documents.push(doc(
            DocumentKind::DefenderAudit,
            serde_json::json!({"available": false, "controls": []}),
            NOW,
        ));
        assert_eq!(defender_row(&d, NOW).status, Status::NoData);
        d.documents[0] = doc(
            DocumentKind::DefenderAudit,
            serde_json::json!({"available": true, "controls": [{"name": "real_time_protection", "state": "enabled"}]}),
            NOW - 30 * 86_400,
        );
        assert_eq!(defender_row(&d, NOW).status, Status::Stale);
        d.documents[0].saved_at_unix = Some(NOW + 86_400);
        assert_eq!(defender_row(&d, NOW).status, Status::Stale);
        d.documents[0].saved_at_unix = Some(NOW - 60);
        assert_eq!(defender_row(&d, NOW).status, Status::Running);
    }

    #[test]
    fn incomplete_scans_are_not_nothing_found() {
        let mut d = Dataset::default();
        let rec = |risk: &str, assessment: &str, level: &str| {
            serde_json::from_value(serde_json::json!({
                "path": "x", "kind": "script", "status": "x", "risk": risk,
                "analysis_complete": assessment == "analyzed",
                "assessment": assessment, "signal_level": level
            }))
            .unwrap()
        };
        d.scans.push(rec("incomplete", "incomplete", "low_signal"));
        d.scan_files.push(crate::data::ScanFileSummary {
            path: "s".into(),
            records: 1,
            problems: 0,
            newer_schema: 0,
            truncated: None,
            saved_at_unix: Some(NOW),
        });
        let rows = home_rows(&d, &Live::default(), NOW);
        assert_eq!(rows[4].status, Status::Incomplete);
        d.scans.push(rec("review", "analyzed", "review"));
        assert_eq!(
            home_rows(&d, &Live::default(), NOW)[4].status,
            Status::Review
        );
        let c = scan_counts(&d);
        assert_eq!(
            (c.total, c.review, c.incomplete, c.nothing_found),
            (2, 1, 1, 0)
        );
    }

    #[test]
    fn missing_sysmon_sources_are_shown_as_unknown() {
        let mut d = Dataset::default();
        d.documents.push(doc(
            DocumentKind::Correlation,
            serde_json::json!({"unobserved": ["image_load"], "correlation": {"rules": [], "findings": []}}),
            NOW,
        ));
        let r = sensor_row(&d, NOW);
        assert_eq!(r.status, Status::Incomplete);
        assert!(r.detail.contains("image_load"));
    }

    #[test]
    fn browser_rules_not_evaluable_are_incomplete() {
        let mut d = Dataset::default();
        d.documents.push(doc(
            DocumentKind::Correlation,
            serde_json::json!({"correlation": {"rules": [{"rule_id": "AG-B003", "evaluable": false}], "findings": []}}),
            NOW,
        ));
        assert_eq!(browser_rows(&d, NOW)[1].status, Status::Incomplete);
    }

    #[test]
    fn expired_rule_pack_is_stale() {
        let mut d = Dataset::default();
        d.documents.push(doc(
            DocumentKind::RulePack,
            serde_json::json!({"status": "valid", "generation": "current", "sequence": 3, "expires_at_unix": NOW - 1, "payload_sha256": "x"}),
            NOW,
        ));
        assert_eq!(rules_row(&d, NOW).status, Status::Stale);
    }
}
