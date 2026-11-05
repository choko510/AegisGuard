//! Read-only local HTML report (P4-03). Built from the JSON/JSONL that the
//! other commands print; it runs no script (strict CSP), escapes every value,
//! uploads nothing and needs no privileges. Missing inputs are shown as not
//! provided, incomplete analysis is shown first, and nothing reads as "safe".
use crate::{store, Result};
use serde_json::Value;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SCAN_LINES: usize = 200_000;
const MAX_ROWS: usize = 500;

pub struct Inputs {
    pub scans: Vec<PathBuf>,
    pub correlation: Option<PathBuf>,
    pub iocs: Option<PathBuf>,
    pub defender: Option<PathBuf>,
    pub c2_status: Option<PathBuf>,
    pub fim: Option<PathBuf>,
}

pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => escape(s),
        Value::Null => "—".into(),
        other => escape(&other.to_string()),
    }
}

fn read_json(path: &Path) -> Result<Value> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("{} exceeds the input size limit", path.display()).into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Scan reports plus the number of lines that were not valid reports.
fn read_scans(paths: &[PathBuf]) -> Result<(Vec<Value>, usize, bool)> {
    let mut reports = Vec::new();
    let mut bad = 0usize;
    let mut truncated = false;
    for path in paths {
        let reader = BufReader::new(std::fs::File::open(path)?.take(MAX_INPUT_BYTES));
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if reports.len() >= MAX_SCAN_LINES {
                truncated = true;
                break;
            }
            match serde_json::from_str::<Value>(&line) {
                Ok(v) if v.get("path").is_some() && v.get("risk").is_some() => reports.push(v),
                _ => bad += 1,
            }
        }
    }
    Ok((reports, bad, truncated))
}

fn not_provided(html: &mut String, title: &str) {
    let _ = write!(
        html,
        "<section><h2>{}</h2><p class=unknown>未提供：この項目の状態は不明です（問題なしという意味ではありません）。</p></section>",
        escape(title)
    );
}

fn table(html: &mut String, headers: &[&str], rows: &[Vec<String>], total: usize) {
    html.push_str("<table><tr>");
    for h in headers {
        let _ = write!(html, "<th>{}</th>", escape(h));
    }
    html.push_str("</tr>");
    for row in rows.iter().take(MAX_ROWS) {
        html.push_str("<tr>");
        for cell in row {
            let _ = write!(html, "<td>{cell}</td>");
        }
        html.push_str("</tr>");
    }
    html.push_str("</table>");
    if total > MAX_ROWS {
        let _ = write!(
            html,
            "<p class=warn>表示は先頭{MAX_ROWS}件です（全{total}件）。</p>"
        );
    }
}

fn scan_section(html: &mut String, reports: &[Value], bad: usize, truncated: bool) {
    html.push_str("<section><h2>ファイル検査</h2>");
    if reports.is_empty() {
        html.push_str("<p class=unknown>検査結果がありません。検査していない状態は安全の証明ではありません。</p></section>");
        return;
    }
    let count = |f: &dyn Fn(&Value) -> bool| reports.iter().filter(|r| f(r)).count();
    let not_complete = count(&|r| r["analysis_complete"] != Value::Bool(true));
    if not_complete > 0 || bad > 0 || truncated {
        let _ = write!(
            html,
            "<p class=alert>{not_complete}件は完全に解析できていません（incomplete / not_assessed）。読み取れない行{bad}件{}。検出なしは安全の証明ではありません。</p>",
            if truncated { "、入力の上限で以降を省略" } else { "" }
        );
    }
    let summary: Vec<Vec<String>> = ["analyzed", "incomplete", "not_assessed"]
        .iter()
        .map(|a| {
            vec![
                escape(a),
                count(&|r| r["assessment"] == *a || (r["assessment"].is_null() && legacy(r) == *a))
                    .to_string(),
            ]
        })
        .collect();
    table(html, &["解析の完全性", "件数"], &summary, summary.len());
    let notable: Vec<&Value> = reports
        .iter()
        .filter(|r| r["risk"] != "low_signal")
        .collect();
    let rows: Vec<Vec<String>> = notable
        .iter()
        .map(|r| {
            let signals = r["signals"]
                .as_array()
                .map(|s| {
                    s.iter()
                        .map(|x| text(&x["code"]))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let reasons = r["incomplete_reasons"]
                .as_array()
                .map(|s| s.iter().map(text).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            vec![
                text(&r["path"]),
                text(&r["risk"]),
                text(&r["assessment"]),
                signals,
                format!("{reasons} {}", text(&r["not_assessed_reason"])),
            ]
        })
        .collect();
    html.push_str("<h3>確認が必要な項目（low_signal以外）</h3>");
    table(
        html,
        &["パス", "risk", "完全性", "シグナル", "未到達の理由"],
        &rows,
        notable.len(),
    );
    html.push_str("</section>");
}

/// v1 reports have no `assessment`; derive it from `status`.
fn legacy(r: &Value) -> &'static str {
    match r["status"].as_str() {
        Some("analyzed") => "analyzed",
        Some("incomplete") => "incomplete",
        _ => "not_assessed",
    }
}

fn correlation_section(html: &mut String, v: &Value) {
    let c = if v.get("correlation").is_some() {
        &v["correlation"]
    } else {
        v
    };
    html.push_str("<section><h2>イベント相関</h2>");
    let not_evaluable: Vec<String> = c["rules"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter(|r| r["evaluable"] != Value::Bool(true))
        .map(|r| {
            format!(
                "{}（不足：{}）",
                text(&r["rule_id"]),
                text(&r["missing_sources"])
            )
        })
        .collect();
    if !not_evaluable.is_empty() {
        let _ = write!(
            html,
            "<p class=unknown>評価できなかったルール：{}</p>",
            not_evaluable.join("、")
        );
    }
    let findings = c["findings"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = findings
        .iter()
        .map(|f| {
            vec![
                text(&f["rule_id"]),
                text(&f["verdict"]),
                text(&f["confidence"]),
                text(&f["process_key"]),
                text(&f["explanation"]),
            ]
        })
        .collect();
    table(
        html,
        &["ルール", "判定", "確度", "ProcessGuid", "説明"],
        &rows,
        findings.len(),
    );
    html.push_str("</section>");
}

fn iocs_section(html: &mut String, v: &Value) {
    let r = if v.get("report").is_some() {
        &v["report"]
    } else {
        v
    };
    html.push_str("<section><h2>IOCの帰属</h2>");
    if let Some(vis) = r["visibility"].as_array() {
        let notes: Vec<String> = vis.iter().map(text).collect();
        let _ = write!(
            html,
            "<p class=unknown>見えない範囲：{}</p>",
            notes.join("、")
        );
    }
    let findings = r["findings"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = findings
        .iter()
        .map(|f| {
            vec![
                text(&f["verdict"]),
                text(&f["basis"]),
                text(&f["destination"]),
                text(&f["image"]),
                text(&f["confidence"]),
            ]
        })
        .collect();
    table(
        html,
        &["判定", "根拠", "宛先", "プログラム", "確度"],
        &rows,
        findings.len(),
    );
    html.push_str("</section>");
}

fn defender_section(html: &mut String, v: &Value) {
    html.push_str("<section><h2>Microsoft Defender（読み取り専用の監査）</h2>");
    if v["available"] != Value::Bool(true) {
        html.push_str("<p class=alert>Defenderの状態を読み取れませんでした（不明）。</p>");
    }
    let controls = v["controls"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = controls
        .iter()
        .map(|c| {
            let state = text(&c["state"]);
            let class = match c["state"].as_str() {
                Some("unknown") => "unknown",
                Some("disabled") => "warn",
                _ => "",
            };
            vec![
                text(&c["name"]),
                format!("<span class=\"{class}\">{state}</span>"),
            ]
        })
        .collect();
    table(html, &["項目", "状態"], &rows, controls.len());
    let _ = write!(
        html,
        "<p>管理：{}　除外の件数（パス）：{}</p><p class=note>{}</p></section>",
        text(&v["management"]),
        text(&v["exclusions"]["path_count"]),
        text(&v["note"])
    );
}

fn c2_section(html: &mut String, v: &Value) {
    html.push_str("<section><h2>C2フィードの鮮度</h2>");
    let feeds = v["feeds"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = feeds
        .iter()
        .map(|f| {
            let stale = f["stale"] != Value::Bool(false);
            vec![
                text(&f["source"]),
                if stale {
                    "<span class=warn>期限切れ・未取得</span>".into()
                } else {
                    "期限内".into()
                },
                text(&f["indicators"]),
            ]
        })
        .collect();
    table(html, &["ソース", "鮮度", "件数"], &rows, feeds.len());
    html.push_str("<p class=note>空・古い・未登録のフィードは「感染していない」ことを意味しません。</p></section>");
}

fn fim_section(html: &mut String, v: &Value) {
    html.push_str("<section><h2>限定FIM</h2>");
    let changes = v["changes"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = changes
        .iter()
        .map(|c| {
            vec![
                text(&c["kind"]),
                text(&c["path"]),
                text(&c["previous_path"]),
                text(&c["detail"]),
            ]
        })
        .collect();
    table(
        html,
        &["種類", "パス", "以前のパス", "詳細"],
        &rows,
        changes.len(),
    );
    let _ = write!(
        html,
        "<p class=note>{}</p></section>",
        text(&v["limitation"])
    );
}

pub fn render(inputs: &Inputs, generated_at_unix: u64) -> Result<String> {
    let mut html = String::from(
        "<!doctype html><html lang=ja><head><meta charset=utf-8>\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
         <meta name=viewport content=\"width=device-width, initial-scale=1\"><title>AegisGuard report</title><style>\
         body{font-family:system-ui,sans-serif;margin:16px;max-width:1100px;color:#1a1a1a;background:#fff}\
         table{border-collapse:collapse;width:100%;margin:8px 0;font-size:14px}td,th{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top;word-break:break-all}\
         .alert{background:#fde8e8;border-left:4px solid #c62828;padding:8px}.warn{color:#b45309}.unknown{background:#f3f4f6;border-left:4px solid #6b7280;padding:8px}.note{color:#555;font-size:13px}\
         </style></head><body><h1>AegisGuard ローカルレポート</h1>",
    );
    let _ = write!(
        html,
        "<p class=note>生成時刻（UNIX）：{generated_at_unix}。このファイルはローカルの出力から作成した読み取り専用のレポートで、外部へ送信していません。所見は確認のための根拠であり、悪性の判定ではありません。</p>"
    );
    let (scans, bad, truncated) = read_scans(&inputs.scans)?;
    scan_section(&mut html, &scans, bad, truncated);
    type Section = fn(&mut String, &Value);
    let optional: [(&Option<PathBuf>, &str, Section); 5] = [
        (&inputs.correlation, "イベント相関", correlation_section),
        (&inputs.iocs, "IOCの帰属", iocs_section),
        (&inputs.defender, "Microsoft Defender", defender_section),
        (&inputs.c2_status, "C2フィードの鮮度", c2_section),
        (&inputs.fim, "限定FIM", fim_section),
    ];
    for (path, title, section) in optional {
        match path {
            Some(p) => section(&mut html, &read_json(p)?),
            None => not_provided(&mut html, title),
        }
    }
    html.push_str("</body></html>\n");
    Ok(html)
}

pub fn write(inputs: &Inputs, out: &Path, generated_at_unix: u64) -> Result<()> {
    let html = render(inputs, generated_at_unix)?;
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create_new(out)
        .map_err(|e| format!("{}: {e} (reports are never overwritten)", out.display()))?;
    store::restrict_to_owner(out)?;
    std::io::Write::write_all(&mut file, html.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("aegisguard-report-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn inputs(scans: Vec<PathBuf>) -> Inputs {
        Inputs {
            scans,
            correlation: None,
            iocs: None,
            defender: None,
            c2_status: None,
            fim: None,
        }
    }

    #[test]
    fn hostile_values_are_escaped_and_no_script_can_run() {
        let dir = temp_dir("xss");
        let scan = dir.join("scan.jsonl");
        std::fs::write(
            &scan,
            r#"{"path":"C:\\x\\<script>alert(1)</script>.ps1","risk":"high","assessment":"analyzed","analysis_complete":true,"signals":[{"code":"<img src=x onerror=alert(1)>"}],"incomplete_reasons":[]}"#,
        )
        .unwrap();
        let html = render(&inputs(vec![scan]), 1).unwrap();
        assert!(!html.contains("<script>alert") && !html.contains("<img"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("default-src 'none'"));
        assert!(!html.contains("<script"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_or_partial_data_never_reads_as_safe() {
        let dir = temp_dir("partial");
        let empty = dir.join("empty.jsonl");
        std::fs::write(&empty, "").unwrap();
        let html = render(&inputs(vec![empty]), 1).unwrap();
        assert!(html.contains("検査結果がありません"));
        assert_eq!(html.matches("未提供").count(), 5);

        let scan = dir.join("scan.jsonl");
        std::fs::write(
            &scan,
            "{\"path\":\"a.ps1\",\"risk\":\"incomplete\",\"assessment\":\"incomplete\",\"analysis_complete\":false,\"signals\":[],\"incomplete_reasons\":[\"analysis_time_limit\"]}\nnot json\n",
        )
        .unwrap();
        let html = render(&inputs(vec![scan]), 1).unwrap();
        assert!(html.contains("1件は完全に解析できていません"));
        assert!(html.contains("読み取れない行1件"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn defender_unknowns_and_stale_feeds_are_highlighted() {
        let dir = temp_dir("sections");
        let defender = dir.join("defender.json");
        std::fs::write(&defender, r#"{"available":false,"controls":[{"name":"real_time_protection","state":"unknown"}],"management":"unknown","exclusions":{"path_count":null},"note":"n"}"#).unwrap();
        let c2 = dir.join("c2.json");
        std::fs::write(
            &c2,
            r#"{"feeds":[{"source":"feodo","stale":true,"indicators":0}]}"#,
        )
        .unwrap();
        let mut i = inputs(vec![]);
        i.defender = Some(defender);
        i.c2_status = Some(c2);
        let html = render(&i, 1).unwrap();
        assert!(html.contains("Defenderの状態を読み取れませんでした"));
        assert!(html.contains("期限切れ・未取得"));
        let out = dir.join("report.html");
        write(&i, &out, 1).unwrap();
        assert!(write(&i, &out, 1).is_err(), "reports are never overwritten");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
