//! Offline, deterministic correlation over Sysmon process lifetimes.
//! A finding is a reason to look, never a verdict of malware. Rules that need
//! an event type that was not observed are reported as not evaluable instead
//! of producing a silent "nothing found".
use super::process::{ProcessRecord, ProcessTable};
use serde::Serialize;
use std::collections::BTreeMap;

pub const RULESET_VERSION: u32 = 1;

const OFFICE_APPS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
    "msaccess.exe",
];
const SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
];
/// AG-C002: contacts within this long after process start are considered.
const C2_WINDOW_MS: i64 = 5 * 60 * 1000;
/// AG-C003: this many children inside the window.
const BURST_CHILDREN: usize = 10;
const BURST_WINDOW_MS: i64 = 60 * 1000;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: &'static str,
    pub rule_version: u32,
    pub process_key: String,
    pub event_refs: Vec<String>,
    pub window_start_unix_ms: Option<i64>,
    pub window_end_unix_ms: Option<i64>,
    pub confidence: &'static str,
    pub missing_sources: Vec<&'static str>,
    pub suppressed_reason: Option<String>,
    /// `observed` (fact worth noting), `review` (look at it) or `unknown`.
    pub verdict: &'static str,
    pub explanation: &'static str,
}

#[derive(Debug, Serialize)]
pub struct RuleStatus {
    pub rule_id: &'static str,
    pub rule_version: u32,
    pub evaluable: bool,
    pub missing_sources: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Correlation {
    pub ruleset_version: u32,
    pub rules: Vec<RuleStatus>,
    pub findings: Vec<Finding>,
}

fn basename(path: &Option<String>) -> String {
    path.as_deref()
        .unwrap_or("")
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn observed(table: &ProcessTable, event_id: u32) -> bool {
    table.observed_event_ids.contains_key(&event_id)
}

/// `ioc_sources(ip)` returns the *fresh* IOC feeds listing that IP, if any.
pub fn correlate(table: &ProcessTable, ioc_sources: &dyn Fn(&str) -> Vec<String>) -> Correlation {
    use super::process::{NETWORK_CONNECT, PROCESS_CREATE};
    let has_create = observed(table, PROCESS_CREATE);
    let has_network = observed(table, NETWORK_CONNECT);
    let missing = |ok: bool, name: &'static str| if ok { vec![] } else { vec![name] };
    let rules = vec![
        RuleStatus {
            rule_id: "AG-C001",
            rule_version: 1,
            evaluable: has_create,
            missing_sources: missing(has_create, "sysmon_process_create"),
        },
        RuleStatus {
            rule_id: "AG-C002",
            rule_version: 1,
            evaluable: has_create && has_network,
            missing_sources: [
                missing(has_create, "sysmon_process_create"),
                missing(has_network, "sysmon_network_connect"),
            ]
            .concat(),
        },
        RuleStatus {
            rule_id: "AG-C003",
            rule_version: 1,
            evaluable: has_create,
            missing_sources: missing(has_create, "sysmon_process_create"),
        },
    ];
    let mut rules = rules;
    rules.extend(credential_rule_status(table));

    let mut findings = Vec::new();
    let processes: Vec<&ProcessRecord> = table.processes.values().collect();
    for p in &processes {
        // AG-C001: an Office application started a script host or LOLBin.
        if p.start_observed
            && OFFICE_APPS.contains(&basename(&p.parent_image).as_str())
            && SCRIPT_HOSTS.contains(&basename(&p.image).as_str())
        {
            findings.push(Finding {
                rule_id: "AG-C001",
                rule_version: 1,
                process_key: p.process_guid.clone(),
                event_refs: p.event_uids.iter().take(1).cloned().collect(),
                window_start_unix_ms: p.started_at_unix_ms,
                window_end_unix_ms: p.started_at_unix_ms,
                confidence: "medium",
                missing_sources: vec![],
                suppressed_reason: None,
                verdict: "review",
                explanation: "An Office application started a script host or system binary often used to run code",
            });
        }
        // AG-C002: a process contacted a fresh C2 IOC shortly after it started.
        if let Some(start) = p.started_at_unix_ms {
            let hits: Vec<_> = p
                .contacts
                .iter()
                .filter(|c| {
                    c.at_unix_ms
                        .is_some_and(|at| at >= start && at - start <= C2_WINDOW_MS)
                })
                .filter(|c| {
                    c.ip.as_deref()
                        .is_some_and(|ip| !ioc_sources(ip).is_empty())
                })
                .collect();
            if !hits.is_empty() {
                findings.push(Finding {
                    rule_id: "AG-C002",
                    rule_version: 1,
                    process_key: p.process_guid.clone(),
                    event_refs: hits.iter().map(|c| c.event_uid.clone()).collect(),
                    window_start_unix_ms: Some(start),
                    window_end_unix_ms: hits.iter().filter_map(|c| c.at_unix_ms).max(),
                    confidence: "medium",
                    missing_sources: vec![],
                    suppressed_reason: None,
                    verdict: "review",
                    explanation: "The process contacted an address listed by a fresh C2 feed within five minutes of starting; IP matches can be shared or reassigned addresses",
                });
            }
        }
    }
    // AG-C003: many children from one parent inside a short window.
    let mut children: BTreeMap<&str, Vec<&ProcessRecord>> = BTreeMap::new();
    for p in processes.iter().filter(|p| p.start_observed) {
        if let Some(parent) = p.parent_guid.as_deref() {
            children.entry(parent).or_default().push(p);
        }
    }
    for (parent, mut kids) in children {
        kids.sort_by_key(|k| (k.started_at_unix_ms, k.process_guid.clone()));
        let starts: Vec<i64> = kids.iter().filter_map(|k| k.started_at_unix_ms).collect();
        let burst = starts
            .windows(BURST_CHILDREN)
            .find(|w| w[BURST_CHILDREN - 1] - w[0] <= BURST_WINDOW_MS);
        if let Some(window) = burst {
            findings.push(Finding {
                rule_id: "AG-C003",
                rule_version: 1,
                process_key: parent.to_owned(),
                event_refs: kids
                    .iter()
                    .filter(|k| {
                        k.started_at_unix_ms
                            .is_some_and(|s| s >= window[0] && s <= window[BURST_CHILDREN - 1])
                    })
                    .filter_map(|k| k.event_uids.first().cloned())
                    .collect(),
                window_start_unix_ms: Some(window[0]),
                window_end_unix_ms: Some(window[BURST_CHILDREN - 1]),
                confidence: "low",
                missing_sources: vec![],
                suppressed_reason: None,
                verdict: "observed",
                explanation: "A process started at least ten child processes within one minute (build tools and installers do this too)",
            });
        }
    }
    credential_theft_signs(table, &mut findings);
    findings.sort_by(|a, b| (a.rule_id, &a.process_key).cmp(&(b.rule_id, &b.process_key)));
    Correlation {
        ruleset_version: RULESET_VERSION,
        rules,
        findings,
    }
}

/// Processes expected to open lsass with read access (system components and
/// Microsoft Defender). Anything else doing so is worth a look, not a verdict.
const LSASS_EXPECTED_ACCESSORS: &[&str] = &[
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "svchost.exe",
    "lsm.exe",
    "msmpeng.exe",
    "mpdefendercoreservice.exe",
    "wmiprvse.exe",
];
/// PROCESS_VM_READ: needed to read lsass memory (credential material).
const PROCESS_VM_READ: u32 = 0x0010;
/// AG-C011: a dump file written this soon after the lsass access.
const DUMP_WINDOW_MS: i64 = 10 * 60 * 1000;

/// P4-01 rule statuses (evaluable only when the needed Sysmon/Defender
/// events were observed).
fn credential_rule_status(table: &ProcessTable) -> Vec<RuleStatus> {
    use super::process::{FILE_CREATE, PROCESS_ACCESS, PROCESS_CREATE};
    let has = |id| observed(table, id);
    let has_defender = !table.observed_defender_event_ids.is_empty();
    let missing = |pairs: &[(bool, &'static str)]| {
        pairs
            .iter()
            .filter(|(ok, _)| !ok)
            .map(|(_, name)| *name)
            .collect::<Vec<_>>()
    };
    vec![
        RuleStatus {
            rule_id: "AG-C010",
            rule_version: 1,
            evaluable: has(PROCESS_ACCESS),
            missing_sources: missing(&[(has(PROCESS_ACCESS), "sysmon_process_access")]),
        },
        RuleStatus {
            rule_id: "AG-C011",
            rule_version: 1,
            evaluable: has(PROCESS_ACCESS) && has(FILE_CREATE),
            missing_sources: missing(&[
                (has(PROCESS_ACCESS), "sysmon_process_access"),
                (has(FILE_CREATE), "sysmon_file_create"),
            ]),
        },
        RuleStatus {
            rule_id: "AG-C012",
            rule_version: 1,
            evaluable: has(PROCESS_CREATE) && has_defender,
            missing_sources: missing(&[
                (has(PROCESS_CREATE), "sysmon_process_create"),
                (has_defender, "defender_detection_events"),
            ]),
        },
    ]
}

/// P4-01: combinations that suggest credential theft. Credential stores and
/// process memory are never read; only event metadata is used.
fn credential_theft_signs(table: &ProcessTable, findings: &mut Vec<Finding>) {
    for p in table.processes.values() {
        let source = basename(&p.image);
        let lsass_reads: Vec<_> = p
            .accesses
            .iter()
            .filter(|a| basename(&Some(a.target_image.clone())) == "lsass.exe")
            .filter(|a| a.granted_access.is_some_and(|g| g & PROCESS_VM_READ != 0))
            .collect();
        if !lsass_reads.is_empty() && !LSASS_EXPECTED_ACCESSORS.contains(&source.as_str()) {
            let first = lsass_reads.iter().filter_map(|a| a.at_unix_ms).min();
            findings.push(Finding {
                rule_id: "AG-C010",
                rule_version: 1,
                process_key: p.process_guid.clone(),
                event_refs: lsass_reads.iter().map(|a| a.event_uid.clone()).collect(),
                window_start_unix_ms: first,
                window_end_unix_ms: lsass_reads.iter().filter_map(|a| a.at_unix_ms).max(),
                confidence: "medium",
                missing_sources: vec![],
                suppressed_reason: None,
                verdict: "review",
                explanation: "A non-system process opened lsass.exe with memory read access (admin and backup tools can do this too)",
            });
            // AG-C011: the same process then wrote a dump file.
            if let Some(start) = first {
                let dumps: Vec<_> = p
                    .created_files
                    .iter()
                    .filter(|f| f.path.to_ascii_lowercase().ends_with(".dmp"))
                    .filter(|f| {
                        f.at_unix_ms
                            .is_some_and(|t| t >= start && t - start <= DUMP_WINDOW_MS)
                    })
                    .collect();
                if !dumps.is_empty() {
                    findings.push(Finding {
                        rule_id: "AG-C011",
                        rule_version: 1,
                        process_key: p.process_guid.clone(),
                        event_refs: lsass_reads
                            .iter()
                            .map(|a| a.event_uid.clone())
                            .chain(dumps.iter().map(|f| f.event_uid.clone()))
                            .collect(),
                        window_start_unix_ms: Some(start),
                        window_end_unix_ms: dumps.iter().filter_map(|f| f.at_unix_ms).max(),
                        confidence: "medium",
                        missing_sources: vec![],
                        suppressed_reason: None,
                        verdict: "review",
                        explanation: "The process that read lsass memory wrote a .dmp file within ten minutes",
                    });
                }
            }
        }
        // AG-C012: a file Defender had flagged was started afterwards.
        if let (true, Some(image), Some(start)) =
            (p.start_observed, p.image.as_deref(), p.started_at_unix_ms)
        {
            let image = image.to_ascii_lowercase();
            let hits: Vec<_> = table
                .defender_detections
                .iter()
                .filter(|d| d.path == image && d.at_unix_ms.is_some_and(|t| t <= start))
                .collect();
            if !hits.is_empty() {
                findings.push(Finding {
                    rule_id: "AG-C012",
                    rule_version: 1,
                    process_key: p.process_guid.clone(),
                    event_refs: hits
                        .iter()
                        .map(|d| d.event_uid.clone())
                        .chain(p.event_uids.iter().take(1).cloned())
                        .collect(),
                    window_start_unix_ms: hits.iter().filter_map(|d| d.at_unix_ms).min(),
                    window_end_unix_ms: Some(start),
                    confidence: "medium",
                    missing_sources: vec![],
                    suppressed_reason: None,
                    verdict: "review",
                    explanation: "A file that Microsoft Defender had reported was started afterwards; check Defender's remediation status",
                });
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::super::process::tests::{create, ev};
    use super::super::process::{ProcessTable, NETWORK_CONNECT};
    use super::super::EventEnvelope;
    use super::*;

    fn no_ioc(_: &str) -> Vec<String> {
        Vec::new()
    }

    fn c2(ip: &str) -> Vec<String> {
        if ip == "192.0.2.66" {
            vec!["feodo".into()]
        } else {
            Vec::new()
        }
    }

    fn scenario() -> Vec<EventEnvelope> {
        let mut events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{OFFICE}",
                "10",
                "C:\\Program Files\\Office\\WINWORD.EXE",
                "C:\\Windows\\explorer.exe",
            ),
            create(
                2,
                "2026-11-05T10:00:05Z",
                "{PS}",
                "11",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "C:\\Program Files\\Office\\WINWORD.EXE",
            ),
            ev(
                NETWORK_CONNECT,
                3,
                "2026-11-05T10:00:30Z",
                &[
                    ("ProcessGuid", "{PS}"),
                    ("DestinationIp", "192.0.2.66"),
                    ("DestinationPort", "443"),
                ],
            ),
            ev(
                NETWORK_CONNECT,
                4,
                "2026-11-05T10:20:00Z",
                &[
                    ("ProcessGuid", "{PS}"),
                    ("DestinationIp", "192.0.2.66"),
                    ("DestinationPort", "443"),
                ],
            ),
        ];
        events[1].parent_guid = Some("{OFFICE}".into());
        events
    }

    #[test]
    fn office_child_and_c2_contact_are_flagged_for_review() {
        let table = ProcessTable::build(&scenario());
        let result = correlate(&table, &c2);
        let ids: Vec<_> = result.findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, vec!["AG-C001", "AG-C002"]);
        let c2_finding = &result.findings[1];
        // Only the contact inside the five-minute window is evidence.
        assert_eq!(c2_finding.event_refs.len(), 1);
        assert_eq!(c2_finding.verdict, "review");
        assert!(result
            .rules
            .iter()
            .filter(|r| ["AG-C001", "AG-C002", "AG-C003"].contains(&r.rule_id))
            .all(|r| r.evaluable));
    }

    #[test]
    fn replay_is_deterministic_under_reordering_and_duplicates() {
        let base = correlate(&ProcessTable::build(&scenario()), &c2).findings;
        let mut shuffled = scenario();
        shuffled.reverse();
        shuffled.extend(scenario());
        assert_eq!(
            correlate(&ProcessTable::build(&shuffled), &c2).findings,
            base
        );
    }

    #[test]
    fn missing_network_events_make_the_c2_rule_not_evaluable() {
        let events: Vec<_> = scenario()
            .into_iter()
            .filter(|e| e.event_id != NETWORK_CONNECT)
            .collect();
        let result = correlate(&ProcessTable::build(&events), &c2);
        let rule = result
            .rules
            .iter()
            .find(|r| r.rule_id == "AG-C002")
            .unwrap();
        assert!(!rule.evaluable);
        assert_eq!(rule.missing_sources, vec!["sysmon_network_connect"]);
        assert!(result.findings.iter().all(|f| f.rule_id != "AG-C002"));
    }

    #[test]
    fn unknown_parent_and_stale_ioc_do_not_produce_findings() {
        // Child whose parent create was never seen still carries ParentImage.
        let events = vec![create(
            9,
            "2026-11-05T10:00:00Z",
            "{X}",
            "5",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Tools\\editor.exe",
        )];
        let result = correlate(&ProcessTable::build(&events), &no_ioc);
        assert!(result.findings.is_empty());
        let result = correlate(&ProcessTable::build(&scenario()), &no_ioc);
        assert!(result.findings.iter().all(|f| f.rule_id != "AG-C002"));
    }

    #[test]
    fn child_burst_is_observed_with_low_confidence() {
        let mut events = vec![create(
            1,
            "2026-11-05T10:00:00Z",
            "{P}",
            "1",
            "C:\\build.exe",
            "C:\\x.exe",
        )];
        for i in 0..10u64 {
            let mut child = create(
                10 + i,
                &format!("2026-11-05T10:00:{:02}Z", 10 + i),
                &format!("{{K{i}}}"),
                &(100 + i).to_string(),
                "C:\\cl.exe",
                "C:\\build.exe",
            );
            child.parent_guid = Some("{P}".into());
            events.push(child);
        }
        let result = correlate(&ProcessTable::build(&events), &no_ioc);
        let burst = result
            .findings
            .iter()
            .find(|f| f.rule_id == "AG-C003")
            .unwrap();
        assert_eq!((burst.verdict, burst.confidence), ("observed", "low"));
        assert_eq!(burst.event_refs.len(), 10);
    }

    #[test]
    fn empty_input_marks_every_rule_not_evaluable() {
        let result = correlate(&ProcessTable::build(&[]), &no_ioc);
        assert!(result.findings.is_empty());
        assert!(result.rules.iter().all(|r| !r.evaluable));
    }
}

#[cfg(test)]
mod credential_tests {
    use super::super::fixtures::sysmon;
    use super::super::parse_event_xml;
    use super::super::process::tests::{create, ev};
    use super::super::process::{ProcessTable, FILE_CREATE, PROCESS_ACCESS};
    use super::super::EventEnvelope;
    use super::*;

    fn none(_: &str) -> Vec<String> {
        Vec::new()
    }

    fn access(record: u64, time: &str, guid: &str, source: &str, granted: &str) -> EventEnvelope {
        ev(
            PROCESS_ACCESS,
            record,
            time,
            &[
                ("SourceProcessGuid", guid),
                ("SourceImage", source),
                ("TargetImage", r"C:\Windows\system32\lsass.exe"),
                ("GrantedAccess", granted),
            ],
        )
    }

    fn defender_detection(record: u64, time: &str, path: &str) -> EventEnvelope {
        let xml = sysmon(
            1116,
            record,
            time,
            &[("Threat Name", "Test:Win32/Synthetic"), ("Path", path)],
        )
        .replace(
            "Microsoft-Windows-Sysmon",
            "Microsoft-Windows-Windows Defender",
        );
        parse_event_xml(&xml, "x", 0).unwrap()
    }

    fn rule_ids(events: &[EventEnvelope]) -> Vec<&'static str> {
        correlate(&ProcessTable::build(events), &none)
            .findings
            .iter()
            .map(|f| f.rule_id)
            .collect()
    }

    #[test]
    fn lsass_read_then_dump_is_flagged_for_review() {
        let tool = r"C:\Users\u\AppData\Local\Temp\tool.exe";
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{R}",
                "50",
                tool,
                r"C:\Windows\explorer.exe",
            ),
            access(2, "2026-11-05T10:00:10Z", "{R}", tool, "0x1010"),
            ev(
                FILE_CREATE,
                3,
                "2026-11-05T10:01:00Z",
                &[
                    ("ProcessGuid", "{R}"),
                    ("TargetFilename", r"C:\Users\u\AppData\Local\Temp\out.DMP"),
                ],
            ),
        ];
        assert_eq!(rule_ids(&events), vec!["AG-C010", "AG-C011"]);
    }

    #[test]
    fn benign_controls_do_not_trigger() {
        let defender = r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe";
        let monitor = r"C:\Program Files\Monitor\mon.exe";
        let events = vec![
            // Defender scanning lsass with read access is expected.
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{D}",
                "60",
                defender,
                r"C:\Windows\System32\services.exe",
            ),
            access(2, "2026-11-05T10:00:01Z", "{D}", defender, "0x1410"),
            // A monitoring tool querying limited information only (no VM_READ).
            create(
                3,
                "2026-11-05T10:00:02Z",
                "{M}",
                "61",
                monitor,
                r"C:\Windows\explorer.exe",
            ),
            access(4, "2026-11-05T10:00:03Z", "{M}", monitor, "0x1000"),
            // A backup tool writing a .dmp without touching lsass.
            create(
                5,
                "2026-11-05T10:00:04Z",
                "{B}",
                "62",
                r"C:\Program Files\Backup\b.exe",
                r"C:\Windows\explorer.exe",
            ),
            ev(
                FILE_CREATE,
                6,
                "2026-11-05T10:00:05Z",
                &[
                    ("ProcessGuid", "{B}"),
                    ("TargetFilename", r"D:\backup\app.dmp"),
                ],
            ),
        ];
        assert!(rule_ids(&events).is_empty());
    }

    #[test]
    fn executing_a_file_defender_reported_is_flagged() {
        let events = vec![
            defender_detection(
                1,
                "2026-11-05T09:59:00Z",
                r"file:_C:\Users\u\Downloads\setup.exe",
            ),
            create(
                2,
                "2026-11-05T10:00:00Z",
                "{X}",
                "70",
                r"C:\Users\u\Downloads\setup.exe",
                r"C:\Windows\explorer.exe",
            ),
            // A different file that was never reported.
            create(
                3,
                "2026-11-05T10:00:01Z",
                "{Y}",
                "71",
                r"C:\Users\u\Downloads\other.exe",
                r"C:\Windows\explorer.exe",
            ),
        ];
        let result = correlate(&ProcessTable::build(&events), &none);
        let ids: Vec<_> = result.findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, vec!["AG-C012"]);
        assert_eq!(result.findings[0].process_key, "{X}");
        assert!(result
            .rules
            .iter()
            .any(|r| r.rule_id == "AG-C012" && r.evaluable));
    }

    #[test]
    fn missing_sysmon_access_events_are_not_evaluable_rather_than_clean() {
        let events = vec![create(
            1,
            "2026-11-05T10:00:00Z",
            "{A}",
            "1",
            r"C:\a.exe",
            r"C:\p.exe",
        )];
        let result = correlate(&ProcessTable::build(&events), &none);
        let status = |id: &str| result.rules.iter().find(|r| r.rule_id == id).unwrap();
        assert!(!status("AG-C010").evaluable);
        assert_eq!(
            status("AG-C011").missing_sources,
            vec!["sysmon_process_access", "sysmon_file_create"]
        );
        assert_eq!(
            status("AG-C012").missing_sources,
            vec!["defender_detection_events"]
        );
    }
}
