//! Browser-hijack timelines (P7-03): for each DLL that a per-user COM
//! registration points at, or that a non-browser process wrote into browser
//! user data, list the stages launcher -> DLL created -> COM registered ->
//! browser loaded -> outbound contact.
//!
//! Only observed events fill a stage. A stage that was not seen says whether
//! its event source was missing (unknown) or present but without a match
//! (not observed); nothing is inferred to complete the chain.
use super::browser_rules::{
    com_value_path, is_browser, is_browser_component, under, user_writable, USER_DATA_ROOTS,
};
use super::process::{
    ProcessRecord, ProcessTable, FILE_CREATE, IMAGE_LOAD, NETWORK_CONNECT, PROCESS_CREATE,
    REGISTRY_VALUE_SET,
};
use super::{ComScope, ComServerKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// At most this many timelines are built (most recent first).
const MAX_TIMELINES: usize = 200;
/// Outbound contacts after the load considered part of the chain.
const OUTBOUND_WINDOW_MS: i64 = 10 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageKind {
    Launcher,
    DllCreated,
    ComRegistered,
    BrowserLoaded,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageState {
    Observed,
    /// The event source was available but no matching event was seen.
    NotObserved,
    /// The event source itself was not observed: unknown.
    SourceMissing,
}

#[derive(Debug, Clone, Serialize)]
pub struct Stage {
    pub kind: StageKind,
    pub state: StageState,
    pub at_unix_ms: Option<i64>,
    pub process_guid: Option<String>,
    pub image: Option<String>,
    /// Short factual detail (path, CLSID, address); never registry values
    /// other than the COM server path.
    pub detail: Option<String>,
    pub event_uid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Timeline {
    pub dll_path: String,
    pub stages: Vec<Stage>,
    pub observed_stages: usize,
}

#[derive(Debug, Serialize)]
pub struct TimelineReport {
    pub timelines: Vec<Timeline>,
    pub omitted: usize,
    pub note: &'static str,
}

fn image(p: &ProcessRecord) -> Option<String> {
    p.image.clone()
}

fn empty(kind: StageKind, have_source: bool) -> Stage {
    Stage {
        kind,
        state: if have_source {
            StageState::NotObserved
        } else {
            StageState::SourceMissing
        },
        at_unix_ms: None,
        process_guid: None,
        image: None,
        detail: None,
        event_uid: None,
    }
}

pub fn build(table: &ProcessTable, ioc_sources: &dyn Fn(&str) -> Vec<String>) -> TimelineReport {
    let has = |id| table.observed_event_ids.contains_key(&id);
    // Candidate DLLs: per-user COM targets in user-writable folders and DLLs
    // written into browser user data by non-browser processes.
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for p in table.processes.values() {
        for r in &p.registry_changes {
            if let (Some(com), Some(v)) = (&r.com, &r.com_value) {
                let key = com_value_path(v);
                if com.scope == ComScope::PerUser
                    && com.server == ComServerKind::InprocServer32
                    && user_writable(&key)
                {
                    candidates.insert(key);
                }
            }
        }
        if !is_browser_component(p) {
            for f in &p.created_files {
                if f.path_key.ends_with(".dll") && under(&f.path_key, USER_DATA_ROOTS) {
                    candidates.insert(f.path_key.clone());
                }
            }
        }
    }
    let by_guid: BTreeMap<&str, &ProcessRecord> = table
        .processes
        .values()
        .map(|p| (p.process_guid.as_str(), p))
        .collect();
    let mut timelines = Vec::new();
    for path in candidates {
        let created = table
            .processes
            .values()
            .flat_map(|p| p.created_files.iter().map(move |f| (p, f)))
            .filter(|(_, f)| f.path_key == path)
            .min_by_key(|(_, f)| f.at_unix_ms);
        let registered = table
            .processes
            .values()
            .flat_map(|p| p.registry_changes.iter().map(move |r| (p, r)))
            .filter(|(_, r)| {
                r.com.as_ref().is_some_and(|c| c.scope == ComScope::PerUser)
                    && r.com_value.as_deref().map(com_value_path).as_deref() == Some(path.as_str())
            })
            .min_by_key(|(_, r)| r.at_unix_ms);
        let loaded = table
            .processes
            .values()
            .filter(|p| is_browser(p))
            .flat_map(|p| p.loaded_images.iter().map(move |l| (p, l)))
            .filter(|(_, l)| l.path_key == path)
            .min_by_key(|(_, l)| l.at_unix_ms);

        let actor = created.map(|(p, _)| p).or(registered.map(|(p, _)| p));
        let launcher = match actor {
            Some(p) if p.start_observed => Stage {
                kind: StageKind::Launcher,
                state: StageState::Observed,
                at_unix_ms: p.started_at_unix_ms,
                process_guid: Some(p.process_guid.clone()),
                image: image(p),
                detail: p
                    .parent_guid
                    .as_deref()
                    .and_then(|g| by_guid.get(g))
                    .and_then(|parent| parent.image.clone())
                    .or_else(|| p.parent_image.clone())
                    .map(|parent| format!("parent: {parent}")),
                event_uid: p.event_uids.first().cloned(),
            },
            _ => empty(StageKind::Launcher, has(PROCESS_CREATE)),
        };
        let dll = match created {
            Some((p, f)) => Stage {
                kind: StageKind::DllCreated,
                state: StageState::Observed,
                at_unix_ms: f.at_unix_ms,
                process_guid: Some(p.process_guid.clone()),
                image: image(p),
                detail: Some(f.path.clone()),
                event_uid: Some(f.event_uid.clone()),
            },
            None => empty(StageKind::DllCreated, has(FILE_CREATE)),
        };
        let com = match registered {
            Some((p, r)) => Stage {
                kind: StageKind::ComRegistered,
                state: StageState::Observed,
                at_unix_ms: r.at_unix_ms,
                process_guid: Some(p.process_guid.clone()),
                image: image(p),
                detail: r.com.as_ref().map(|c| format!("CLSID {} (HKCU)", c.clsid)),
                event_uid: Some(r.event_uid.clone()),
            },
            None => empty(StageKind::ComRegistered, has(REGISTRY_VALUE_SET)),
        };
        let (load, outbound) = match loaded {
            Some((p, l)) => {
                let contact = p
                    .contacts
                    .iter()
                    .filter(|c| match (c.at_unix_ms, l.at_unix_ms) {
                        (Some(c), Some(t)) => c >= t && c - t <= OUTBOUND_WINDOW_MS,
                        _ => false,
                    })
                    .min_by_key(|c| c.at_unix_ms);
                let load = Stage {
                    kind: StageKind::BrowserLoaded,
                    state: StageState::Observed,
                    at_unix_ms: l.at_unix_ms,
                    process_guid: Some(p.process_guid.clone()),
                    image: image(p),
                    detail: Some(format!(
                        "signed: {}",
                        l.signed.map_or("unknown".into(), |s| s.to_string())
                    )),
                    event_uid: Some(l.event_uid.clone()),
                };
                let out = match contact {
                    Some(c) => {
                        let ioc = c.ip.as_deref().map(ioc_sources).unwrap_or_default();
                        Stage {
                            kind: StageKind::Outbound,
                            state: StageState::Observed,
                            at_unix_ms: c.at_unix_ms,
                            process_guid: Some(p.process_guid.clone()),
                            image: image(p),
                            detail: Some(format!(
                                "{}{}{}",
                                c.ip.clone().or(c.dns_name.clone()).unwrap_or_default(),
                                c.port.map(|p| format!(":{p}")).unwrap_or_default(),
                                if ioc.is_empty() {
                                    String::new()
                                } else {
                                    format!(" (fresh IOC: {})", ioc.join(", "))
                                }
                            )),
                            event_uid: Some(c.event_uid.clone()),
                        }
                    }
                    // Browsers talk to the network constantly; only a missing
                    // source is worth stating.
                    None => empty(StageKind::Outbound, has(NETWORK_CONNECT)),
                };
                (load, out)
            }
            None => (
                empty(StageKind::BrowserLoaded, has(IMAGE_LOAD)),
                empty(StageKind::Outbound, has(NETWORK_CONNECT)),
            ),
        };
        let stages = vec![launcher, dll, com, load, outbound];
        let observed_stages = stages
            .iter()
            .filter(|s| s.state == StageState::Observed)
            .count();
        timelines.push(Timeline {
            dll_path: path,
            stages,
            observed_stages,
        });
    }
    timelines
        .sort_by_key(|t| std::cmp::Reverse(t.stages.iter().filter_map(|s| s.at_unix_ms).max()));
    let omitted = timelines.len().saturating_sub(MAX_TIMELINES);
    timelines.truncate(MAX_TIMELINES);
    TimelineReport {
        timelines,
        omitted,
        note: "Only observed events are shown. source_missing means the event type was not collected, so that step is unknown, not absent.",
    }
}

#[cfg(test)]
mod tests {
    use super::super::process::tests::{create, ev};
    use super::*;

    const DLL: &str = r"C:\Users\u\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\x\platform_experience_helper.dll";

    fn none(_: &str) -> Vec<String> {
        Vec::new()
    }

    fn chain() -> Vec<super::super::EventEnvelope> {
        let target = r"HKU\S-1-5-21-1_Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32\(Default)";
        vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{L}",
                "10",
                r"C:\Games\launcher.exe",
                r"C:\Windows\explorer.exe",
            ),
            ev(
                FILE_CREATE,
                2,
                "2026-11-05T10:00:01Z",
                &[("ProcessGuid", "{L}"), ("TargetFilename", DLL)],
            ),
            ev(
                REGISTRY_VALUE_SET,
                3,
                "2026-11-05T10:00:02Z",
                &[
                    ("ProcessGuid", "{L}"),
                    ("EventType", "SetValue"),
                    ("TargetObject", target),
                    ("Details", DLL),
                ],
            ),
            create(
                4,
                "2026-11-05T10:05:00Z",
                "{B}",
                "20",
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "explorer.exe",
            ),
            ev(
                IMAGE_LOAD,
                5,
                "2026-11-05T10:05:01Z",
                &[
                    ("ProcessGuid", "{B}"),
                    ("ImageLoaded", DLL),
                    ("Signed", "false"),
                ],
            ),
            ev(
                NETWORK_CONNECT,
                6,
                "2026-11-05T10:05:30Z",
                &[
                    ("ProcessGuid", "{B}"),
                    ("DestinationIp", "192.0.2.66"),
                    ("DestinationPort", "443"),
                ],
            ),
        ]
    }

    #[test]
    fn full_chain_has_all_five_observed_stages_in_order() {
        let table = ProcessTable::build(&chain());
        let c2 = |ip: &str| {
            if ip == "192.0.2.66" {
                vec!["feodo".to_string()]
            } else {
                vec![]
            }
        };
        let report = build(&table, &c2);
        assert_eq!(report.timelines.len(), 1);
        let t = &report.timelines[0];
        assert_eq!(t.observed_stages, 5);
        let times: Vec<i64> = t.stages.iter().map(|s| s.at_unix_ms.unwrap()).collect();
        assert!(times.windows(2).all(|w| w[0] <= w[1]));
        assert!(t.stages[4]
            .detail
            .as_deref()
            .unwrap()
            .contains("fresh IOC: feodo"));
    }

    #[test]
    fn missing_sources_are_unknown_not_absent() {
        // Without image-load and network events the chain stops at COM.
        let events: Vec<_> = chain()
            .into_iter()
            .filter(|e| e.event_id != IMAGE_LOAD && e.event_id != NETWORK_CONNECT)
            .collect();
        let report = build(&ProcessTable::build(&events), &none);
        let t = &report.timelines[0];
        assert_eq!(t.observed_stages, 3);
        assert_eq!(t.stages[3].state, StageState::SourceMissing);
        assert_eq!(t.stages[4].state, StageState::SourceMissing);
    }

    #[test]
    fn present_source_without_match_is_not_observed() {
        let mut events = chain();
        events.retain(|e| e.event_id != IMAGE_LOAD);
        events.push(ev(
            IMAGE_LOAD,
            9,
            "2026-11-05T10:06:00Z",
            &[
                ("ProcessGuid", "{B}"),
                ("ImageLoaded", r"C:\Windows\System32\kernel32.dll"),
            ],
        ));
        let report = build(&ProcessTable::build(&events), &none);
        assert_eq!(report.timelines[0].stages[3].state, StageState::NotObserved);
    }

    #[test]
    fn browser_writing_its_own_data_creates_no_timeline() {
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{B}",
                "20",
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "explorer.exe",
            ),
            ev(
                FILE_CREATE,
                2,
                "2026-11-05T10:00:01Z",
                &[("ProcessGuid", "{B}"), ("TargetFilename", DLL)],
            ),
        ];
        assert!(build(&ProcessTable::build(&events), &none)
            .timelines
            .is_empty());
    }
}
