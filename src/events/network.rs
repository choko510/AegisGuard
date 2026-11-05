//! IP / DNS / process attribution of IOC evidence (P3-01). Each finding says
//! how the destination was tied to the process (`basis`) and how far that can
//! be trusted. What the event sources cannot show (DoH/DoT, VPN tunnels, NRPT
//! redirection, disabled Sysmon event types) is reported as unknown visibility.
use super::process::{ProcessTable, DNS_QUERY, NETWORK_CONNECT};
use crate::ioc::{IocEvidence, IocSet};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// An IOC domain a process resolved: name, time, answers, evidence, event uid.
type IocAnswer<'a> = (&'a str, i64, &'a Vec<String>, Vec<IocEvidence>, &'a str);

/// A connection counts as following a DNS answer only inside this window.
const DNS_LINK_WINDOW_MS: i64 = 5 * 60 * 1000;
/// Destinations contacted by this many different images are likely shared
/// infrastructure (CDN, cloud front ends), which lowers confidence.
const SHARED_DESTINATION_IMAGES: usize = 3;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NetworkFinding {
    pub process_guid: String,
    pub image: Option<String>,
    /// `direct_ip`, `dns_query` or `dns_then_connect`.
    pub basis: &'static str,
    pub destination: String,
    pub at_unix_ms: Option<i64>,
    pub event_refs: Vec<String>,
    pub evidence: Vec<IocEvidence>,
    pub shared_destination: bool,
    /// `review` (active evidence), `stale_only`, or `suppressed` (user exception).
    pub verdict: &'static str,
    pub confidence: &'static str,
}

#[derive(Debug, Serialize)]
pub struct NetworkReport {
    pub findings: Vec<NetworkFinding>,
    pub visibility: Vec<&'static str>,
}

fn verdict(evidence: &[IocEvidence], shared: bool, basis: &str) -> (&'static str, &'static str) {
    if evidence.iter().any(IocEvidence::active) {
        let strong = evidence
            .iter()
            .any(|e| e.active() && e.confidence == "medium");
        let confidence = if shared || !strong || basis == "dns_query" {
            "low"
        } else {
            "medium"
        };
        ("review", confidence)
    } else if evidence
        .iter()
        .any(|e| e.allowlist_reason.is_some() && !e.stale)
    {
        ("suppressed", "low")
    } else {
        ("stale_only", "low")
    }
}

pub fn attribute(table: &ProcessTable, iocs: &IocSet) -> NetworkReport {
    let mut visibility = Vec::new();
    if !table.observed_event_ids.contains_key(&NETWORK_CONNECT) {
        visibility.push("network_connect_not_observed: connections are unknown, not absent");
    }
    if !table.observed_event_ids.contains_key(&DNS_QUERY) {
        visibility.push("dns_query_not_observed: DNS-based attribution is unavailable");
    }
    visibility.push("dns_over_https_vpn_and_nrpt_are_not_visible_to_sysmon");

    // How many distinct images contacted each IP.
    let mut images_per_ip: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for p in table.processes.values() {
        for c in &p.contacts {
            if let Some(ip) = c.ip.as_deref() {
                images_per_ip
                    .entry(ip)
                    .or_default()
                    .insert(p.image.clone().unwrap_or_else(|| p.process_guid.clone()));
            }
        }
    }
    let shared = |ip: &str| {
        images_per_ip
            .get(ip)
            .is_some_and(|s| s.len() >= SHARED_DESTINATION_IMAGES)
    };

    let mut findings = Vec::new();
    for p in table.processes.values() {
        // IOC domains this process resolved, with the answers and when.
        let mut ioc_answers: Vec<IocAnswer> = Vec::new();
        for c in &p.contacts {
            if let Some(name) = c.dns_name.as_deref() {
                let evidence = iocs.domain(name);
                if !evidence.is_empty() {
                    let (v, conf) = verdict(&evidence, false, "dns_query");
                    findings.push(NetworkFinding {
                        process_guid: p.process_guid.clone(),
                        image: p.image.clone(),
                        basis: "dns_query",
                        destination: name.to_owned(),
                        at_unix_ms: c.at_unix_ms,
                        event_refs: vec![c.event_uid.clone()],
                        evidence: evidence.clone(),
                        shared_destination: false,
                        verdict: v,
                        confidence: conf,
                    });
                    if let Some(at) = c.at_unix_ms {
                        ioc_answers.push((name, at, &c.resolved_ips, evidence, &c.event_uid));
                    }
                }
            }
        }
        for c in &p.contacts {
            let Some(ip) = c.ip.as_deref() else { continue };
            let is_shared = shared(ip);
            let evidence = iocs.ip(ip);
            if !evidence.is_empty() {
                let (v, conf) = verdict(&evidence, is_shared, "direct_ip");
                findings.push(NetworkFinding {
                    process_guid: p.process_guid.clone(),
                    image: p.image.clone(),
                    basis: "direct_ip",
                    destination: ip.to_owned(),
                    at_unix_ms: c.at_unix_ms,
                    event_refs: vec![c.event_uid.clone()],
                    evidence,
                    shared_destination: is_shared,
                    verdict: v,
                    confidence: conf,
                });
            }
            // The same process connected to an address its IOC-domain query
            // returned, shortly afterwards. Other addresses are not linked.
            if let Some(at) = c.at_unix_ms {
                for (name, asked_at, answers, evidence, dns_uid) in &ioc_answers {
                    if answers.iter().any(|a| a == ip)
                        && at >= *asked_at
                        && at - asked_at <= DNS_LINK_WINDOW_MS
                    {
                        let (v, conf) = verdict(evidence, is_shared, "dns_then_connect");
                        findings.push(NetworkFinding {
                            process_guid: p.process_guid.clone(),
                            image: p.image.clone(),
                            basis: "dns_then_connect",
                            destination: format!("{name} -> {ip}"),
                            at_unix_ms: Some(at),
                            event_refs: vec![(*dns_uid).to_owned(), c.event_uid.clone()],
                            evidence: evidence.clone(),
                            shared_destination: is_shared,
                            verdict: v,
                            confidence: conf,
                        });
                    }
                }
            }
        }
    }
    findings.sort_by(|a, b| {
        (&a.process_guid, a.basis, &a.destination, a.at_unix_ms).cmp(&(
            &b.process_guid,
            b.basis,
            &b.destination,
            b.at_unix_ms,
        ))
    });
    findings.dedup();
    NetworkReport {
        findings,
        visibility,
    }
}

#[cfg(test)]
mod tests {
    use super::super::process::tests::{create, ev};
    use super::super::process::{ProcessTable, DNS_QUERY, NETWORK_CONNECT};
    use super::*;
    use crate::ioc::tests::entry;

    const NOW: u64 = 1_793_000_000;

    fn iocs() -> IocSet {
        IocSet::from_parts(
            vec![
                entry("domain", "c2.example.invalid", NOW + 3600, None),
                entry("ip", "198.51.100.7", NOW + 3600, None),
                entry("ip", "198.51.100.8", NOW - 1, None),
                entry("ip", "203.0.113.5", NOW + 3600, None),
            ],
            vec![entry(
                "ip",
                "203.0.113.5",
                NOW + 60,
                Some("internal test host"),
            )],
            NOW,
        )
    }

    fn dns(
        record: u64,
        time: &str,
        guid: &str,
        name: &str,
        answers: &str,
    ) -> crate::events::EventEnvelope {
        ev(
            DNS_QUERY,
            record,
            time,
            &[
                ("ProcessGuid", guid),
                ("QueryName", name),
                ("QueryResults", answers),
            ],
        )
    }

    fn net(record: u64, time: &str, guid: &str, ip: &str) -> crate::events::EventEnvelope {
        ev(
            NETWORK_CONNECT,
            record,
            time,
            &[
                ("ProcessGuid", guid),
                ("DestinationIp", ip),
                ("DestinationPort", "443"),
            ],
        )
    }

    #[test]
    fn dns_answer_then_connection_is_linked_but_other_ips_are_not() {
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{A}",
                "1",
                "C:\\a.exe",
                "C:\\p.exe",
            ),
            dns(
                2,
                "2026-11-05T10:00:01Z",
                "{A}",
                "x.c2.example.invalid",
                "type:  5 cdn.example;::ffff:192.0.2.44;",
            ),
            net(3, "2026-11-05T10:00:02Z", "{A}", "192.0.2.44"),
            net(4, "2026-11-05T10:00:03Z", "{A}", "192.0.2.99"),
        ];
        let report = attribute(&ProcessTable::build(&events), &iocs());
        let bases: Vec<_> = report
            .findings
            .iter()
            .map(|f| (f.basis, f.destination.as_str()))
            .collect();
        assert_eq!(
            bases,
            vec![
                ("dns_query", "x.c2.example.invalid"),
                ("dns_then_connect", "x.c2.example.invalid -> 192.0.2.44"),
            ]
        );
        let dns_only = &report.findings[0];
        assert_eq!((dns_only.verdict, dns_only.confidence), ("review", "low"));
    }

    #[test]
    fn stale_allowlisted_and_shared_destinations_are_distinguished() {
        let mut events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{A}",
                "1",
                "C:\\a.exe",
                "C:\\p.exe",
            ),
            net(2, "2026-11-05T10:00:01Z", "{A}", "198.51.100.8"),
            net(3, "2026-11-05T10:00:02Z", "{A}", "203.0.113.5"),
        ];
        // Three different images contact 198.51.100.7: shared infrastructure.
        for (i, image) in ["C:\\b.exe", "C:\\c.exe", "C:\\d.exe"].iter().enumerate() {
            let guid = format!("{{S{i}}}");
            events.push(create(
                10 + i as u64,
                "2026-11-05T10:01:00Z",
                &guid,
                &(10 + i).to_string(),
                image,
                "C:\\p.exe",
            ));
            events.push(net(
                20 + i as u64,
                "2026-11-05T10:01:01Z",
                &guid,
                "198.51.100.7",
            ));
        }
        let report = attribute(&ProcessTable::build(&events), &iocs());
        let by_dest = |d: &str| {
            report
                .findings
                .iter()
                .filter(|f| f.destination == d)
                .collect::<Vec<_>>()
        };
        assert_eq!(by_dest("198.51.100.8")[0].verdict, "stale_only");
        assert_eq!(by_dest("203.0.113.5")[0].verdict, "suppressed");
        let shared = by_dest("198.51.100.7");
        assert_eq!(shared.len(), 3);
        assert!(shared
            .iter()
            .all(|f| f.shared_destination && f.confidence == "low" && f.verdict == "review"));
    }

    #[test]
    fn missing_sources_are_reported_as_unknown_visibility() {
        let events = vec![create(
            1,
            "2026-11-05T10:00:00Z",
            "{A}",
            "1",
            "C:\\a.exe",
            "C:\\p.exe",
        )];
        let report = attribute(&ProcessTable::build(&events), &iocs());
        assert!(report.findings.is_empty());
        assert!(report
            .visibility
            .iter()
            .any(|v| v.starts_with("network_connect_not_observed")));
        assert!(report
            .visibility
            .iter()
            .any(|v| v.starts_with("dns_query_not_observed")));
    }

    #[test]
    fn connection_long_after_the_dns_answer_is_not_linked() {
        let events = vec![
            create(
                1,
                "2026-11-05T10:00:00Z",
                "{A}",
                "1",
                "C:\\a.exe",
                "C:\\p.exe",
            ),
            dns(
                2,
                "2026-11-05T10:00:01Z",
                "{A}",
                "c2.example.invalid",
                "192.0.2.50;",
            ),
            net(3, "2026-11-05T11:00:00Z", "{A}", "192.0.2.50"),
        ];
        let report = attribute(&ProcessTable::build(&events), &iocs());
        assert!(report
            .findings
            .iter()
            .all(|f| f.basis != "dns_then_connect"));
    }
}
