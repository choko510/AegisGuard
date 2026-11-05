//! Windows event ingestion (Phase 2). Events are rendered as XML by the
//! Windows Event Log API (or read from fixtures), normalized into
//! `EventEnvelope v1` with an allow-list of fields, and spooled durably.
//! Command lines are never stored verbatim, only as SHA-256 digests.
pub mod collector;
pub mod correlate;
pub mod network;
pub mod process;

#[cfg(windows)]
pub mod winevt;

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;
/// Rendered event XML larger than this is not parsed (recorded as oversized).
pub const MAX_EVENT_XML_BYTES: usize = 64 * 1024;
const MAX_FIELD_CHARS: usize = 2048;

pub const SYSMON_PROVIDER: &str = "Microsoft-Windows-Sysmon";

/// EventData fields kept verbatim. Everything else is dropped (counted).
const KEPT_FIELDS: &[&str] = &[
    "UtcTime",
    "ProcessGuid",
    "ProcessId",
    "Image",
    "ParentProcessGuid",
    "ParentProcessId",
    "ParentImage",
    "Hashes",
    "Protocol",
    "Initiated",
    "SourceIp",
    "SourcePort",
    "DestinationIp",
    "DestinationPort",
    "DestinationHostname",
    "QueryName",
    "QueryStatus",
    "QueryResults",
    "ImageLoaded",
    "Signed",
    "Signature",
    "SignatureStatus",
    "TargetFilename",
    "TargetObject",
    "EventType",
    "SourceProcessGuid",
    "SourceImage",
    "TargetProcessGuid",
    "TargetImage",
    "GrantedAccess",
    // Microsoft Defender operational events.
    "Threat Name",
    "Severity Name",
    "Category Name",
    "Action Name",
    "ID",
    "Path",
    "Process Name",
    "Old Value",
    "New Value",
];
/// Fields kept only as a SHA-256 digest (`<name>_sha256`).
const HASHED_FIELDS: &[&str] = &["CommandLine", "ParentCommandLine"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventEnvelope {
    pub schema_version: u32,
    /// Stable id for de-duplication across re-reads: channel + record id + provider + event id + time.
    pub event_uid: String,
    pub source: String,
    pub channel: String,
    pub source_record_id: u64,
    pub event_id: u32,
    pub occurred_at: String,
    pub occurred_at_unix_ms: Option<i64>,
    pub observed_at_unix_ms: u64,
    pub process_guid: Option<String>,
    pub pid: Option<u32>,
    pub process_start: Option<String>,
    pub parent_guid: Option<String>,
    pub artifact_hash: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub dns_name: Option<String>,
    pub payload_redacted: BTreeMap<String, String>,
    /// `complete`, `redacted` (fields dropped) or `oversized` (not parsed).
    pub completeness: String,
    pub dropped_fields: usize,
}

impl EventEnvelope {
    #[cfg(test)]
    pub fn field(&self, name: &str) -> Option<&str> {
        self.payload_redacted.get(name).map(String::as_str)
    }
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse `YYYY-MM-DD[T ]hh:mm:ss[.fraction][Z]` as UTC milliseconds.
pub fn parse_utc_ms(text: &str) -> Option<i64> {
    let t = text.trim().trim_end_matches('Z');
    let (date, time) = t.split_once(['T', ' '])?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, mo, da) = (d.next()??, d.next()??, d.next()??);
    let (hms, frac) = time.split_once('.').unwrap_or((time, "0"));
    let mut h = hms.split(':').map(|p| p.parse::<i64>().ok());
    let (hh, mm, ss) = (h.next()??, h.next()??, h.next()??);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let ms_digits: String = frac.chars().take(3).collect();
    let ms = format!("{ms_digits:0<3}").parse::<i64>().ok()?;
    Some(((days_from_civil(y, mo, da) * 24 + hh) * 60 + mm) * 60_000 + ss * 1000 + ms)
}

fn clip(value: String) -> String {
    if value.chars().count() > MAX_FIELD_CHARS {
        value.chars().take(MAX_FIELD_CHARS).collect()
    } else {
        value
    }
}

#[derive(Default)]
struct RawFields {
    provider: String,
    channel: String,
    event_id: Option<u32>,
    record_id: Option<u64>,
    time: String,
    data: Vec<(String, String)>,
}

fn attr(e: &quick_xml::events::BytesStart, name: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| {
            a.normalized_value(XmlVersion::Implicit1_0)
                .ok()
                .map(|v| v.into_owned())
        })
}

fn read_raw(xml: &str) -> Result<RawFields, String> {
    let mut reader = Reader::from_str(xml);
    let mut raw = RawFields::default();
    let mut path: Vec<Vec<u8>> = Vec::new();
    let mut data_name: Option<String> = None;
    let mut text = String::new();
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) => {
                let name = e.local_name().as_ref().to_vec();
                match name.as_slice() {
                    b"Provider" => raw.provider = attr(&e, b"Name").unwrap_or_default(),
                    b"TimeCreated" => raw.time = attr(&e, b"SystemTime").unwrap_or_default(),
                    b"Data" => data_name = Some(attr(&e, b"Name").unwrap_or_default()),
                    _ => {}
                }
                text.clear();
                path.push(name);
            }
            Event::Empty(e) => match e.local_name().as_ref() {
                b"Provider" => raw.provider = attr(&e, b"Name").unwrap_or_default(),
                b"TimeCreated" => raw.time = attr(&e, b"SystemTime").unwrap_or_default(),
                b"Data" => {
                    if let Some(name) = attr(&e, b"Name") {
                        raw.data.push((name, String::new()));
                    }
                }
                _ => {}
            },
            Event::Text(t) => text.push_str(&t.xml10_content().map_err(|e| e.to_string())?),
            Event::GeneralRef(r) => match r.resolve_char_ref().map_err(|e| e.to_string())? {
                Some(c) => text.push(c),
                None => {
                    let name = r.decode().map_err(|e| e.to_string())?;
                    text.push_str(match name.as_ref() {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => return Err(format!("unknown entity &{name};")),
                    });
                }
            },
            Event::End(_) => {
                let name = path.pop().unwrap_or_default();
                let in_system = path.last().is_some_and(|p| p.as_slice() == b"System");
                match (name.as_slice(), in_system) {
                    (b"EventID", true) => raw.event_id = text.trim().parse().ok(),
                    (b"EventRecordID", true) => raw.record_id = text.trim().parse().ok(),
                    (b"Channel", true) => raw.channel = text.trim().to_owned(),
                    (b"Data", _) => {
                        if let Some(name) = data_name.take() {
                            raw.data.push((name, std::mem::take(&mut text)));
                        }
                    }
                    _ => {}
                }
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(raw)
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Normalize one rendered event. Oversized XML yields an `oversized` envelope
/// that still records that an event existed (never a silent drop).
pub fn parse_event_xml(
    xml: &str,
    fallback_channel: &str,
    observed_at_unix_ms: u64,
) -> Result<EventEnvelope, String> {
    if xml.len() > MAX_EVENT_XML_BYTES {
        let digest = sha256_hex(xml);
        return Ok(EventEnvelope {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            event_uid: digest[..32].to_owned(),
            source: String::new(),
            channel: fallback_channel.to_owned(),
            source_record_id: 0,
            event_id: 0,
            occurred_at: String::new(),
            occurred_at_unix_ms: None,
            observed_at_unix_ms,
            process_guid: None,
            pid: None,
            process_start: None,
            parent_guid: None,
            artifact_hash: None,
            ip: None,
            port: None,
            dns_name: None,
            payload_redacted: BTreeMap::new(),
            completeness: "oversized".into(),
            dropped_fields: 0,
        });
    }
    let raw = read_raw(xml)?;
    let event_id = raw.event_id.ok_or("event has no EventID")?;
    let record_id = raw.record_id.ok_or("event has no EventRecordID")?;
    let channel = if raw.channel.is_empty() {
        fallback_channel.to_owned()
    } else {
        raw.channel
    };
    let mut payload = BTreeMap::new();
    let mut dropped = 0usize;
    for (name, value) in raw.data {
        if KEPT_FIELDS.contains(&name.as_str()) {
            payload.insert(name, clip(value));
        } else if HASHED_FIELDS.contains(&name.as_str()) {
            payload.insert(format!("{name}_sha256"), sha256_hex(&value));
        } else {
            dropped += 1;
        }
    }
    let get = |k: &str| payload.get(k).cloned().filter(|v| !v.is_empty());
    let sysmon = raw.provider == SYSMON_PROVIDER;
    let event_uid = sha256_hex(&format!(
        "{channel}\u{1f}{record_id}\u{1f}{}\u{1f}{event_id}\u{1f}{}",
        raw.provider, raw.time
    ))[..32]
        .to_owned();
    Ok(EventEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION,
        event_uid,
        occurred_at_unix_ms: parse_utc_ms(&raw.time),
        occurred_at: raw.time,
        source: raw.provider,
        channel,
        source_record_id: record_id,
        event_id,
        observed_at_unix_ms,
        process_guid: get("ProcessGuid").or_else(|| get("SourceProcessGuid")),
        pid: get("ProcessId").and_then(|p| p.parse().ok()),
        process_start: (sysmon && event_id == 1).then(|| get("UtcTime")).flatten(),
        parent_guid: get("ParentProcessGuid"),
        artifact_hash: get("Hashes"),
        ip: get("DestinationIp"),
        port: get("DestinationPort").and_then(|p| p.parse().ok()),
        dns_name: get("QueryName").or_else(|| get("DestinationHostname")),
        completeness: if dropped > 0 { "redacted" } else { "complete" }.into(),
        dropped_fields: dropped,
        payload_redacted: payload,
    })
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// Synthetic Sysmon-shaped event XML (harmless values, reserved addresses).
    pub fn sysmon(event_id: u32, record: u64, time: &str, data: &[(&str, &str)]) -> String {
        let fields: String = data
            .iter()
            .map(|(k, v)| format!("<Data Name='{k}'>{v}</Data>"))
            .collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Sysmon' Guid='{{5770385F-C22A-43E0-BF4C-06F5698FFBD9}}'/>\
             <EventID>{event_id}</EventID><Version>5</Version><TimeCreated SystemTime='{time}'/>\
             <EventRecordID>{record}</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>\
             <Computer>host.example.invalid</Computer></System><EventData>{fields}</EventData></Event>"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::sysmon;
    use super::*;

    #[test]
    fn sysmon_process_create_is_normalized_and_redacted() {
        let xml = sysmon(
            1,
            42,
            "2026-11-05T08:40:07.3824965Z",
            &[
                ("UtcTime", "2026-11-05 08:40:07.382"),
                ("ProcessGuid", "{AAAA-1}"),
                ("ProcessId", "4242"),
                ("Image", "C:\\Tools\\demo.exe"),
                ("CommandLine", "demo.exe --token SECRET-VALUE"),
                ("ParentProcessGuid", "{AAAA-0}"),
                ("User", "EXAMPLE\\alice"),
                ("Hashes", "SHA256=00ff"),
            ],
        );
        let e = parse_event_xml(&xml, "x", 7).unwrap();
        assert_eq!((e.event_id, e.source_record_id), (1, 42));
        assert_eq!(e.channel, "Microsoft-Windows-Sysmon/Operational");
        assert_eq!(e.process_guid.as_deref(), Some("{AAAA-1}"));
        assert_eq!(e.parent_guid.as_deref(), Some("{AAAA-0}"));
        assert_eq!(e.pid, Some(4242));
        assert_eq!(e.process_start.as_deref(), Some("2026-11-05 08:40:07.382"));
        assert_eq!(e.completeness, "redacted");
        assert_eq!(e.dropped_fields, 1);
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("SECRET-VALUE") && !json.contains("alice"));
        assert!(e.field("CommandLine_sha256").is_some());
        assert_eq!(
            e.occurred_at_unix_ms,
            parse_utc_ms("2026-11-05 08:40:07.382")
        );
    }

    #[test]
    fn network_and_dns_fields_map_to_envelope() {
        let net = sysmon(
            3,
            7,
            "2026-11-05T08:40:08Z",
            &[
                ("ProcessGuid", "{AAAA-1}"),
                ("DestinationIp", "192.0.2.10"),
                ("DestinationPort", "443"),
            ],
        );
        let e = parse_event_xml(&net, "x", 0).unwrap();
        assert_eq!((e.ip.as_deref(), e.port), (Some("192.0.2.10"), Some(443)));
        let dns = sysmon(
            22,
            8,
            "2026-11-05T08:40:09Z",
            &[("QueryName", "c2.example.invalid")],
        );
        assert_eq!(
            parse_event_xml(&dns, "x", 0).unwrap().dns_name.as_deref(),
            Some("c2.example.invalid")
        );
    }

    #[test]
    fn identical_events_share_a_uid_and_oversized_events_are_recorded() {
        let xml = sysmon(5, 9, "2026-11-05T08:41:00Z", &[("ProcessGuid", "{A}")]);
        assert_eq!(
            parse_event_xml(&xml, "x", 1).unwrap().event_uid,
            parse_event_xml(&xml, "x", 2).unwrap().event_uid
        );
        let big = format!("<Event>{}</Event>", "x".repeat(MAX_EVENT_XML_BYTES));
        let e = parse_event_xml(&big, "Security", 1).unwrap();
        assert_eq!(
            (e.completeness.as_str(), e.channel.as_str()),
            ("oversized", "Security")
        );
    }

    #[test]
    fn malformed_xml_is_an_error_not_an_empty_event() {
        assert!(parse_event_xml("<Event><System><EventID>1</Event>", "x", 0).is_err());
        assert!(parse_event_xml("<Event><System></System></Event>", "x", 0).is_err());
    }

    #[test]
    fn utc_parsing_matches_known_epochs() {
        assert_eq!(parse_utc_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc_ms("2000-03-01 00:00:00.5"), Some(951_868_800_500));
        assert_eq!(parse_utc_ms("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_utc_ms("garbage"), None);
    }
}
