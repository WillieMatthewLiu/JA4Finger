use std::collections::{HashMap, HashSet};

use crate::fingerprint::FingerprintKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintEvent {
    pub timestamp_micros: i64,
    pub src: String,
    pub dst: String,
    pub kind: FingerprintKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregateEvent {
    Fingerprint(FingerprintEvent),
    Lifecycle(LifecycleEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEventKind {
    Open,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleFlag {
    Syn,
    Fin,
    Rst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub timestamp_micros: i64,
    pub src: String,
    pub dst: String,
    pub kind: LifecycleEventKind,
    pub flag: LifecycleFlag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateRecord {
    pub anchor_timestamp_micros: i64,
    pub src: String,
    pub dst: String,
    pub ja4: String,
    pub ja4h: String,
    pub ja4t: String,
}

impl AggregateRecord {
    pub fn render(&self) -> String {
        format!(
            "anchor_ts={} src={} dst={} ja4={} ja4h={} ja4t={}",
            render_timestamp_micros(self.anchor_timestamp_micros),
            self.src,
            self.dst,
            self.ja4,
            self.ja4h,
            self.ja4t
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct CanonicalConnectionKey {
    endpoint_a: String,
    endpoint_b: String,
}

impl CanonicalConnectionKey {
    fn from_endpoints(src: &str, dst: &str) -> Self {
        if src <= dst {
            Self {
                endpoint_a: src.to_string(),
                endpoint_b: dst.to_string(),
            }
        } else {
            Self {
                endpoint_a: dst.to_string(),
                endpoint_b: src.to_string(),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    connection: CanonicalConnectionKey,
    fingerprints: Vec<FingerprintEvent>,
}

pub fn parse_fingerprint_events(input: &str) -> Result<Vec<FingerprintEvent>, String> {
    Ok(parse_aggregate_events(input)?
        .into_iter()
        .filter_map(|event| match event {
            AggregateEvent::Fingerprint(event) => Some(event),
            AggregateEvent::Lifecycle(_) => None,
        })
        .collect())
}

pub fn parse_aggregate_events(input: &str) -> Result<Vec<AggregateEvent>, String> {
    let mut events = Vec::new();

    for line in input.lines() {
        if line.trim().is_empty() {
            continue;
        }

        if let Some(event) = parse_aggregate_event(line)? {
            events.push(event);
        }
    }

    Ok(events)
}

fn parse_aggregate_event(line: &str) -> Result<Option<AggregateEvent>, String> {
    let mut ts = None;
    let mut event_name = None;
    let mut flags = None;
    let mut kind = None;
    let mut value = None;
    let mut src = None;
    let mut dst = None;

    for token in line.split_whitespace() {
        let Some((key, raw_value)) = token.split_once('=') else {
            continue;
        };

        match key {
            "ts" => ts = Some(parse_timestamp_micros(raw_value)?),
            "event" => event_name = Some(raw_value),
            "flags" => flags = Some(raw_value),
            "kind" => {
                kind = Some(raw_value)
            }
            "value" => value = Some(raw_value.to_string()),
            "src" => src = Some(raw_value.to_string()),
            "dst" => dst = Some(raw_value.to_string()),
            _ => {}
        }
    }

    let Some(timestamp_micros) = ts else {
        return Ok(None);
    };

    if let Some(kind) = kind {
        let kind = match kind {
            "ja4" => FingerprintKind::Ja4,
            "ja4h" => FingerprintKind::Ja4H,
            "ja4t" => FingerprintKind::Ja4T,
            _ => return Ok(None),
        };
        let Some(value) = value else {
            return Ok(None);
        };
        let Some(src) = src else {
            return Ok(None);
        };
        let Some(dst) = dst else {
            return Ok(None);
        };

        return Ok(Some(AggregateEvent::Fingerprint(FingerprintEvent {
            timestamp_micros,
            src,
            dst,
            kind,
            value,
        })));
    }

    if let Some(event_name) = event_name {
        let kind = match event_name {
            "tcp_open" => LifecycleEventKind::Open,
            "tcp_close" => LifecycleEventKind::Close,
            _ => return Ok(None),
        };
        let flag = match flags {
            Some("syn") => LifecycleFlag::Syn,
            Some("fin") => LifecycleFlag::Fin,
            Some("rst") => LifecycleFlag::Rst,
            _ => return Ok(None),
        };
        let Some(src) = src else {
            return Ok(None);
        };
        let Some(dst) = dst else {
            return Ok(None);
        };

        let accepted = matches!(
            (kind, flag),
            (LifecycleEventKind::Open, LifecycleFlag::Syn)
                | (LifecycleEventKind::Close, LifecycleFlag::Fin)
                | (LifecycleEventKind::Close, LifecycleFlag::Rst)
        );
        if !accepted {
            return Ok(None);
        }

        return Ok(Some(AggregateEvent::Lifecycle(LifecycleEvent {
            timestamp_micros,
            src,
            dst,
            kind,
            flag,
        })));
    }

    Ok(None)
}

fn correlate_segment(segment: Segment) -> Vec<AggregateRecord> {
    let mut records = Vec::new();

    for (anchor_idx, anchor) in segment.fingerprints.iter().enumerate() {
        if anchor.kind != FingerprintKind::Ja4 {
            continue;
        }

        let mut seen_ja4h = HashSet::new();
        let mut seen_ja4t = HashSet::new();

        for candidate in segment.fingerprints.iter().skip(anchor_idx + 1) {
            match candidate.kind {
                FingerprintKind::Ja4H => {
                    if seen_ja4h.insert(candidate.value.clone()) {
                        records.push(AggregateRecord {
                            anchor_timestamp_micros: anchor.timestamp_micros,
                            src: anchor.src.clone(),
                            dst: anchor.dst.clone(),
                            ja4: anchor.value.clone(),
                            ja4h: candidate.value.clone(),
                            ja4t: String::new(),
                        });
                    }
                }
                FingerprintKind::Ja4T => {
                    if seen_ja4t.insert(candidate.value.clone()) {
                        records.push(AggregateRecord {
                            anchor_timestamp_micros: anchor.timestamp_micros,
                            src: anchor.src.clone(),
                            dst: anchor.dst.clone(),
                            ja4: anchor.value.clone(),
                            ja4h: String::new(),
                            ja4t: candidate.value.clone(),
                        });
                    }
                }
                FingerprintKind::Ja4 => {}
            }
        }
    }

    records
}

pub fn correlate_events(events: Vec<AggregateEvent>) -> Vec<AggregateRecord> {
    let mut active_segments = HashMap::<CanonicalConnectionKey, Segment>::new();
    let mut finished_segments = Vec::new();

    for event in events {
        match event {
            AggregateEvent::Lifecycle(event) => {
                let key = CanonicalConnectionKey::from_endpoints(&event.src, &event.dst);

                match event.kind {
                    LifecycleEventKind::Open => {
                        if let Some(previous) = active_segments.insert(
                            key.clone(),
                            Segment {
                                connection: key,
                                fingerprints: Vec::new(),
                            },
                        ) {
                            finished_segments.push(previous);
                        }
                    }
                    LifecycleEventKind::Close => {
                        if let Some(segment) = active_segments.remove(&key) {
                            finished_segments.push(segment);
                        }
                    }
                }
            }
            AggregateEvent::Fingerprint(event) => {
                let key = CanonicalConnectionKey::from_endpoints(&event.src, &event.dst);
                active_segments
                    .entry(key.clone())
                    .or_insert_with(|| Segment {
                        connection: key,
                        fingerprints: Vec::new(),
                    })
                    .fingerprints
                    .push(event);
            }
        }
    }

    finished_segments.extend(active_segments.into_values());

    let mut records = finished_segments
        .into_iter()
        .flat_map(correlate_segment)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.anchor_timestamp_micros
            .cmp(&right.anchor_timestamp_micros)
            .then_with(|| left.src.cmp(&right.src))
            .then_with(|| left.dst.cmp(&right.dst))
            .then_with(|| left.ja4.cmp(&right.ja4))
            .then_with(|| left.ja4h.cmp(&right.ja4h))
            .then_with(|| left.ja4t.cmp(&right.ja4t))
    });
    records
}

pub fn aggregate_text(input: &str) -> Result<Vec<AggregateRecord>, String> {
    let events = parse_aggregate_events(input)?;
    Ok(correlate_events(events))
}

fn parse_timestamp_micros(value: &str) -> Result<i64, String> {
    let (secs_str, frac_str) = match value.split_once('.') {
        Some(parts) => parts,
        None => (value, "0"),
    };

    let secs = secs_str
        .parse::<i64>()
        .map_err(|err| format!("invalid ts seconds `{value}`: {err}"))?;
    let mut frac = frac_str.chars().take(6).collect::<String>();
    while frac.len() < 6 {
        frac.push('0');
    }
    let micros = frac
        .parse::<i64>()
        .map_err(|err| format!("invalid ts micros `{value}`: {err}"))?;

    Ok(secs.saturating_mul(1_000_000).saturating_add(micros))
}

fn render_timestamp_micros(value: i64) -> String {
    let secs = value.div_euclid(1_000_000);
    let micros = value.rem_euclid(1_000_000);
    format!("{secs}.{micros:06}")
}

#[cfg(test)]
mod tests {
    use super::{aggregate_text, parse_aggregate_events, parse_fingerprint_events};

    #[test]
    fn parse_fingerprint_events_skips_lifecycle_and_summary_lines() {
        let input = "\
mode=daemon status=ready iface=eth0
ts=1.000000 mode=daemon kind=ja4 value=ja4-a src=1.1.1.1:1111 dst=2.2.2.2:443
mode=daemon packets_seen=1 flows_tracked=1 fingerprints_emitted=1 parse_failures=0 extraction_failures=0
";

        let events = parse_fingerprint_events(input).expect("parse should succeed");

        assert_eq!(events.len(), 1, "only fingerprint line should be retained");
        assert_eq!(events[0].value, "ja4-a");
    }

    #[test]
    fn aggregate_text_requires_ja4_anchor_and_deduplicates_matching_values() {
        let input = "\
ts=10.000000 mode=pcap kind=ja4 value=ja4-a src=1.1.1.1:1111 dst=2.2.2.2:443
ts=11.000000 mode=pcap kind=ja4h value=ja4h-a src=1.1.1.1:1111 dst=2.2.2.2:443
ts=12.000000 mode=pcap kind=ja4h value=ja4h-a src=1.1.1.1:1111 dst=2.2.2.2:443
ts=13.000000 mode=pcap kind=ja4t value=ja4t-a src=1.1.1.1:1111 dst=2.2.2.2:443
ts=14.000000 mode=pcap kind=ja4t value=ja4t-a src=1.1.1.1:1111 dst=2.2.2.2:443
ts=15.000000 mode=pcap kind=ja4h value=other src=9.9.9.9:9999 dst=2.2.2.2:443
";

        let records = aggregate_text(input).expect("aggregation should succeed");
        let rendered = records
            .iter()
            .map(|record| record.render())
            .collect::<Vec<_>>();

        assert_eq!(
            records.len(),
            2,
            "duplicate matches should collapse per anchor"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("ja4=ja4-a ja4h=ja4h-a ja4t=")),
            "expected JA4 plus JA4H record: {rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("ja4=ja4-a ja4h= ja4t=ja4t-a")),
            "expected JA4 plus JA4T record: {rendered:?}"
        );
    }

    #[test]
    fn aggregate_text_groups_by_tcp_session_without_time_window() {
        let input = "\
ts=20.000000 mode=pcap kind=ja4 value=ja4-b src=1.1.1.1:1111 dst=2.2.2.2:443
ts=35.000000 mode=pcap kind=ja4t value=same-session-ja4t src=1.1.1.1:1111 dst=2.2.2.2:443
ts=40.000000 mode=pcap kind=ja4h value=other-session-ja4h src=3.3.3.3:3333 dst=4.4.4.4:80
";

        let records = aggregate_text(input).expect("aggregation should succeed");
        let rendered = records
            .iter()
            .map(|record| record.render())
            .collect::<Vec<_>>();

        assert_eq!(
            records.len(),
            1,
            "same TCP session should correlate even when timestamps are far apart"
        );
        assert!(
            rendered
                .iter()
                .any(|line| line.contains("ja4=ja4-b ja4h= ja4t=same-session-ja4t")),
            "expected JA4 plus JA4T record from the same TCP session: {rendered:?}"
        );
        assert!(
            !rendered.iter().any(|line| line.contains("other-session-ja4h")),
            "different TCP sessions must not be merged: {rendered:?}"
        );
    }

    #[test]
    fn lifecycle_aggregate_text_parses_fingerprint_and_tcp_events() {
        let input = "\
 ts=10.000000 mode=pcap event=tcp_open flags=syn src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=10.100000 mode=pcap kind=ja4 value=ja4-a src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=10.200000 mode=pcap event=tcp_close flags=fin src=2.2.2.2:443 dst=1.1.1.1:1111
";

        let events = parse_aggregate_events(input).expect("event parse should succeed");

        assert_eq!(events.len(), 3, "expected one open, one fingerprint, one close");
    }

    #[test]
    fn lifecycle_aggregate_text_separates_reconnections_by_syn_and_fin() {
        let input = "\
 ts=1.000000 mode=pcap event=tcp_open flags=syn src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=1.100000 mode=pcap kind=ja4 value=ja4-a src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=1.200000 mode=pcap event=tcp_close flags=fin src=2.2.2.2:443 dst=1.1.1.1:1111
 ts=2.000000 mode=pcap event=tcp_open flags=syn src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=2.100000 mode=pcap kind=ja4h value=ja4h-b src=1.1.1.1:1111 dst=2.2.2.2:443
";

        let records = aggregate_text(input).expect("aggregation should succeed");

        assert!(
            records.is_empty(),
            "ja4 and ja4h from different lifecycle segments must not correlate"
        );
    }

    #[test]
    fn lifecycle_aggregate_text_uses_reverse_fin_to_close_current_segment() {
        let input = "\
 ts=1.000000 mode=pcap event=tcp_open flags=syn src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=1.100000 mode=pcap kind=ja4 value=ja4-a src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=1.200000 mode=pcap kind=ja4h value=ja4h-a src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=1.300000 mode=pcap event=tcp_close flags=fin src=2.2.2.2:443 dst=1.1.1.1:1111
 ts=2.000000 mode=pcap kind=ja4t value=late-ja4t src=1.1.1.1:1111 dst=2.2.2.2:443
";

        let rendered = aggregate_text(input)
            .expect("aggregation should succeed")
            .into_iter()
            .map(|record| record.render())
            .collect::<Vec<_>>();

        assert_eq!(rendered.len(), 1, "only the first segment should produce a record");
        assert!(
            rendered[0].contains("ja4=ja4-a ja4h=ja4h-a ja4t="),
            "expected ja4 plus ja4h: {rendered:?}"
        );
        assert!(
            !rendered.iter().any(|line| line.contains("late-ja4t")),
            "late ja4t must stay out of the closed segment: {rendered:?}"
        );
    }

    #[test]
    fn lifecycle_aggregate_text_uses_reverse_rst_to_close_current_segment() {
        let input = "\
 ts=1.000000 mode=pcap event=tcp_open flags=syn src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=1.100000 mode=pcap kind=ja4 value=ja4-a src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=1.200000 mode=pcap event=tcp_close flags=rst src=2.2.2.2:443 dst=1.1.1.1:1111
 ts=2.000000 mode=pcap kind=ja4h value=late-ja4h src=1.1.1.1:1111 dst=2.2.2.2:443
";

        let records = aggregate_text(input).expect("aggregation should succeed");

        assert!(
            records.is_empty(),
            "reverse rst should close the current segment before late ja4h arrives"
        );
    }

    #[test]
    fn lifecycle_aggregate_text_does_not_attach_pre_anchor_fingerprints_to_ja4() {
        let input = "\
 ts=1.000000 mode=pcap kind=ja4h value=early-ja4h src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=2.000000 mode=pcap kind=ja4 value=ja4-a src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=3.000000 mode=pcap kind=ja4t value=late-ja4t src=1.1.1.1:1111 dst=2.2.2.2:443
";

        let rendered = aggregate_text(input)
            .expect("aggregation should succeed")
            .into_iter()
            .map(|record| record.render())
            .collect::<Vec<_>>();

        assert_eq!(rendered.len(), 1, "only the post-anchor ja4t should correlate");
        assert!(
            rendered[0].contains("ja4=ja4-a ja4h= ja4t=late-ja4t"),
            "expected only post-anchor ja4t: {rendered:?}"
        );
        assert!(
            !rendered.iter().any(|line| line.contains("early-ja4h")),
            "pre-anchor ja4h must not correlate: {rendered:?}"
        );
    }

    #[test]
    fn lifecycle_aggregate_text_keeps_close_before_reopen_when_timestamps_match() {
        let input = "\
 ts=1.000000 mode=pcap event=tcp_open flags=syn src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=1.000000 mode=pcap kind=ja4 value=ja4-a src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=1.000000 mode=pcap event=tcp_close flags=fin src=2.2.2.2:443 dst=1.1.1.1:1111
 ts=1.000000 mode=pcap event=tcp_open flags=syn src=1.1.1.1:1111 dst=2.2.2.2:443
 ts=1.000000 mode=pcap kind=ja4h value=ja4h-b src=1.1.1.1:1111 dst=2.2.2.2:443
";

        let records = aggregate_text(input).expect("aggregation should succeed");

        assert!(
            records.is_empty(),
            "close and reopen events at the same timestamp must still respect text order"
        );
    }
}
