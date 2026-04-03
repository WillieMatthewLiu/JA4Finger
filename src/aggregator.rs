use std::collections::HashSet;

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
pub struct AggregateRecord {
    pub anchor_timestamp_micros: i64,
    pub window_secs: u64,
    pub src: String,
    pub dst: String,
    pub ja4: String,
    pub ja4h: String,
    pub ja4t: String,
}

impl AggregateRecord {
    pub fn render(&self) -> String {
        format!(
            "anchor_ts={} window_secs={} src={} dst={} ja4={} ja4h={} ja4t={}",
            render_timestamp_micros(self.anchor_timestamp_micros),
            self.window_secs,
            self.src,
            self.dst,
            self.ja4,
            self.ja4h,
            self.ja4t
        )
    }
}

pub fn parse_fingerprint_events(input: &str) -> Result<Vec<FingerprintEvent>, String> {
    let mut events = Vec::new();

    for (line_no, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        match parse_fingerprint_event(line)? {
            Some(event) => events.push(event),
            None => {
                let _ = line_no;
            }
        }
    }

    Ok(events)
}

fn parse_fingerprint_event(line: &str) -> Result<Option<FingerprintEvent>, String> {
    let mut ts = None;
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
            "kind" => {
                kind = Some(match raw_value {
                    "ja4" => FingerprintKind::Ja4,
                    "ja4h" => FingerprintKind::Ja4H,
                    "ja4t" => FingerprintKind::Ja4T,
                    _ => return Ok(None),
                })
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
    let Some(kind) = kind else {
        return Ok(None);
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

    Ok(Some(FingerprintEvent {
        timestamp_micros,
        src,
        dst,
        kind,
        value,
    }))
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

pub fn correlate_events(
    mut events: Vec<FingerprintEvent>,
    window_secs: u64,
) -> Vec<AggregateRecord> {
    events.sort_by(|left, right| {
        left.src
            .cmp(&right.src)
            .then_with(|| left.dst.cmp(&right.dst))
            .then_with(|| left.timestamp_micros.cmp(&right.timestamp_micros))
            .then_with(|| left.kind.as_str().cmp(right.kind.as_str()))
            .then_with(|| left.value.cmp(&right.value))
    });

    let window_micros = (window_secs as i64).saturating_mul(1_000_000);
    let mut records = Vec::new();

    for (idx, anchor) in events.iter().enumerate() {
        if anchor.kind != FingerprintKind::Ja4 {
            continue;
        }

        let deadline = anchor.timestamp_micros.saturating_add(window_micros);
        let mut seen_ja4h = HashSet::new();
        let mut seen_ja4t = HashSet::new();

        for candidate in events.iter().skip(idx + 1) {
            if candidate.src != anchor.src || candidate.dst != anchor.dst {
                if candidate.src > anchor.src
                    || (candidate.src == anchor.src && candidate.dst > anchor.dst)
                {
                    break;
                }
                continue;
            }

            if candidate.timestamp_micros >= deadline {
                break;
            }

            if candidate.timestamp_micros < anchor.timestamp_micros {
                continue;
            }

            match candidate.kind {
                FingerprintKind::Ja4H => {
                    if seen_ja4h.insert(candidate.value.clone()) {
                        records.push(AggregateRecord {
                            anchor_timestamp_micros: anchor.timestamp_micros,
                            window_secs,
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
                            window_secs,
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

pub fn aggregate_text(input: &str, window_secs: u64) -> Result<Vec<AggregateRecord>, String> {
    let events = parse_fingerprint_events(input)?;
    Ok(correlate_events(events, window_secs))
}

#[cfg(test)]
mod tests {
    use super::{aggregate_text, parse_fingerprint_events};

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

        let records = aggregate_text(input, 10).expect("aggregation should succeed");
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
    fn aggregate_text_excludes_out_of_window_and_missing_ja4_pairs() {
        let input = "\
ts=20.000000 mode=pcap kind=ja4 value=ja4-b src=1.1.1.1:1111 dst=2.2.2.2:443
ts=35.000000 mode=pcap kind=ja4t value=too-late src=1.1.1.1:1111 dst=2.2.2.2:443
ts=40.000000 mode=pcap kind=ja4h value=missing-anchor src=3.3.3.3:3333 dst=4.4.4.4:80
";

        let records = aggregate_text(input, 10).expect("aggregation should succeed");

        assert!(
            records.is_empty(),
            "out-of-window and missing-anchor matches should be excluded"
        );
    }
}
