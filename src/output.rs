use crate::capture::PacketRecord;
use crate::fingerprint::FingerprintKind;
use crate::pipeline::{DecodedPacket, RuntimeCounters};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeMode {
    Daemon,
    Pcap,
}

impl RuntimeMode {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Pcap => "pcap",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintEmission {
    pub timestamp_secs: i64,
    pub timestamp_micros: i64,
    pub mode: RuntimeMode,
    pub kind: FingerprintKind,
    pub value: String,
    pub src_endpoint: String,
    pub dst_endpoint: String,
}

impl FingerprintEmission {
    fn format_endpoint(ip: &str, port: u16) -> String {
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => format!("[{ip}]:{port}"),
            _ => format!("{ip}:{port}"),
        }
    }

    pub fn from_packet_context(
        record: &PacketRecord,
        decoded: &DecodedPacket,
        mode: RuntimeMode,
        kind: FingerprintKind,
        value: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_secs: record.timestamp_secs,
            timestamp_micros: record.timestamp_micros,
            mode,
            kind,
            value: value.into(),
            src_endpoint: Self::format_endpoint(
                &decoded.flow_key.src_ip,
                decoded.flow_key.src_port,
            ),
            dst_endpoint: Self::format_endpoint(
                &decoded.flow_key.dst_ip,
                decoded.flow_key.dst_port,
            ),
        }
    }

    pub fn render(&self) -> String {
        format!(
            "ts={}.{:06} mode={} kind={} value={} src={} dst={}",
            self.timestamp_secs,
            self.timestamp_micros,
            self.mode.as_str(),
            self.kind.as_str(),
            self.value,
            self.src_endpoint,
            self.dst_endpoint
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryReport {
    pub mode: RuntimeMode,
    pub counters: RuntimeCounters,
    pub fingerprints_emitted: u64,
}

impl SummaryReport {
    pub fn render(&self) -> String {
        format!(
            "mode={} packets_seen={} flows_tracked={} fingerprints_emitted={} parse_failures={} extraction_failures={}",
            self.mode.as_str(),
            self.counters.packets_seen,
            self.counters.flows_tracked,
            self.fingerprints_emitted,
            self.counters.parse_failures,
            self.counters.extraction_failures
        )
    }
}

pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use crate::capture::PacketRecord;
    use crate::fingerprint::FingerprintKind;
    use crate::pipeline::{DecodedPacket, FlowKey, RuntimeCounters, TransportProtocol};

    use super::{FingerprintEmission, RuntimeMode, SummaryReport};

    #[test]
    fn fingerprint_emission_renders_required_fields() {
        let emission = FingerprintEmission {
            timestamp_secs: 1710000000,
            timestamp_micros: 123456,
            mode: RuntimeMode::Pcap,
            kind: FingerprintKind::Ja4T,
            value: "64240_2-1-3-1-1-4_1460_8".into(),
            src_endpoint: "192.168.1.10:42424".into(),
            dst_endpoint: "192.168.1.20:443".into(),
        };

        let rendered = emission.render();

        assert!(
            rendered.contains("ts=1710000000.123456"),
            "missing timestamp: {rendered}"
        );
        assert!(rendered.contains("mode=pcap"), "missing mode: {rendered}");
        assert!(rendered.contains("kind=ja4t"), "missing kind: {rendered}");
        assert!(
            rendered.contains("value=64240_2-1-3-1-1-4_1460_8"),
            "missing value: {rendered}"
        );
        assert!(
            rendered.contains("src=192.168.1.10:42424"),
            "missing source endpoint: {rendered}"
        );
        assert!(
            rendered.contains("dst=192.168.1.20:443"),
            "missing destination endpoint: {rendered}"
        );
    }

    #[test]
    fn summary_report_renders_required_counters() {
        let summary = SummaryReport {
            mode: RuntimeMode::Daemon,
            counters: RuntimeCounters {
                packets_seen: 42,
                flows_tracked: 3,
                parse_failures: 1,
                extraction_failures: 2,
            },
            fingerprints_emitted: 7,
        };

        let rendered = summary.render();

        assert!(rendered.contains("mode=daemon"), "missing mode: {rendered}");
        assert!(
            rendered.contains("packets_seen=42"),
            "missing packets_seen: {rendered}"
        );
        assert!(
            rendered.contains("flows_tracked=3"),
            "missing flows_tracked: {rendered}"
        );
        assert!(
            rendered.contains("fingerprints_emitted=7"),
            "missing fingerprints_emitted: {rendered}"
        );
        assert!(
            rendered.contains("parse_failures=1"),
            "missing parse_failures: {rendered}"
        );
        assert!(
            rendered.contains("extraction_failures=2"),
            "missing extraction_failures: {rendered}"
        );
    }

    #[test]
    fn fingerprint_emission_from_packet_context_populates_required_fields() {
        let record = PacketRecord {
            timestamp_secs: 1710000001,
            timestamp_micros: 654321,
            captured_len: 10,
            original_len: 10,
            data: vec![],
        };
        let decoded = DecodedPacket {
            flow_key: FlowKey {
                src_ip: "10.0.0.1".into(),
                dst_ip: "10.0.0.2".into(),
                src_port: 12345,
                dst_port: 443,
                protocol: TransportProtocol::Tcp,
            },
            payload: vec![],
            timestamp_secs: 0,
            timestamp_micros: 0,
        };

        let emission = FingerprintEmission::from_packet_context(
            &record,
            &decoded,
            RuntimeMode::Pcap,
            FingerprintKind::Ja4,
            "t13d1516h2_8daaf6152771_02713d6af862",
        );

        assert_eq!(emission.timestamp_secs, 1710000001);
        assert_eq!(emission.timestamp_micros, 654321);
        assert_eq!(emission.mode, RuntimeMode::Pcap);
        assert_eq!(emission.kind, FingerprintKind::Ja4);
        assert_eq!(emission.value, "t13d1516h2_8daaf6152771_02713d6af862");
        assert_eq!(emission.src_endpoint, "10.0.0.1:12345");
        assert_eq!(emission.dst_endpoint, "10.0.0.2:443");
    }

    #[test]
    fn fingerprint_emission_from_packet_context_wraps_ipv6_endpoints_with_brackets() {
        let record = PacketRecord {
            timestamp_secs: 1710000002,
            timestamp_micros: 111222,
            captured_len: 10,
            original_len: 10,
            data: vec![],
        };
        let decoded = DecodedPacket {
            flow_key: FlowKey {
                src_ip: "2001:db8::10".into(),
                dst_ip: "2001:db8::20".into(),
                src_port: 12345,
                dst_port: 443,
                protocol: TransportProtocol::Tcp,
            },
            payload: vec![],
            timestamp_secs: 0,
            timestamp_micros: 0,
        };

        let emission = FingerprintEmission::from_packet_context(
            &record,
            &decoded,
            RuntimeMode::Pcap,
            FingerprintKind::Ja4,
            "t13d1516h2_8daaf6152771_02713d6af862",
        );

        assert_eq!(emission.src_endpoint, "[2001:db8::10]:12345");
        assert_eq!(emission.dst_endpoint, "[2001:db8::20]:443");
    }
}
