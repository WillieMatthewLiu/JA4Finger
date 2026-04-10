use std::collections::{HashMap, VecDeque};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::capture::{CaptureSource, PacketRecord};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPacket {
    pub flow_key: FlowKey,
    pub payload: Vec<u8>,
    pub tcp_flags: Option<TcpFlags>,
    pub timestamp_secs: i64,
    pub timestamp_micros: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlowState {
    pub packet_count: u64,
    pub payload_bytes: usize,
    pub last_seen_secs: i64,
    pub last_seen_micros: i64,
}

pub struct SessionTracker {
    flows: HashMap<FlowKey, FlowState>,
    order: VecDeque<FlowKey>,
    max_flows: usize,
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::with_max_flows(4096)
    }
}

impl SessionTracker {
    pub fn with_max_flows(max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            order: VecDeque::new(),
            max_flows,
        }
    }

    pub fn observe(&mut self, packet: &DecodedPacket) {
        let is_new_flow = !self.flows.contains_key(&packet.flow_key);
        let state = self.flows.entry(packet.flow_key.clone()).or_default();
        state.packet_count += 1;
        state.payload_bytes += packet.payload.len();
        state.last_seen_secs = packet.timestamp_secs;
        state.last_seen_micros = packet.timestamp_micros;

        if is_new_flow {
            self.order.push_back(packet.flow_key.clone());
            self.evict_if_needed();
        }
    }

    pub fn flow(&self, key: &FlowKey) -> Option<&FlowState> {
        self.flows.get(key)
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    fn evict_if_needed(&mut self) {
        while self.flows.len() > self.max_flows {
            if let Some(oldest) = self.order.pop_front() {
                self.flows.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeCounters {
    pub packets_seen: u64,
    pub flows_tracked: usize,
    pub parse_failures: u64,
    pub extraction_failures: u64,
}

#[derive(Default)]
pub struct PipelineRuntime {
    tracker: SessionTracker,
    counters: RuntimeCounters,
}

impl PipelineRuntime {
    pub fn process_record(
        &mut self,
        record: &PacketRecord,
    ) -> Result<Option<DecodedPacket>, DecodeError> {
        self.counters.packets_seen += 1;

        match Pipeline::decode(record) {
            Ok(decoded) => {
                self.tracker.observe(&decoded);
                self.counters.flows_tracked = self.tracker.flow_count();
                Ok(Some(decoded))
            }
            Err(err) => {
                self.counters.parse_failures += 1;
                Err(err)
            }
        }
    }

    pub fn counters(&self) -> &RuntimeCounters {
        &self.counters
    }

    pub fn record_extraction_failure(&mut self) {
        self.counters.extraction_failures += 1;
    }
}

#[derive(Debug)]
pub enum DecodeError {
    Slice(String),
    MissingNetLayer,
    MissingTransportLayer,
    UnsupportedNetwork,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Slice(err) => write!(f, "{err}"),
            Self::MissingNetLayer => write!(f, "missing network layer"),
            Self::MissingTransportLayer => write!(f, "missing transport layer"),
            Self::UnsupportedNetwork => write!(f, "unsupported network layer"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    source: CaptureSource,
}

impl Pipeline {
    pub fn new(source: CaptureSource) -> Self {
        Self { source }
    }

    pub fn source(&self) -> &CaptureSource {
        &self.source
    }

    pub fn decode(record: &PacketRecord) -> Result<DecodedPacket, DecodeError> {
        let sliced = SlicedPacket::from_ethernet(&record.data)
            .map_err(|err| DecodeError::Slice(err.to_string()))?;

        let (src_ip, dst_ip) = match sliced.net.as_ref().ok_or(DecodeError::MissingNetLayer)? {
            NetSlice::Ipv4(ipv4) => (
                ipv4.header().source_addr().to_string(),
                ipv4.header().destination_addr().to_string(),
            ),
            NetSlice::Ipv6(ipv6) => (
                ipv6.header().source_addr().to_string(),
                ipv6.header().destination_addr().to_string(),
            ),
            NetSlice::Arp(_) => return Err(DecodeError::UnsupportedNetwork),
        };

        let (src_port, dst_port, protocol, payload, tcp_flags) = match sliced
            .transport
            .as_ref()
            .ok_or(DecodeError::MissingTransportLayer)?
        {
            TransportSlice::Tcp(tcp) => (
                tcp.source_port(),
                tcp.destination_port(),
                TransportProtocol::Tcp,
                tcp.payload().to_vec(),
                Some(TcpFlags {
                    syn: tcp.syn(),
                    fin: tcp.fin(),
                    rst: tcp.rst(),
                }),
            ),
            TransportSlice::Udp(udp) => (
                udp.source_port(),
                udp.destination_port(),
                TransportProtocol::Udp,
                udp.payload().to_vec(),
                None,
            ),
            _ => return Err(DecodeError::MissingTransportLayer),
        };

        Ok(DecodedPacket {
            flow_key: FlowKey {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
            },
            payload,
            tcp_flags,
            timestamp_secs: record.timestamp_secs,
            timestamp_micros: record.timestamp_micros,
        })
    }
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use crate::capture::PacketRecord;

    use super::{
        FlowKey, Pipeline, PipelineRuntime, SessionTracker, TcpFlags, TransportProtocol,
    };

    fn tcp_record(payload: &[u8]) -> PacketRecord {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
            .tcp(42424, 443, 1, 4096);

        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut packet, payload)
            .expect("packet should be serializable");

        PacketRecord {
            timestamp_secs: 100,
            timestamp_micros: 200,
            captured_len: packet.len() as u32,
            original_len: packet.len() as u32,
            data: packet,
        }
    }

    fn udp_record(payload: &[u8]) -> PacketRecord {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
            .udp(5353, 53);

        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut packet, payload)
            .expect("packet should be serializable");

        PacketRecord {
            timestamp_secs: 103,
            timestamp_micros: 500,
            captured_len: packet.len() as u32,
            original_len: packet.len() as u32,
            data: packet,
        }
    }

    fn tcp_syn_record() -> PacketRecord {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
            .tcp(42424, 443, 1, 4096)
            .syn();

        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).expect("packet should serialize");

        PacketRecord {
            timestamp_secs: 100,
            timestamp_micros: 200,
            captured_len: packet.len() as u32,
            original_len: packet.len() as u32,
            data: packet,
        }
    }

    fn tcp_fin_record() -> PacketRecord {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
            .tcp(42424, 443, 2, 4096)
            .fin();

        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).expect("packet should serialize");

        PacketRecord {
            timestamp_secs: 101,
            timestamp_micros: 300,
            captured_len: packet.len() as u32,
            original_len: packet.len() as u32,
            data: packet,
        }
    }

    fn tcp_rst_record() -> PacketRecord {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
            .tcp(42424, 443, 3, 4096)
            .rst();

        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).expect("packet should serialize");

        PacketRecord {
            timestamp_secs: 102,
            timestamp_micros: 400,
            captured_len: packet.len() as u32,
            original_len: packet.len() as u32,
            data: packet,
        }
    }

    #[test]
    fn decode_extracts_flow_key_and_payload_from_tcp_packet() {
        let record = tcp_record(b"GET / HTTP/1.1\r\n\r\n");

        let decoded = Pipeline::decode(&record).expect("packet should decode");

        assert_eq!(
            decoded.flow_key,
            FlowKey {
                src_ip: "192.168.1.10".into(),
                dst_ip: "192.168.1.20".into(),
                src_port: 42424,
                dst_port: 443,
                protocol: TransportProtocol::Tcp,
            }
        );
        assert_eq!(decoded.payload, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn session_tracker_groups_multiple_packets_into_same_flow() {
        let mut tracker = SessionTracker::default();
        let first = Pipeline::decode(&tcp_record(b"hello")).expect("first packet should decode");
        let second = Pipeline::decode(&tcp_record(b"world")).expect("second packet should decode");

        tracker.observe(&first);
        tracker.observe(&second);

        let state = tracker.flow(&first.flow_key).expect("flow should exist");
        assert_eq!(state.packet_count, 2);
        assert_eq!(state.payload_bytes, 10);
    }

    #[test]
    fn session_tracker_evicts_oldest_flow_when_capacity_is_exceeded() {
        let mut tracker = SessionTracker::with_max_flows(1);
        let first = Pipeline::decode(&tcp_record(b"first")).expect("first packet should decode");
        let mut second_record = tcp_record(b"second");
        second_record.data[26] = 10;
        second_record.data[30] = 30;
        let second = Pipeline::decode(&second_record).expect("second packet should decode");

        tracker.observe(&first);
        tracker.observe(&second);

        assert!(
            tracker.flow(&first.flow_key).is_none(),
            "oldest flow should be evicted"
        );
        assert!(
            tracker.flow(&second.flow_key).is_some(),
            "newest flow should be retained"
        );
    }

    #[test]
    fn runtime_counts_parse_failures_for_invalid_packets() {
        let mut runtime = PipelineRuntime::default();
        let invalid = PacketRecord {
            timestamp_secs: 1,
            timestamp_micros: 2,
            captured_len: 3,
            original_len: 3,
            data: vec![1, 2, 3],
        };

        let result = runtime.process_record(&invalid);

        assert!(result.is_err(), "invalid packet should return an error");
        assert_eq!(runtime.counters().packets_seen, 1);
        assert_eq!(runtime.counters().parse_failures, 1);
    }

    #[test]
    fn lifecycle_decode_extracts_tcp_flags_for_syn_fin_and_rst_packets() {
        let syn = Pipeline::decode(&tcp_syn_record()).expect("syn packet should decode");
        let fin = Pipeline::decode(&tcp_fin_record()).expect("fin packet should decode");
        let rst = Pipeline::decode(&tcp_rst_record()).expect("rst packet should decode");

        assert_eq!(
            syn.tcp_flags,
            Some(TcpFlags {
                syn: true,
                fin: false,
                rst: false,
            })
        );
        assert_eq!(
            fin.tcp_flags,
            Some(TcpFlags {
                syn: false,
                fin: true,
                rst: false,
            })
        );
        assert_eq!(
            rst.tcp_flags,
            Some(TcpFlags {
                syn: false,
                fin: false,
                rst: true,
            })
        );
    }

    #[test]
    fn lifecycle_decode_extracts_tcp_flags_for_non_lifecycle_tcp_packet() {
        let decoded = Pipeline::decode(&tcp_record(b"ping")).expect("tcp packet should decode");

        assert_eq!(
            decoded.tcp_flags,
            Some(TcpFlags {
                syn: false,
                fin: false,
                rst: false,
            })
        );
    }

    #[test]
    fn lifecycle_decode_sets_tcp_flags_none_for_udp_packets() {
        let decoded = Pipeline::decode(&udp_record(b"dns")).expect("udp packet should decode");

        assert_eq!(decoded.tcp_flags, None);
    }
}
