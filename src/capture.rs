use std::fs::File;
use std::io::BufReader;
use std::io::ErrorKind;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pcap_file::pcap::{PcapPacket, PcapReader};
use pnet_datalink::{self, Channel, Config, DataLinkReceiver};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureSource {
    Interface(String),
    PcapFile(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketRecord {
    pub timestamp_secs: i64,
    pub timestamp_micros: i64,
    pub captured_len: u32,
    pub original_len: u32,
    pub data: Vec<u8>,
}

impl From<PcapPacket<'_>> for PacketRecord {
    fn from(packet: PcapPacket<'_>) -> Self {
        Self {
            timestamp_secs: packet.timestamp.as_secs() as i64,
            timestamp_micros: packet.timestamp.subsec_micros() as i64,
            captured_len: packet.data.len() as u32,
            original_len: packet.orig_len,
            data: packet.data.into_owned(),
        }
    }
}

enum CaptureHandle {
    Live(Box<dyn DataLinkReceiver>),
    Offline(PcapReader<BufReader<File>>),
}

#[derive(Debug)]
pub enum CaptureError {
    InterfaceNotFound(String),
    Io(std::io::Error),
    Pcap(String),
    UnsupportedChannel,
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InterfaceNotFound(iface) => write!(f, "interface not found: {iface}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Pcap(err) => write!(f, "{err}"),
            Self::UnsupportedChannel => write!(f, "unsupported datalink channel type"),
        }
    }
}

impl std::error::Error for CaptureError {}

impl From<std::io::Error> for CaptureError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

pub struct CaptureAdapter {
    source: CaptureSource,
    handle: Option<CaptureHandle>,
}

const LIVE_READ_TIMEOUT: Duration = Duration::from_millis(50);

impl CaptureAdapter {
    pub fn from_source(source: CaptureSource) -> Self {
        Self {
            source,
            handle: None,
        }
    }

    pub fn open(mut self) -> Result<Self, CaptureError> {
        let handle = match &self.source {
            CaptureSource::Interface(iface) => {
                let interface = pnet_datalink::interfaces()
                    .into_iter()
                    .find(|candidate| candidate.name == *iface)
                    .ok_or_else(|| CaptureError::InterfaceNotFound(iface.clone()))?;
                let mut config = Config::default();
                config.read_timeout = Some(LIVE_READ_TIMEOUT);

                match pnet_datalink::channel(&interface, config) {
                    Ok(Channel::Ethernet(_, receiver)) => CaptureHandle::Live(receiver),
                    Ok(_) => return Err(CaptureError::UnsupportedChannel),
                    Err(err) => return Err(CaptureError::Io(err)),
                }
            }
            CaptureSource::PcapFile(path) => {
                let file =
                    File::open(path).map_err(|err| CaptureError::Pcap(format!("{path}: {err}")))?;
                let reader = PcapReader::new(BufReader::new(file))
                    .map_err(|err| CaptureError::Pcap(err.to_string()))?;
                CaptureHandle::Offline(reader)
            }
        };

        self.handle = Some(handle);
        Ok(self)
    }

    pub fn source(&self) -> &CaptureSource {
        &self.source
    }

    pub fn next_record(&mut self) -> Result<Option<PacketRecord>, CaptureError> {
        let handle = self
            .handle
            .as_mut()
            .expect("capture adapter must be opened before reading packets");

        match handle {
            CaptureHandle::Live(receiver) => match receiver.next() {
                Ok(packet) => {
                    let data = packet.to_vec();
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_else(|_| Duration::from_secs(0));

                    Ok(Some(PacketRecord {
                        timestamp_secs: timestamp.as_secs() as i64,
                        timestamp_micros: timestamp.subsec_micros() as i64,
                        captured_len: data.len() as u32,
                        original_len: data.len() as u32,
                        data,
                    }))
                }
                Err(err) if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                    Ok(None)
                }
                Err(err) => Err(CaptureError::Io(err)),
            },
            CaptureHandle::Offline(reader) => match reader.next_packet() {
                Some(Ok(packet)) => Ok(Some(PacketRecord::from(packet))),
                Some(Err(err)) => Err(CaptureError::Pcap(err.to_string())),
                None => Ok(None),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pcap_file::pcap::PcapPacket;

    use super::{CaptureAdapter, CaptureSource, PacketRecord};

    #[test]
    fn packet_record_copies_pcap_packet_fields() {
        let packet = PcapPacket::new_owned(Duration::new(42, 123_456_000), 5, vec![1, 2, 3]);

        let record = PacketRecord::from(packet);

        assert_eq!(record.timestamp_secs, 42);
        assert_eq!(record.timestamp_micros, 123_456);
        assert_eq!(record.captured_len, 3);
        assert_eq!(record.original_len, 5);
        assert_eq!(record.data, vec![1, 2, 3]);
    }

    #[test]
    fn adapter_reports_configured_source() {
        let source = CaptureSource::PcapFile("fixtures/sample.pcap".to_owned());
        let adapter = CaptureAdapter::from_source(source.clone());

        assert_eq!(adapter.source(), &source);
    }
}
