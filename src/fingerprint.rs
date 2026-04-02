use etherparse::{SlicedPacket, TcpOptionElement, TransportSlice};
use hpack::Decoder as HpackDecoder;
use sha2::{Digest, Sha256};
use tls_parser::{
    TlsExtension, TlsExtensionType, TlsMessage, TlsMessageHandshake,
    parse_tls_client_hello_extensions, parse_tls_plaintext,
};

use crate::capture::PacketRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintKind {
    Ja4,
    Ja4H,
    Ja4T,
}

impl FingerprintKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ja4 => "ja4",
            Self::Ja4H => "ja4h",
            Self::Ja4T => "ja4t",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpClientFeatures {
    pub window_size: u16,
    pub option_kinds: Vec<u8>,
    pub maximum_segment_size: u16,
    pub window_scale: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHelloFeatures {
    tls_version: &'static str,
    has_sni: bool,
    alpn_marker: String,
    ciphers: Vec<u16>,
    extension_types: Vec<u16>,
    signature_algorithms: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpClientFeatures {
    method: String,
    version_token: &'static str,
    has_cookie: bool,
    has_referer: bool,
    header_names: Vec<String>,
    language_token: String,
    cookie_names: Vec<String>,
    cookie_pairs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintError {
    Decode(String),
    NotTcp,
    NotSyn,
}

impl std::fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "{err}"),
            Self::NotTcp => write!(f, "packet is not tcp"),
            Self::NotSyn => write!(f, "packet is not a tcp syn"),
        }
    }
}

impl std::error::Error for FingerprintError {}

impl TcpClientFeatures {
    pub fn extract(record: &PacketRecord) -> Result<Self, FingerprintError> {
        let sliced = SlicedPacket::from_ethernet(&record.data)
            .map_err(|err| FingerprintError::Decode(err.to_string()))?;

        let tcp = match sliced.transport {
            Some(TransportSlice::Tcp(tcp)) => tcp,
            _ => return Err(FingerprintError::NotTcp),
        };

        if !tcp.syn() {
            return Err(FingerprintError::NotSyn);
        }

        let mut option_kinds = Vec::new();
        let mut maximum_segment_size = 0u16;
        let mut window_scale = 0u8;

        for option in tcp.options_iterator() {
            let option = option.map_err(|err| FingerprintError::Decode(err.to_string()))?;
            match option {
                TcpOptionElement::Noop => option_kinds.push(1),
                TcpOptionElement::MaximumSegmentSize(value) => {
                    option_kinds.push(2);
                    maximum_segment_size = value;
                }
                TcpOptionElement::WindowScale(value) => {
                    option_kinds.push(3);
                    window_scale = value;
                }
                TcpOptionElement::SelectiveAcknowledgementPermitted => option_kinds.push(4),
                TcpOptionElement::SelectiveAcknowledgement(_, _) => option_kinds.push(5),
                TcpOptionElement::Timestamp(_, _) => option_kinds.push(8),
            }
        }

        Ok(Self {
            window_size: tcp.window_size(),
            option_kinds,
            maximum_segment_size,
            window_scale,
        })
    }

    pub fn fingerprint_string(&self) -> String {
        let option_kinds = self
            .option_kinds
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-");

        format!(
            "{}_{}_{}_{}",
            self.window_size, option_kinds, self.maximum_segment_size, self.window_scale
        )
    }
}

impl HttpClientFeatures {
    pub fn extract(payload: &[u8]) -> Result<Self, FingerprintError> {
        if payload.starts_with(HTTP2_CLEAR_PREFACE) || looks_like_h2c_frames(payload) {
            return Self::extract_h2c(payload);
        }

        Self::extract_http1(payload)
    }

    pub fn fingerprint_string(&self) -> String {
        let method = token2(&self.method);
        let cookie_marker = if self.has_cookie { 'c' } else { 'n' };
        let referer_marker = if self.has_referer { 'r' } else { 'n' };
        let header_count = self.header_names.len().min(99);
        let headers_hash = hash12(&self.header_names.join(","));
        let cookies_hash = if self.cookie_names.is_empty() {
            ZERO_HASH_12.to_string()
        } else {
            hash12(&self.cookie_names.join(","))
        };
        let cookie_values_hash = if self.cookie_pairs.is_empty() {
            ZERO_HASH_12.to_string()
        } else {
            hash12(&self.cookie_pairs.join(","))
        };

        format!(
            "{method}{}{cookie_marker}{referer_marker}{header_count:02}{}_{}_{}_{}",
            self.version_token, self.language_token, headers_hash, cookies_hash, cookie_values_hash
        )
    }

    fn extract_http1(payload: &[u8]) -> Result<Self, FingerprintError> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
        let mut request = httparse::Request::new(&mut headers);

        let status = request
            .parse(payload)
            .map_err(|err| FingerprintError::Decode(format!("http/1 parse failed: {err}")))?;
        let consumed = match status {
            httparse::Status::Complete(consumed) => consumed,
            httparse::Status::Partial => {
                return Err(FingerprintError::Decode(
                    "http/1 request is incomplete".to_string(),
                ));
            }
        };

        let method = request
            .method
            .ok_or_else(|| FingerprintError::Decode("http/1 request method is missing".into()))?;
        let version = request
            .version
            .ok_or_else(|| FingerprintError::Decode("http/1 request version is missing".into()))?;
        let version_token = match version {
            0 | 1 => "11",
            _ => {
                return Err(FingerprintError::Decode(format!(
                    "unsupported http/1 version: {version}"
                )));
            }
        };

        let mut parsed_headers = Vec::new();
        for header in request.headers.iter() {
            let value = std::str::from_utf8(header.value)
                .map_err(|_| {
                    FingerprintError::Decode("http/1 header contains invalid utf-8".to_string())
                })?
                .to_string();
            parsed_headers.push((header.name.to_string(), value));
        }

        if is_h2c_upgrade_request_headers(&parsed_headers) {
            let remaining = &payload[consumed..];
            if !remaining.is_empty()
                && (remaining.starts_with(HTTP2_CLEAR_PREFACE) || looks_like_h2c_frames(remaining))
            {
                if let Ok(h2c_features) = Self::extract_h2c(remaining) {
                    return Ok(h2c_features);
                }
            }
        }

        Self::from_parts(method, version_token, parsed_headers)
    }

    fn extract_h2c(payload: &[u8]) -> Result<Self, FingerprintError> {
        let mut offset = 0usize;
        if payload.starts_with(HTTP2_CLEAR_PREFACE) {
            offset = HTTP2_CLEAR_PREFACE.len();
        }

        let mut decoder = HpackDecoder::new();

        while offset + HTTP2_FRAME_HEADER_LEN <= payload.len() {
            let length = ((payload[offset] as usize) << 16)
                | ((payload[offset + 1] as usize) << 8)
                | payload[offset + 2] as usize;
            let frame_type = payload[offset + 3];
            let flags = payload[offset + 4];
            let stream_id = u32::from_be_bytes([
                payload[offset + 5],
                payload[offset + 6],
                payload[offset + 7],
                payload[offset + 8],
            ]) & 0x7fff_ffff;
            offset += HTTP2_FRAME_HEADER_LEN;

            if offset + length > payload.len() {
                return Err(FingerprintError::Decode(
                    "h2c frame is truncated".to_string(),
                ));
            }

            let frame_payload = &payload[offset..offset + length];
            offset += length;

            if frame_type != HTTP2_FRAME_TYPE_HEADERS {
                continue;
            }
            if stream_id == 0 {
                return Err(FingerprintError::Decode(
                    "h2c HEADERS frame has stream id 0".to_string(),
                ));
            }
            if flags & HTTP2_FLAG_END_HEADERS == 0 {
                return Err(FingerprintError::Decode(
                    "h2c HEADERS continuation is not supported".to_string(),
                ));
            }

            let header_block = parse_h2_headers_fragment(frame_payload, flags)?;
            let decoded_headers = decoder
                .decode(header_block)
                .map_err(|err| FingerprintError::Decode(format!("hpack decode failed: {err:?}")))?;

            let mut method: Option<String> = None;
            let mut parsed_headers = Vec::new();
            for (name, value) in decoded_headers {
                let name = String::from_utf8(name).map_err(|_| {
                    FingerprintError::Decode("h2c header name contains invalid utf-8".to_string())
                })?;
                let value = String::from_utf8(value).map_err(|_| {
                    FingerprintError::Decode("h2c header value contains invalid utf-8".to_string())
                })?;

                if name.eq_ignore_ascii_case(":method") {
                    method = Some(value.clone());
                }
                parsed_headers.push((name, value));
            }

            let method = method
                .ok_or_else(|| FingerprintError::Decode("h2c :method header is missing".into()))?;
            return Self::from_parts(&method, "20", parsed_headers);
        }

        Err(FingerprintError::Decode(
            "h2c payload does not contain request headers".to_string(),
        ))
    }

    fn from_parts(
        method: &str,
        version_token: &'static str,
        parsed_headers: Vec<(String, String)>,
    ) -> Result<Self, FingerprintError> {
        let method = method.to_ascii_lowercase();
        if method.is_empty() {
            return Err(FingerprintError::Decode(
                "http request method is empty".to_string(),
            ));
        }

        let mut has_cookie = false;
        let mut has_referer = false;
        let mut header_names = Vec::new();
        let mut accept_language = None;
        let mut cookie_names = Vec::new();
        let mut cookie_pairs = Vec::new();

        for (raw_name, raw_value) in parsed_headers {
            let name = raw_name.to_ascii_lowercase();
            if name.starts_with(':') {
                continue;
            }
            if name == "cookie" {
                has_cookie = true;
                parse_cookie_values(&raw_value, &mut cookie_names, &mut cookie_pairs);
                continue;
            }
            if name == "referer" {
                has_referer = true;
                continue;
            }
            if name == "accept-language" && accept_language.is_none() {
                accept_language = Some(raw_value.to_ascii_lowercase());
            }
            header_names.push(name);
        }

        header_names.sort_unstable();
        cookie_names.sort_unstable();
        cookie_pairs.sort_unstable();

        Ok(Self {
            method,
            version_token,
            has_cookie,
            has_referer,
            header_names,
            language_token: language_token(accept_language.as_deref()),
            cookie_names,
            cookie_pairs,
        })
    }
}

impl TlsClientHelloFeatures {
    pub fn extract(payload: &[u8]) -> Result<Self, FingerprintError> {
        let (_, plaintext) = parse_tls_plaintext(payload)
            .map_err(|err| FingerprintError::Decode(format!("tls parse failed: {err:?}")))?;

        let client_hello = plaintext
            .msg
            .iter()
            .find_map(|message| match message {
                TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => Some(ch),
                _ => None,
            })
            .ok_or_else(|| {
                FingerprintError::Decode("tls payload does not contain clienthello".into())
            })?;

        let extensions = match client_hello.ext {
            Some(raw_ext) => {
                let (_, exts) = parse_tls_client_hello_extensions(raw_ext).map_err(|err| {
                    FingerprintError::Decode(format!("tls extension parse failed: {err:?}"))
                })?;
                exts
            }
            None => Vec::new(),
        };

        let mut has_sni = false;
        let mut alpn_marker = "00".to_string();
        let mut supported_versions = Vec::new();
        let mut extension_types = Vec::new();
        let mut signature_algorithms = Vec::new();

        for ext in &extensions {
            match ext {
                TlsExtension::SNI(_) => {
                    has_sni = true;
                }
                TlsExtension::ALPN(protocols) => {
                    if alpn_marker == "00" {
                        if let Some(first_protocol) = protocols.first() {
                            alpn_marker = alpn_marker_from_protocol(first_protocol);
                        }
                    }
                }
                TlsExtension::SupportedVersions(versions) => {
                    supported_versions = versions.iter().map(|version| version.0).collect();
                }
                TlsExtension::SignatureAlgorithms(sigs) => {
                    signature_algorithms.extend(sigs.iter().copied());
                }
                _ => {}
            }

            let ext_type = u16::from(TlsExtensionType::from(ext));
            if !is_grease(ext_type) {
                extension_types.push(ext_type);
            }
        }

        let ciphers = client_hello
            .ciphers
            .iter()
            .map(|cipher| cipher.0)
            .filter(|cipher| !is_grease(*cipher))
            .collect();

        let tls_version = if supported_versions.is_empty() {
            tls_version_label(client_hello.version.0)
        } else {
            tls_version_from_supported_versions(&supported_versions)
        };

        Ok(Self {
            tls_version,
            has_sni,
            alpn_marker,
            ciphers,
            extension_types,
            signature_algorithms,
        })
    }

    pub fn fingerprint_string(&self) -> String {
        let sni_marker = if self.has_sni { "d" } else { "i" };
        let cipher_count = self.ciphers.len().min(99);
        let extension_count = self.extension_types.len().min(99);

        let first_chunk = format!(
            "t{}{sni_marker}{cipher_count:02}{extension_count:02}{}",
            self.tls_version, self.alpn_marker
        );

        let mut ciphers = self.ciphers.clone();
        ciphers.sort_unstable();
        let ciphers_csv = ciphers
            .iter()
            .map(|cipher| format!("{cipher:04x}"))
            .collect::<Vec<_>>()
            .join(",");

        let mut extension_types = self
            .extension_types
            .iter()
            .copied()
            .filter(|ext| *ext != 0 && *ext != 16)
            .collect::<Vec<_>>();
        extension_types.sort_unstable();
        let exts_csv = extension_types
            .iter()
            .map(|ext| format!("{ext:04x}"))
            .collect::<Vec<_>>()
            .join(",");

        let sigs_csv = self
            .signature_algorithms
            .iter()
            .map(|sig| format!("{sig:04x}"))
            .collect::<Vec<_>>()
            .join(",");

        let exts_sigs = if sigs_csv.is_empty() {
            exts_csv
        } else {
            format!("{exts_csv}_{sigs_csv}")
        };

        format!(
            "{}_{}_{}",
            first_chunk,
            hash12(&ciphers_csv),
            hash12(&exts_sigs)
        )
    }
}

const HTTP2_CLEAR_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP2_FRAME_HEADER_LEN: usize = 9;
const HTTP2_FRAME_TYPE_HEADERS: u8 = 0x1;
const HTTP2_FLAG_END_HEADERS: u8 = 0x4;
const HTTP2_FLAG_PADDED: u8 = 0x8;
const HTTP2_FLAG_PRIORITY: u8 = 0x20;
const MAX_HTTP_HEADERS: usize = 64;
const ZERO_HASH_12: &str = "000000000000";

fn parse_h2_headers_fragment<'a>(
    frame_payload: &'a [u8],
    flags: u8,
) -> Result<&'a [u8], FingerprintError> {
    let mut start = 0usize;
    let mut pad_len = 0usize;

    if flags & HTTP2_FLAG_PADDED != 0 {
        if frame_payload.is_empty() {
            return Err(FingerprintError::Decode(
                "h2c HEADERS frame missing pad length".to_string(),
            ));
        }
        pad_len = frame_payload[0] as usize;
        start += 1;
    }
    if flags & HTTP2_FLAG_PRIORITY != 0 {
        if frame_payload.len() < start + 5 {
            return Err(FingerprintError::Decode(
                "h2c HEADERS frame missing priority fields".to_string(),
            ));
        }
        start += 5;
    }
    if frame_payload.len() < start || frame_payload.len() < start + pad_len {
        return Err(FingerprintError::Decode(
            "h2c HEADERS frame padding is invalid".to_string(),
        ));
    }

    Ok(&frame_payload[start..frame_payload.len() - pad_len])
}

fn looks_like_h2c_frames(payload: &[u8]) -> bool {
    if payload.len() < HTTP2_FRAME_HEADER_LEN {
        return false;
    }
    let length = ((payload[0] as usize) << 16) | ((payload[1] as usize) << 8) | payload[2] as usize;
    let frame_type = payload[3];
    length + HTTP2_FRAME_HEADER_LEN <= payload.len() && matches!(frame_type, 0x0..=0x9)
}

fn token2(value: &str) -> String {
    let mut out = value.chars().take(2).collect::<String>();
    while out.len() < 2 {
        out.push('0');
    }
    out
}

fn language_token(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "0000".to_string();
    };

    let normalized = value
        .to_ascii_lowercase()
        .replace('-', "")
        .replace(';', ",");
    let first = normalized.split(',').next().unwrap_or_default();

    let mut token = first.chars().take(4).collect::<String>();
    while token.len() < 4 {
        token.push('0');
    }
    token
}

fn parse_cookie_values(value: &str, names: &mut Vec<String>, pairs: &mut Vec<String>) {
    for chunk in value.split(';') {
        let piece = chunk.trim();
        if piece.is_empty() {
            continue;
        }
        let Some((name, value)) = piece.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            continue;
        }
        names.push(name.to_string());
        pairs.push(format!("{name}={value}"));
    }
}

fn is_h2c_upgrade_request_headers(headers: &[(String, String)]) -> bool {
    let mut has_upgrade_h2c = false;
    let mut has_http2_settings = false;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("upgrade")
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("h2c"))
        {
            has_upgrade_h2c = true;
        }
        if name.eq_ignore_ascii_case("http2-settings") {
            has_http2_settings = true;
        }
    }

    has_upgrade_h2c && has_http2_settings
}

fn alpn_marker_from_protocol(protocol: &[u8]) -> String {
    if protocol.is_empty() {
        return "00".into();
    }

    let first = safe_marker_char(protocol[0]);
    let last = safe_marker_char(*protocol.last().unwrap_or(&protocol[0]));
    format!("{first}{last}")
}

fn safe_marker_char(byte: u8) -> char {
    if byte.is_ascii() && !byte.is_ascii_control() {
        byte as char
    } else {
        '0'
    }
}

fn tls_version_from_supported_versions(versions: &[u16]) -> &'static str {
    let mut best_rank = 0u8;
    let mut best_label = "00";
    for version in versions {
        let (rank, label) = tls_version_rank(*version);
        if rank > best_rank {
            best_rank = rank;
            best_label = label;
        }
    }
    best_label
}

fn tls_version_label(version: u16) -> &'static str {
    tls_version_rank(version).1
}

fn tls_version_rank(version: u16) -> (u8, &'static str) {
    match version {
        0x0304 => (6, "13"),
        0x0303 => (5, "12"),
        0x0302 => (4, "11"),
        0x0301 => (3, "10"),
        0x0300 => (2, "s3"),
        0x0002 => (1, "s2"),
        _ => (0, "00"),
    }
}

fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && ((value >> 8) as u8 == (value & 0xff) as u8)
}

fn hash12(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use etherparse::{PacketBuilder, TcpOptionElement};

    use crate::capture::PacketRecord;

    use super::{FingerprintError, HttpClientFeatures, TcpClientFeatures, TlsClientHelloFeatures};

    fn syn_record(window_size: u16) -> PacketRecord {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
            .tcp(42424, 443, 1, window_size)
            .syn()
            .options(&[
                TcpOptionElement::MaximumSegmentSize(1460),
                TcpOptionElement::Noop,
                TcpOptionElement::WindowScale(8),
                TcpOptionElement::Noop,
                TcpOptionElement::Noop,
                TcpOptionElement::SelectiveAcknowledgementPermitted,
            ])
            .expect("tcp options should be valid");

        let payload = [];
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut packet, &payload)
            .expect("packet should be serializable");

        PacketRecord {
            timestamp_secs: 10,
            timestamp_micros: 20,
            captured_len: packet.len() as u32,
            original_len: packet.len() as u32,
            data: packet,
        }
    }

    fn ack_record() -> PacketRecord {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
            .tcp(42424, 443, 1, 64240)
            .ack(2);

        let payload = [];
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut packet, &payload)
            .expect("packet should be serializable");

        PacketRecord {
            timestamp_secs: 10,
            timestamp_micros: 20,
            captured_len: packet.len() as u32,
            original_len: packet.len() as u32,
            data: packet,
        }
    }

    fn udp_record() -> PacketRecord {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
            .udp(5353, 443);

        let payload = [0x42];
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut packet, &payload)
            .expect("packet should be serializable");

        PacketRecord {
            timestamp_secs: 10,
            timestamp_micros: 20,
            captured_len: packet.len() as u32,
            original_len: packet.len() as u32,
            data: packet,
        }
    }

    fn tls_client_hello_payload() -> Vec<u8> {
        vec![
            0x16, 0x03, 0x01, 0x00, 0x61, 0x01, 0x00, 0x00, 0x5d, 0x03, 0x03, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x00, 0x00, 0x06, 0x13, 0x01, 0x0a, 0x0a, 0x13, 0x02, 0x01, 0x00, 0x00, 0x2e,
            0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x00, 0x05, 0x61, 0x2e, 0x63, 0x6f, 0x6d,
            0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x0d, 0x00, 0x06, 0x00,
            0x04, 0x04, 0x03, 0x05, 0x03, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32,
            0x0a, 0x0a, 0x00, 0x00,
        ]
    }

    fn http1_request_payload() -> Vec<u8> {
        b"GET /index.html HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: curl/8.0\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
Referer: https://example.com/\r\n\
Cookie: session=abc123; theme=light\r\n\
X-Trace-Id: abc\r\n\
\r\n"
            .to_vec()
    }

    fn h2c_prior_knowledge_payload() -> Vec<u8> {
        let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        payload.extend_from_slice(&[
            // empty SETTINGS frame
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            // HEADERS frame header, length = 67, type = 1, flags = END_STREAM|END_HEADERS
            0x00, 0x00, 0x43, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01,
            // HPACK block
            0x82, // :method GET
            0x84, // :path /
            0x86, // :scheme http
            0x01, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
            b'm', // :authority: example.com
            0x0f, 0x2b, 0x08, b'h', b'2', b'c', b'-', b't', b'e', b's',
            b't', // user-agent: h2c-test
            0x0f, 0x02, 0x0e, b'f', b'r', b'-', b'C', b'A', b',', b'f', b'r', b';', b'q', b'=',
            b'0', b'.', b'8', // accept-language: fr-CA,fr;q=0.8
            0x0f, 0x11, 0x08, b'b', b'=', b'2', b';', b' ', b'a', b'=',
            b'1', // cookie: b=2; a=1
            0x00, 0x08, b'x', b'-', b'c', b'u', b's', b't', b'o', b'm', 0x01,
            b'z', // x-custom: z
        ]);
        payload
    }

    fn h2c_upgrade_with_following_h2_payload() -> Vec<u8> {
        let mut payload = b"GET / HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: Upgrade, HTTP2-Settings\r\n\
Upgrade: h2c\r\n\
HTTP2-Settings: AAMAAABkAAQAAAP_\r\n\
\r\n"
            .to_vec();
        payload.extend_from_slice(&h2c_prior_knowledge_payload());
        payload
    }

    fn h2c_headers_without_method_payload() -> Vec<u8> {
        let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x84]);
        payload
    }

    fn h2c_headers_without_end_headers_payload() -> Vec<u8> {
        let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x82]);
        payload
    }

    fn h2c_truncated_headers_frame_payload() -> Vec<u8> {
        let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x82]);
        payload
    }

    #[test]
    fn tcp_syn_packet_produces_ja4t_fingerprint() {
        let record = syn_record(64240);

        let features = TcpClientFeatures::extract(&record).expect("syn packet should be supported");

        assert_eq!(features.fingerprint_string(), "64240_2-1-3-1-1-4_1460_8");
    }

    #[test]
    fn non_syn_tcp_packet_is_rejected_for_ja4t() {
        let record = ack_record();

        let result = TcpClientFeatures::extract(&record);

        assert!(
            matches!(result, Err(FingerprintError::NotSyn)),
            "non-syn packet should return NotSyn, got: {result:?}"
        );
    }

    #[test]
    fn non_tcp_packet_is_rejected_for_ja4t() {
        let record = udp_record();

        let result = TcpClientFeatures::extract(&record);

        assert!(
            matches!(result, Err(FingerprintError::NotTcp)),
            "non-tcp packet should return NotTcp, got: {result:?}"
        );
    }

    #[test]
    fn tls_client_hello_packet_produces_ja4_fingerprint() {
        let payload = tls_client_hello_payload();

        let features =
            TlsClientHelloFeatures::extract(&payload).expect("valid clienthello should parse");

        assert_eq!(
            features.fingerprint_string(),
            "t13d0204h2_62ed6f6ca7ad_0442b87b8999"
        );
    }

    #[test]
    fn tls_extract_filters_grease_cipher_and_extension_values() {
        let payload = tls_client_hello_payload();

        let features =
            TlsClientHelloFeatures::extract(&payload).expect("valid clienthello should parse");

        assert!(
            !features.ciphers.contains(&0x0a0a),
            "grease cipher should be filtered, got: {:?}",
            features.ciphers
        );
        assert!(
            !features.extension_types.contains(&0x0a0a),
            "grease extension should be filtered, got: {:?}",
            features.extension_types
        );
    }

    #[test]
    fn tls_fingerprint_normalizes_cipher_and_extension_order() {
        let feature_a = TlsClientHelloFeatures {
            tls_version: "13",
            has_sni: true,
            alpn_marker: "h2".to_string(),
            ciphers: vec![0x1302, 0x1301],
            extension_types: vec![43, 0, 16, 13],
            signature_algorithms: vec![0x0403, 0x0503],
        };
        let feature_b = TlsClientHelloFeatures {
            tls_version: "13",
            has_sni: true,
            alpn_marker: "h2".to_string(),
            ciphers: vec![0x1301, 0x1302],
            extension_types: vec![16, 13, 43, 0],
            signature_algorithms: vec![0x0403, 0x0503],
        };

        assert_eq!(
            feature_a.fingerprint_string(),
            feature_b.fingerprint_string()
        );
    }

    #[test]
    fn tls_fingerprint_prefix_contains_version_sni_and_alpn_markers() {
        let features = TlsClientHelloFeatures {
            tls_version: "12",
            has_sni: false,
            alpn_marker: "00".to_string(),
            ciphers: vec![0x1301],
            extension_types: vec![43],
            signature_algorithms: Vec::new(),
        };

        let fingerprint = features.fingerprint_string();

        assert!(
            fingerprint.starts_with("t12i010100_"),
            "expected marker prefix t12i010100, got: {fingerprint}"
        );
    }

    #[test]
    fn truncated_tls_client_hello_returns_recoverable_failure() {
        let mut payload = tls_client_hello_payload();
        payload.truncate(payload.len() - 8);

        let result = TlsClientHelloFeatures::extract(&payload);

        assert!(
            matches!(result, Err(FingerprintError::Decode(_))),
            "truncated payload should return recoverable parse error, got: {result:?}"
        );
    }

    #[test]
    fn http1_request_produces_ja4h_fingerprint() {
        let payload = http1_request_payload();

        let features = HttpClientFeatures::extract(&payload).expect("valid HTTP/1.1 request");

        assert_eq!(
            features.fingerprint_string(),
            "ge11cr04enus_33f7519adbc8_6263fd0189b4_230379c57c15"
        );
    }

    #[test]
    fn http1_fingerprint_normalizes_header_cookie_and_language_inputs() {
        let payload_a = b"GET / HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: curl/8.0\r\n\
Accept-Language: fr-CA,fr;q=0.8\r\n\
Cookie: b=2; a=1\r\n\
X-Custom: z\r\n\
\r\n"
            .to_vec();
        let payload_b = b"GET / HTTP/1.1\r\n\
host: example.com\r\n\
x-custom: z\r\n\
cookie: a=1; b=2\r\n\
accept-language: FRCA;Q=0.8,en\r\n\
user-agent: curl/8.0\r\n\
\r\n"
            .to_vec();

        let feature_a =
            HttpClientFeatures::extract(&payload_a).expect("first HTTP/1 request should parse");
        let feature_b =
            HttpClientFeatures::extract(&payload_b).expect("second HTTP/1 request should parse");

        assert_eq!(
            feature_a.fingerprint_string(),
            feature_b.fingerprint_string()
        );
    }

    #[test]
    fn h2c_prior_knowledge_request_produces_ja4h_fingerprint() {
        let payload = h2c_prior_knowledge_payload();

        let features =
            HttpClientFeatures::extract(&payload).expect("valid prior-knowledge h2c request");

        assert_eq!(
            features.fingerprint_string(),
            "ge20cn03frca_acc1f387590f_1eb7c54d5283_06beefe2b477"
        );
    }

    #[test]
    fn h2c_missing_method_returns_recoverable_failure() {
        let payload = h2c_headers_without_method_payload();

        let result = HttpClientFeatures::extract(&payload);

        assert!(
            matches!(
                result,
                Err(FingerprintError::Decode(ref err))
                if err.contains("h2c :method header is missing")
            ),
            "expected explicit missing :method error, got: {result:?}"
        );
    }

    #[test]
    fn h2c_headers_continuation_not_supported_returns_recoverable_failure() {
        let payload = h2c_headers_without_end_headers_payload();

        let result = HttpClientFeatures::extract(&payload);

        assert!(
            matches!(
                result,
                Err(FingerprintError::Decode(ref err))
                if err.contains("h2c HEADERS continuation is not supported")
            ),
            "expected continuation unsupported error, got: {result:?}"
        );
    }

    #[test]
    fn h2c_truncated_frame_returns_recoverable_failure() {
        let payload = h2c_truncated_headers_frame_payload();

        let result = HttpClientFeatures::extract(&payload);

        assert!(
            matches!(
                result,
                Err(FingerprintError::Decode(ref err))
                if err.contains("h2c frame is truncated")
            ),
            "expected truncated h2c frame error, got: {result:?}"
        );
    }

    #[test]
    fn h2c_upgrade_request_with_following_frames_prefers_upgraded_h2c_fingerprint() {
        let payload = h2c_upgrade_with_following_h2_payload();

        let features =
            HttpClientFeatures::extract(&payload).expect("valid upgrade-based h2c request");

        assert_eq!(
            features.fingerprint_string(),
            "ge20cn03frca_acc1f387590f_1eb7c54d5283_06beefe2b477"
        );
    }

    #[test]
    fn truncated_http_request_returns_recoverable_failure() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0".to_vec();

        let result = HttpClientFeatures::extract(&payload);

        assert!(
            matches!(result, Err(FingerprintError::Decode(_))),
            "truncated HTTP payload should return recoverable parse error, got: {result:?}"
        );
    }
}
