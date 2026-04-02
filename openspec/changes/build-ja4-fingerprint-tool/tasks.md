## 1. Project Setup

- [x] 1.1 Initialize the Go module and create the base directory layout for `cmd`, `engine`, `capture`, `decoder`, `fingerprint`, and `output`
- [x] 1.2 Add CLI command parsing for `live` and `pcap` modes with required flags for interface and input file selection
- [x] 1.3 Add the packet capture dependencies needed for live interface monitoring and PCAP analysis; the current TLS ClientHello decoding path is implemented in-repo and does not require an additional external TLS library
- [x] 1.4 Record that the FoxIO JA4 TLS ClientHello reference (see `README.md` and the FoxIO/ja4 README) defines the canonical JA4 baseline for implementation and validation

## 2. Unified Capture Pipeline

- [x] 2.1 Implement a shared packet event model that both live capture and PCAP readers can produce
- [x] 2.2 Implement live interface capture that opens a specified network interface and streams packets into the shared pipeline
- [x] 2.3 Implement PCAP file reading that opens a specified capture file and streams packets into the shared pipeline
- [x] 2.4 Add startup error handling for invalid interfaces, unreadable PCAP files, and pipeline initialization failures

## 3. Protocol Decoding and Fingerprinting

- [x] 3.1 Implement decoding logic that identifies candidate TLS client traffic from captured packets
- [x] 3.2 Implement JA4 fingerprint extraction from supported TLS ClientHello data
- [x] 3.3 Define the fingerprinter interface and registration boundary needed for future TCP fingerprint or HTTP/JA4H support
- [x] 3.4 Add packet-level error handling so malformed, partial, or unsupported traffic is skipped without terminating analysis

## 4. Output and Verification

- [x] 4.1 Implement structured fingerprint logging that emits `src_ip`, `src_port`, `protocol`, `fingerprint_type`, and `fingerprint`
- [x] 4.2 Wire the engine so both `live` and `pcap` commands use the same decode, fingerprint, and output flow
- [x] 4.3 Add tests or reproducible verification fixtures for supported TLS JA4 generation paths and confirm stable output for the same sample input
- [x] 4.4 Verify CLI behavior for unreadable PCAP files, invalid interfaces, and incomplete TLS handshakes and document the expected operator workflow in the project README
