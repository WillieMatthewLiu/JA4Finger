## 1. Project Setup

- [x] 1.1 Initialize the Rust crate layout for the `ja4finger` binary and define the top-level module boundaries for CLI, capture, pipeline, fingerprint, and output code.
- [x] 1.2 Add and configure the Rust dependencies required for CLI parsing, logging, packet decoding, Linux live capture, and offline PCAP reading.
- [x] 1.3 Implement the CLI entrypoint with explicit `daemon` and `pcap` subcommands and argument validation for interface and file inputs.

## 2. Shared Packet Processing Pipeline

- [x] 2.1 Implement input adapters that normalize packets from Linux interface capture and PCAP files into a shared packet/event stream.
- [x] 2.2 Implement packet decoding and flow/session tracking primitives needed for TCP feature extraction, TLS ClientHello parsing, and HTTP request parsing.
- [x] 2.3 Add bounded flow lifecycle management, recoverable parse error handling, and runtime counters for packets, flows, and extraction failures.

## 3. JA4 Family Fingerprinting

- [x] 3.1 Implement normalized feature extraction for TCP client traffic and compute JA4T fingerprints when sufficient client-side metadata is available.
- [x] 3.2 Implement normalized feature extraction for TLS ClientHello traffic and compute JA4 fingerprints when required TLS fields can be parsed.
- [x] 3.3 Implement JA4H extraction for cleartext HTTP client traffic, including `HTTP/1.x` requests and `h2c` entry paths.
- [x] 3.4 Implement a shared fingerprint emission path that outputs successful JA4, JA4H, and JA4T results with the required runtime fields and flow context.

## 4. Runtime Behavior And Verification

- [x] 4.1 Implement startup failure handling, recoverable warning/error logging, foreground daemon signal handling, and per-run or periodic summaries for `pcap` and `daemon` modes.
- [x] 4.2 Add unit tests for feature normalization and JA4-family fingerprint calculation behavior, including insufficient-data failure cases.
- [x] 4.3 Add PCAP-based integration tests that verify expected JA4, JA4H (`HTTP/1.x` and `h2c`), and JA4T outputs plus resilience to malformed traffic.
- [x] 4.4 Add CLI behavior checks that verify explicit non-zero failures, foreground `daemon` lifecycle behavior, and clean shutdown handling.
