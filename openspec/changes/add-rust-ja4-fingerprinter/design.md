## Context

The repository is currently a minimal project scaffold with no established Rust implementation for JA4 fingerprinting. This change introduces the first end-to-end design for a Rust binary that can analyze live Linux interface traffic and offline PCAP files while sharing one packet-processing core.

The primary constraints are:
- The implementation MUST be in Rust.
- The tool MUST support both live capture and offline PCAP analysis.
- The first release MUST focus on stdout/log output instead of storage backends.
- The first release MUST cover TLS client, HTTP client, and TCP client JA4-family fingerprints.
- The first release MUST support HTTP client fingerprint extraction for cleartext `HTTP/1.x` and cleartext `h2c`.
- Linux is the only required platform for live capture in this scope.

## Goals / Non-Goals

**Goals:**
- Provide one Rust binary with subcommands for `daemon` and `pcap`.
- Reuse one internal processing pipeline across live and offline execution modes.
- Extract the protocol features needed to compute JA4, JA4H, and JA4T client fingerprints.
- Support JA4H extraction across cleartext `HTTP/1.x` and cleartext `h2c` entry paths.
- Handle startup failures and per-packet parse failures explicitly without panicking.
- Produce stable stdout/log output that can be used for manual verification and future automation.

**Non-Goals:**
- Full cross-platform live capture support beyond Linux.
- Database sinks, message queues, or long-term storage.
- Full TCP stack fidelity for every fragmentation, reordering, and retransmission edge case.
- Complete coverage of the entire FoxIO JA4+ family beyond TLS client, HTTP client, and TCP client fingerprints.
- HTTP/3 or QUIC-based HTTP fingerprint extraction.

## Decisions

### Decision: Use a single binary with subcommands
The tool will expose `ja4finger daemon` and `ja4finger pcap` rather than separate binaries or flag-switched modes.

This keeps operational entrypoints explicit while allowing shared CLI configuration, shared logging setup, and one release artifact.

Alternatives considered:
- Separate binaries: rejected because it would duplicate packaging and operational wiring.
- Mode flags on one command: rejected because subcommands express intent more clearly and scale better if more commands are added later.

### Decision: Define daemon mode as a supervised foreground process
The `daemon` subcommand will run as a long-lived foreground process rather than self-daemonizing or forking into the background.

This keeps signal handling, stdout/stderr logging, and operational control straightforward while still satisfying the requirement to run continuously under a process manager such as `systemd` or another supervisor.

Alternatives considered:
- Self-daemonizing background process: rejected because it complicates process control, logging, and first-release operational behavior.
- Supporting both foreground and self-daemonized modes initially: rejected because it expands lifecycle and logging complexity before the packet pipeline is proven.

### Decision: Isolate input adapters from the fingerprinting pipeline
Live capture and PCAP reading will be separate input adapters that emit a common packet/event stream into the same decode, flow tracking, protocol extraction, and fingerprint calculation pipeline.

This avoids divergent behavior between `daemon` and `pcap` modes and allows offline PCAP tests to validate most of the core logic that live capture depends on.

Alternatives considered:
- Independent pipelines per mode: rejected because it would risk fingerprint mismatches and duplicate maintenance.

### Decision: Implement minimal necessary flow tracking for first-release protocol extraction
The pipeline will maintain flow state keyed by connection metadata and support limited payload buffering sufficient for:
- TCP client feature extraction from early handshake packets
- TLS ClientHello extraction
- HTTP client request extraction

The design does not attempt to reproduce a full TCP/IP reassembly stack. Instead, it optimizes for stable extraction on common well-formed traffic and clear failure behavior on incomplete or malformed streams.

Alternatives considered:
- Full reassembly engine first: rejected because it would materially expand scope before the first usable release.
- Stateless packet-only extraction: rejected because TLS and HTTP client fingerprinting require connection-oriented context.

### Decision: Explicitly scope HTTP client extraction to cleartext HTTP/1.x and h2c
The HTTP client extraction path will support two first-release entry modes:
- `HTTP/1.x` request parsing from cleartext TCP payloads
- `h2c` request parsing from cleartext HTTP/2 traffic, including prior-knowledge preface and upgrade-based entry

This scope matches the approved feature boundary while excluding encrypted `h2`, HTTP/3, and other transports that would require request decryption or materially different session handling.

Alternatives considered:
- Support only `HTTP/1.x`: rejected because it would miss a substantial part of modern client traffic.
- Add TLS-carried `h2` in the same change: rejected because passive capture cannot recover request-level HTTP/2 metadata without additional decryption inputs.
- Add HTTP/3 in the same change: rejected because it would introduce QUIC and a separate transport stack.

### Decision: Separate protocol feature extraction from fingerprint calculation
The implementation will normalize parsed protocol inputs into dedicated feature objects, then compute JA4-family fingerprint strings from those objects in a dedicated fingerprint layer.

This keeps parser behavior, feature normalization, and fingerprint formatting independently testable and makes later conformance work against FoxIO behavior more controlled.

Alternatives considered:
- Build fingerprint strings directly in parsers: rejected because it couples parsing and output logic too tightly.

### Decision: Treat startup failures as fatal and per-flow parse failures as recoverable
The binary will fail fast for invalid arguments, inaccessible interfaces, unreadable PCAP files, and similar startup issues. Once running, per-packet and per-flow parsing errors will be logged and counted without terminating the entire process unless the capture source itself becomes unrecoverable.

This model is necessary for daemon stability while still keeping CLI behavior predictable for automated usage.

Alternatives considered:
- Fail on every parse error: rejected because a daemon would be too fragile on real traffic.
- Silently ignore parse errors: rejected because it would hide missing coverage and make JA4 debugging impossible.

## Risks / Trade-offs

- [FoxIO parity risk] Exact JA4-family behavior may differ from FoxIO reference behavior until conformance samples are added. -> Mitigation: isolate normalization and fingerprint calculators so conformance fixes remain localized.
- [Partial reassembly risk] TLS or HTTP fingerprints may be missed on fragmented or heavily reordered traffic. -> Mitigation: document first-release limits and make PCAP-based regression tests the primary acceptance path.
- [HTTP/2 path complexity risk] Supporting `h2c` alongside `HTTP/1.x` increases parser branching and stream-state handling. -> Mitigation: keep the entry modes explicit in the design and split verification coverage by protocol path.
- [Operational noise risk] Default logs may become too noisy on malformed traffic. -> Mitigation: provide log levels and keep normal fingerprint output separate from warning/error logs.
- [Daemon resource risk] Long-running flow tracking can grow memory under high-cardinality traffic. -> Mitigation: enforce time-based cleanup and bounded flow state retention in the tracking layer.

## Migration Plan

This is a greenfield capability introduction, so no production migration is required.

Implementation rollout should follow this order:
1. Establish the Rust crate and CLI skeleton.
2. Add shared packet decoding and flow tracking primitives.
3. Add protocol feature extractors and JA4-family calculators.
4. Add stdout/log output and summaries.
5. Validate behavior against fixed PCAP samples before broadening live capture use.

Rollback strategy:
- If the implementation proves unstable, revert the new Rust binary and capability code without any data migration concerns because no persistent storage is introduced in this change.

## Open Questions

- Which exact Rust packet capture and parsing crates provide the best balance between Linux live capture support and testability for offline PCAP work?
- What FoxIO sample corpus or independently curated PCAP corpus will be used to tighten conformance after the first implementation pass?
