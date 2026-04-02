## Why

The project needs a Rust implementation of a JA4 fingerprinting tool that can work both on live traffic and offline packet captures. Building the first change now establishes a consistent foundation for packet ingestion, protocol feature extraction, and JA4-family client fingerprints before the codebase grows in incompatible directions.

## What Changes

- Add a Rust binary that exposes subcommands for `daemon` live capture and `pcap` offline analysis.
- Add shared packet processing and session tracking logic so both execution modes use the same fingerprinting core.
- Add TLS client, HTTP client (`HTTP/1.x` and `h2c`), and TCP client fingerprint extraction aligned with the FoxIO JA4+ family at the capability level.
- Add stdout/log output for emitted fingerprints, startup failures, recoverable parse errors, and per-run summaries.
- Define `daemon` as a long-running foreground capture process intended for external supervision and graceful shutdown.
- Define Linux as the initial supported platform for live capture in the first release scope.

## Capabilities

### New Capabilities
- `capture-modes`: Run the tool as a long-running foreground live capture process on a specified Linux network interface or as a CLI command that analyzes a specified PCAP file.
- `ja4-client-fingerprinting`: Extract JA4-family client fingerprints for TLS client, HTTP client (`HTTP/1.x` and `h2c`), and TCP client traffic from the shared processing pipeline.

### Modified Capabilities
- None.

## Impact

- Affected code: new Rust crate layout for CLI entrypoints, capture adapters, packet/session pipeline, fingerprint calculators, and stdout/log output.
- Affected APIs: new command-line interface for `daemon` and `pcap` subcommands and their runtime options.
- Dependencies: Rust packet capture and packet parsing libraries, plus logging/CLI support crates.
- Affected systems: Linux live packet capture, offline PCAP analysis, and future conformance work against FoxIO JA4+ reference behavior.
