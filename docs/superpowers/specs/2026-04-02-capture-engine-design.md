# Capture/Engine Wave 2 Design

## Summary

This wave establishes the shared capture foundations that both live interface monitoring and PCAP playback will depend on. The goal is to define a unified `PacketEvent` that carries the gopacket-decoded packet, timestamps, and capture metadata, plus sources for live and offline captures, and a thin engine that drives a per-event processor while surfacing startup failures and runtime errors. Startup validation will now produce distinct errors for invalid interfaces, missing PCAP files, or missing pipeline dependencies, and the downstream pipeline remains tolerant of single-packet failures.

## Architecture

### Shared Packet Event Model

- Define `capture.PacketEvent` (timestamp, source ID, gopacket packet, capture info) so downstream decoders never need to re-read the handle.
- Expose `capture.EventSource` interface so any producer (live, PCAP, stub) can plug into a pipeline.
- Each source sets the `Source` string to the interface name or PCAP path for traceability.

- ### Live and PCAP Sources

- `NewLiveSource` validates that the interface name is non-empty and, when building with the `pcap` tag, opens it via `pcap.OpenLive`. In environments where the `pcap` build tag (and libpcap headers) are unavailable, the function peers with `ErrLiveCaptureDisabled` so the caller can opt to skip live capture.
- `NewPCAPSource` either delegates to `pcap.OpenOffline` (when built with `pcap`) or uses the pure-Go `pcapgo.Reader` fallback so our current test environment stays self-contained. No matter the implementation, file-open failures bubble up immediately.
- Both constructors derive a cancellable context for their goroutine and expose `Close()` so callers can stop the capture and release handles.

### Engine Pipeline

- `engine.Pipeline` wires any `capture.EventSource` into a `PacketProcessor` interface and starts an event loop.
- The pipeline rejects nil sources or processors to patrol startup errors (covers task 2.4).
- Errors coming from the source or returned by the processor are delivered over a buffered channel so they can be logged without dropping the entire run.
- `Pipeline.Close()` cancels the loop, and `Wait()` allows callers to block until the pipeline finishes processing (e.g., after the source closes).
- `PacketHandlerFunc` makes it easy to inline processors in tests or future engine wiring code.

## Error Handling

- Source constructors trim inputs and reject empty interface/file names. `pcap.OpenLive`/`pcap.OpenOffline` errors are wrapped to highlight the failing resource.
- The capture goroutine treats `io.EOF` as normal completion, continues past `pcap.NextErrorTimeoutExpired`, and surfaces other `ReadPacketData` failures to the errors channel without stopping the loop.
- The pipeline exposes the aggregated errors channel through `Errors()` and drops values when the consumer cannot keep up so a single noisy handler cannot deadlock the loop.

## Testing Plan

- `capture/source_test.go` exercises the invalid-interface and unreadable-PCAP startup errors plus a temp-PCAP generation path that confirms at least one event flows through.
- The temp PCAP is built with gopacket serialization and traced via `src.Events()` so we can assert the source name and non-nil packet payload.
- `engine/pipeline_test.go` covers pipeline constructor validation and ensures event handler and source-side errors are forwarded through `Pipeline.Errors()` while still allowing the pipeline to exit cleanly.
- `go test ./...` will exercise both packages.

## Open Questions

1. Is the assumption that `PacketEvent` should contain the full `gopacket.Packet` acceptable, or would you rather transports only hand off raw bytes/timestamps and let the engine decode lazily?
2. Should pipeline errors be deduplicated or rate-limited beyond the buffered channel? For now I drop values when the channel is full.

Spec written. Please review and let me know if any changes are needed before I proceed to the next implementation plan.
