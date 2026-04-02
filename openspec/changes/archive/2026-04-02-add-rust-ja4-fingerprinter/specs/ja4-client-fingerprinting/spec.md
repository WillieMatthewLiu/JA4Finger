## ADDED Requirements

### Requirement: Fingerprint extraction uses one shared processing core
The system SHALL use a shared internal processing pipeline for live capture and offline PCAP analysis so that the same packet decoding, flow tracking, protocol extraction, and fingerprint calculation rules apply in both modes.

#### Scenario: Same client traffic appears in both modes
- **WHEN** equivalent client traffic is analyzed once through `daemon` mode and once through `pcap` mode
- **THEN** the system applies the same fingerprinting rules to both executions

### Requirement: System computes JA4T from TCP client traffic
The system SHALL extract TCP client features from connection setup traffic and compute a JA4T fingerprint when sufficient client-side TCP metadata is available.

#### Scenario: TCP handshake contains required client features
- **WHEN** a client connection provides the TCP features required by the JA4T algorithm
- **THEN** the system emits a JA4T fingerprint for that client flow

#### Scenario: TCP features are insufficient
- **WHEN** the client flow does not provide the minimum TCP features required to compute JA4T
- **THEN** the system does not emit a fabricated JA4T fingerprint and records the extraction failure as recoverable

### Requirement: System computes JA4 from TLS ClientHello traffic
The system SHALL extract the normalized TLS client features required for JA4 from a client-side TLS ClientHello and compute a JA4 fingerprint when the ClientHello can be parsed successfully.

#### Scenario: Complete ClientHello is available
- **WHEN** the system can parse a client-side TLS ClientHello with the fields required by the JA4 algorithm
- **THEN** the system emits a JA4 fingerprint for that client flow

#### Scenario: ClientHello is incomplete or malformed
- **WHEN** the TLS client payload is truncated, malformed, or otherwise insufficient for JA4 calculation
- **THEN** the system does not emit a fabricated JA4 fingerprint and records the extraction failure as recoverable

### Requirement: System computes JA4H from HTTP client request traffic
The system SHALL extract the normalized HTTP client request features required for JA4H and compute a JA4H fingerprint from supported cleartext `HTTP/1.x` and cleartext `h2c` client request traffic when the required request metadata can be parsed successfully.

#### Scenario: HTTP/1.x request is available
- **WHEN** the system can parse an `HTTP/1.x` client request with the fields required by the JA4H algorithm
- **THEN** the system emits a JA4H fingerprint for that client flow

#### Scenario: Cleartext h2c request is available
- **WHEN** the system can parse a client request carried over cleartext `h2c` with the fields required by the JA4H algorithm
- **THEN** the system emits a JA4H fingerprint for that client flow

#### Scenario: HTTP request is incomplete or unsupported
- **WHEN** the client request payload is incomplete, malformed, uses an unsupported encrypted transport such as TLS-carried `h2` or HTTP/3, or does not expose the fields required for JA4H calculation
- **THEN** the system does not emit a fabricated JA4H fingerprint and records the extraction failure as recoverable

### Requirement: Successful fingerprints are emitted with execution context
The system SHALL output each successful JA4-family fingerprint with the minimum execution context needed to identify when and where it was produced, including timestamp, runtime mode, fingerprint type, fingerprint value, source endpoint, and destination endpoint.

#### Scenario: Fingerprint is emitted during processing
- **WHEN** the system successfully computes a JA4, JA4H, or JA4T fingerprint
- **THEN** the output includes timestamp, runtime mode, fingerprint type, fingerprint value, and source/destination flow context

### Requirement: Completed runs provide observable processing summaries
The system SHALL expose processing summaries that report packet and fingerprint outcomes for each completed offline run and for periodic or shutdown reporting in live capture mode, including at least `packets_seen`, `flows_tracked`, `fingerprints_emitted`, and `parse_failures`.

#### Scenario: Offline run completes
- **WHEN** the `pcap` subcommand reaches the end of the input file
- **THEN** the system outputs a summary that includes `packets_seen`, `flows_tracked`, `fingerprints_emitted`, and `parse_failures`

#### Scenario: Live run reports health
- **WHEN** the `daemon` runtime reaches a reporting interval or controlled shutdown point
- **THEN** the system outputs a summary that includes `packets_seen`, `flows_tracked`, `fingerprints_emitted`, and `parse_failures`
