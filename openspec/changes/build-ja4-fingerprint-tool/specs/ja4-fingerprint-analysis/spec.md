## ADDED Requirements

### Requirement: CLI mode SHALL analyze a specified PCAP file
The system SHALL provide a CLI mode that accepts a PCAP file path, reads packets from that file, and runs them through the same fingerprint analysis pipeline used by live capture mode.

#### Scenario: Analyze a valid PCAP file
- **WHEN** the user runs the tool in PCAP mode with a readable PCAP file path
- **THEN** the system MUST process packets from the file and emit fingerprint logs for supported TLS client traffic

#### Scenario: Reject an unreadable PCAP file
- **WHEN** the user runs the tool in PCAP mode with a missing or unreadable PCAP file
- **THEN** the system MUST exit with an error explaining that the input file cannot be opened or read

### Requirement: Live mode SHALL monitor a specified network interface
The system SHALL provide a live capture mode that accepts a network interface identifier and continuously inspects traffic from that interface until the process is stopped or initialization fails.

#### Scenario: Start live capture on a valid interface
- **WHEN** the user runs the tool in live mode with an accessible network interface
- **THEN** the system MUST start packet capture on that interface and emit fingerprint logs for supported TLS client traffic

#### Scenario: Reject an invalid interface
- **WHEN** the user runs the tool in live mode with an invalid or inaccessible network interface
- **THEN** the system MUST fail startup with an error explaining that the interface cannot be monitored

### Requirement: The system SHALL generate JA4 fingerprints for supported TLS client traffic
The system SHALL inspect decoded traffic and generate JA4 fingerprints for supported TLS client flows. JA4 fingerprint generation MUST use the TLS ClientHello data defined by the chosen JA4 reference baseline.

#### Scenario: Generate a fingerprint for TLS client traffic
- **WHEN** the system observes a supported TLS client flow with sufficient ClientHello data
- **THEN** the system MUST emit a fingerprint record identified as TLS or HTTPS, according to the implementation's protocol labeling rules

#### Scenario: Skip incomplete TLS handshake data
- **WHEN** the system observes TLS traffic but cannot recover the ClientHello data required by the chosen JA4 baseline
- **THEN** the system MUST skip fingerprint emission for that traffic, record the failure, and continue processing subsequent traffic

#### Scenario: Ignore unsupported traffic without terminating analysis
- **WHEN** the system observes traffic that is not supported TLS client traffic
- **THEN** the system MUST skip fingerprint emission for that traffic and continue processing subsequent packets

### Requirement: Fingerprint output SHALL include source and protocol fields
Each emitted fingerprint record SHALL include the source IP address, source port, protocol classification, fingerprint type, and fingerprint value so operators can correlate the result to observed traffic and distinguish JA4 from future fingerprint families.

#### Scenario: Emit required output fields
- **WHEN** the system emits a fingerprint record
- **THEN** that record MUST contain `src_ip`, `src_port`, `protocol`, `fingerprint_type`, and `fingerprint`

### Requirement: The analysis engine SHALL remain extensible for future protocol fingerprinting
The system SHALL define a fingerprint processing boundary that allows a future TCP fingerprint or HTTP/JA4H implementation to be added without replacing the capture pipeline, protocol decoding pipeline, or output pipeline.

#### Scenario: Add a new protocol-specific fingerprinter
- **WHEN** a developer adds a future TCP fingerprint or HTTP/JA4H implementation behind the defined fingerprint processing boundary
- **THEN** the live and PCAP execution flows MUST be able to invoke it without requiring a redesign of their input handling pipeline

### Requirement: Packet-level failures SHALL not stop overall analysis
The system SHALL continue processing subsequent traffic when an individual packet, flow, or parsing step fails after capture has started, while still surfacing startup failures that prevent analysis from beginning.

#### Scenario: Continue after a parse failure
- **WHEN** the system encounters a malformed packet or insufficient data during analysis after startup succeeds
- **THEN** the system MUST record the failure and continue processing later packets or flows

#### Scenario: Stop on initialization failure
- **WHEN** the system cannot initialize capture, open the input file, or start the analysis pipeline
- **THEN** the system MUST terminate with a startup error instead of entering a partial running state

### Requirement: PCAP verification SHALL produce stable JA4 output for the same sample input
The system SHALL provide at least one reproducible verification path in PCAP mode so operators and developers can confirm that the same sample input produces stable JA4 output across runs.

#### Scenario: Replay a known sample capture
- **WHEN** the user runs the tool in PCAP mode against a documented sample capture used for verification
- **THEN** the emitted JA4 output MUST remain stable for that sample across repeated runs of the same build
