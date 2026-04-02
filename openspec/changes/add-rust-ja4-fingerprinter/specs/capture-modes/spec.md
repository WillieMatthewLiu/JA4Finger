## ADDED Requirements

### Requirement: Tool exposes explicit capture subcommands
The system SHALL provide a single Rust binary that exposes a `daemon` subcommand for live interface capture and a `pcap` subcommand for offline packet capture analysis.

#### Scenario: User selects live capture mode
- **WHEN** an operator runs the binary with the `daemon` subcommand and required interface argument
- **THEN** the system starts the live capture runtime instead of the offline analysis runtime

#### Scenario: User selects offline analysis mode
- **WHEN** an operator runs the binary with the `pcap` subcommand and required file argument
- **THEN** the system starts offline PCAP analysis instead of the live capture runtime

### Requirement: Live capture mode targets a specified Linux interface
The system SHALL accept a Linux network interface identifier for `daemon` mode and start collecting packets from that interface when initialization succeeds.

#### Scenario: Interface can be opened
- **WHEN** the operator provides an existing Linux interface and the process has capture permissions
- **THEN** the system begins reading packets from that interface

#### Scenario: Interface cannot be opened
- **WHEN** the operator provides a missing interface or the process lacks permissions
- **THEN** the system exits with a non-zero status and a clear startup error

### Requirement: Daemon mode runs as a supervised foreground process
The system SHALL run `daemon` mode as a long-lived foreground process that is intended to be managed by an external supervisor rather than self-daemonizing into the background.

#### Scenario: Daemon mode starts successfully
- **WHEN** the operator starts `daemon` mode with a valid Linux interface and required permissions
- **THEN** the system remains attached as a foreground process while continuously capturing traffic

#### Scenario: Daemon mode receives termination
- **WHEN** the running `daemon` process receives a supported termination signal from the operating environment
- **THEN** the system stops capture, emits final observable state when possible, and exits cleanly

### Requirement: Offline analysis mode targets a specified PCAP file
The system SHALL accept a PCAP file path for `pcap` mode and analyze packets from that file until the input is exhausted or a fatal input error occurs.

#### Scenario: PCAP file is readable
- **WHEN** the operator provides a readable PCAP file
- **THEN** the system processes packets from the file and completes with an explicit run result

#### Scenario: PCAP file is invalid
- **WHEN** the operator provides a missing, unreadable, or unsupported PCAP input
- **THEN** the system exits with a non-zero status and a clear error message

### Requirement: Recoverable packet parsing failures do not terminate a healthy run
The system SHALL continue processing remaining traffic after recoverable packet, flow, or protocol parsing failures unless the capture source itself becomes unusable.

#### Scenario: Malformed packet appears during daemon mode
- **WHEN** the running daemon encounters a malformed or incomplete packet that cannot produce a fingerprint
- **THEN** the system logs or counts the failure and continues processing subsequent traffic

#### Scenario: Malformed packet appears during pcap mode
- **WHEN** the offline analyzer encounters a malformed or incomplete packet that can be skipped by the underlying reader
- **THEN** the system logs or counts the failure and continues processing later packets in the same file
