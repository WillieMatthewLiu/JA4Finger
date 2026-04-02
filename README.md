# JA4Finger

`ja4finger` is a Go CLI for extracting TLS ClientHello JA4 fingerprints from either a PCAP file or live Linux interface capture.

## JA4 Baseline

The project anchors all JA4 interpretation, validation, and output on the FoxIO JA4 TLS ClientHello reference definition so downstream work can rely on a single, well-defined fingerprint format.

The canonical baseline is the FoxIO JA4 TLS ClientHello definition published in the [FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4) repository README. For this project, that means the `a_b_c` JA4 layout from FoxIO: the `a` segment captures the transport/protocol marker, TLS version, SNI indicator, cipher count, extension count, and ALPN marker; the `b` segment is derived from the sorted non-GREASE cipher suite list; and the `c` segment is derived from the sorted non-GREASE extension list plus signature algorithms as described by FoxIO. All future decoding, fingerprinting, and verification logic must use that same field order, GREASE handling, and sorting behavior so the same sample capture yields the same JA4 value across runs.

## Usage

Analyze a PCAP file:

```bash
go run ./cmd/ja4finger pcap --file ./capture.pcap
```

Analyze a PCAP file and include the normalized JA4 pre-hash input strings for debugging:

```bash
go run ./cmd/ja4finger pcap --debug-hash-inputs --file ./capture.pcap
```

Analyze a PCAP file, keep JSONL on stdout, and also append the same results to a custom log file:

```bash
go run ./cmd/ja4finger pcap --file ./capture.pcap --log-file ./logs/custom-ja4.log
```

Monitor a live interface on Linux:

```bash
sudo go run ./cmd/ja4finger live --interface eth0
```

Monitor a live interface on Linux using a YAML config file:

```bash
sudo go run ./cmd/ja4finger live --config ./ja4finger.yaml
```

Example config:

```yaml
live:
  interface: eth0
```

Output is JSON lines on stdout with these fields:

- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `protocol`
- `fingerprint_type`
- `fingerprint`

By default, the same JSON lines are also appended to a log file in the current directory:

- `pcap`: `logs/yyyyMMdd-ja4finger-pcap.log`
- `live`: `logs/yyyyMMdd-ja4finger-live.log`

Use `--log-file <path>` to override the default log file location.

When `--debug-hash-inputs` is enabled, each JSON object also includes:

- `cipher_hash_input`
- `ext_hash_input`

These two fields are the normalized raw strings used as JA4 hash inputs, not the raw TLS bytes from the packet.

- `cipher_hash_input` is the sorted non-GREASE cipher suite list.
- `ext_hash_input` follows the FoxIO/Wireshark JA4 `c` segment input form: sorted non-GREASE extensions excluding `0000` (SNI) and `0010` (ALPN), followed by `_`, followed by the non-GREASE signature algorithms in their original ClientHello order.

## Operator Notes

- `pcap` and `live` share the same decode, fingerprint, and output pipeline.
- `--debug-hash-inputs` is available on both `pcap` and `live`.
- In `live` mode, `--interface` takes precedence over `--config`; if `--interface` is omitted, the tool reads `live.interface` from the YAML config file.
- `live` requires Linux `AF_PACKET` support plus privileges to open the requested interface.
- Non-Linux builds return a startup error for `live` instead of silently pretending support exists.
- The current implementation only fingerprints TLS ClientHello traffic that is fully present in a single captured TCP payload.
- Missing PCAP files, invalid interfaces, and pipeline startup failures exit the command with an error.
- Malformed or incomplete TLS handshakes are reported on stderr and skipped without terminating the overall analysis flow.
