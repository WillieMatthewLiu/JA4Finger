# Live Exclude IP Design

## Summary

Add optional source and destination IP exclusion settings for `live` mode so operators can suppress fingerprinting for traffic involving specific IP addresses.

The feature is configuration-file driven only. The existing `live --interface` CLI remains valid, while `live --config` gains two optional YAML lists:

```yaml
live:
  interface: eth0
  exclude_src_ips:
    - 192.168.1.10
  exclude_dst_ips:
    - 8.8.8.8
```

When a live packet matches either exclusion list, the packet is ignored before TLS fingerprint emission. Non-matching traffic continues through the normal decode and output pipeline.

## Goals

- Allow operators to exclude known source IPs from `live` inspection.
- Allow operators to exclude known destination IPs from `live` inspection.
- Keep the change limited to `live` mode and the existing YAML config path.
- Preserve current output behavior for non-excluded traffic.

## Non-Goals

- Do not add equivalent exclusion support to `pcap` mode.
- Do not add new CLI flags for exclude-IP lists in this change.
- Do not introduce CIDR, wildcard, or subnet matching in this change.
- Do not alter JA4 calculation for packets that are not excluded.

## Design

### Config Shape

Extend the existing `live` YAML section with two optional lists:

- `exclude_src_ips`
- `exclude_dst_ips`

Each entry must be a single IP string. Empty lists are treated the same as unset lists.

### Precedence

The existing precedence for interface selection remains unchanged:

- `--interface` overrides `live.interface`
- `live.interface` is used when `--interface` is not provided

Exclude-IP settings are read only from the YAML config file.

### Filtering Point

Apply exclusion in the `live` packet processing path before TLS decode and fingerprint generation. This keeps the rule local to live capture, avoids changing pcap semantics, and avoids wasting decode work for packets that will be dropped anyway.

For each packet:

- if the source IP is in `exclude_src_ips`, skip the packet
- if the destination IP is in `exclude_dst_ips`, skip the packet
- otherwise continue through the existing pipeline

Packets without IPv4/IPv6 layers continue to rely on the current candidate detection behavior.

### Validation

Config loading must reject invalid IP entries with a clear startup error. This avoids silent misconfiguration.

Startup should fail when:

- a configured exclude entry is not a valid IP literal
- the YAML structure for the exclude lists is malformed

## Verification

Add tests that confirm:

- `live --config` can load source exclusion IPs
- `live --config` can load destination exclusion IPs
- invalid exclude IP entries fail fast at startup
- excluded packets are ignored in live-mode processing
- non-excluded packets still emit the same fingerprint output as before

## Risks

- The current minimal YAML parser already only supports a narrow subset of YAML, so exclude-list parsing must stay within that same constrained model.
- If filtering is applied too late in the pipeline, excluded packets would still spend CPU on decode work.
- If invalid IP strings are silently ignored, operators could believe filtering is active when it is not.
