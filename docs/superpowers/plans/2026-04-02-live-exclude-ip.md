# Live Exclude IP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `live`-mode source and destination IP exclusion lists from YAML config so matching packets are skipped before TLS fingerprinting.

**Architecture:** Keep config parsing in `cmd/ja4finger`, extending the existing minimal YAML loader to read `exclude_src_ips` and `exclude_dst_ips` alongside `live.interface`. Keep the exclusion runtime behavior in `engine`, where the live-mode processor checks packet IP layers before decode and silently skips packets whose source or destination IP matches the configured exclusion sets.

**Tech Stack:** Go, existing stdlib-only YAML subset parser, gopacket packet layers, Go test

---

### Task 1: Extend live CLI/config parsing

**Files:**
- Modify: `cmd/ja4finger/main.go`
- Test: `cmd/ja4finger/main_test.go`

- [ ] **Step 1: Write the failing config parsing tests**

Add tests covering:

```go
func TestRunLiveAcceptsExcludeIPsFromConfig(t *testing.T)
func TestRunLiveRejectsInvalidExcludeSourceIP(t *testing.T)
func TestRunLiveRejectsInvalidExcludeDestinationIP(t *testing.T)
```

The successful case should write a config like:

```yaml
live:
  interface: eth0
  exclude_src_ips:
    - 192.168.1.10
  exclude_dst_ips:
    - 8.8.8.8
```

and assert that the parsed live config passes those values into the live runner.

- [ ] **Step 2: Run the CLI tests to verify they fail**

Run: `go test ./cmd/ja4finger`
Expected: FAIL because `main.go` does not yet parse or pass exclude IP settings.

- [ ] **Step 3: Implement minimal live config parsing**

In `cmd/ja4finger/main.go`:

- add a `liveConfig` model carrying:
  - `Interface string`
  - `ExcludeSrcIPs []string`
  - `ExcludeDstIPs []string`
- extend the minimal YAML reader to parse:
  - `live.interface`
  - `live.exclude_src_ips`
  - `live.exclude_dst_ips`
- validate each configured IP with `net.ParseIP`
- keep precedence:
  - `--interface` overrides `live.interface`
  - exclude lists are config-only

- [ ] **Step 4: Run the CLI tests to verify they pass**

Run: `go test ./cmd/ja4finger`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/ja4finger/main.go cmd/ja4finger/main_test.go
git commit -m "Add live exclude IP config parsing"
```

### Task 2: Apply exclusion in the live processing path

**Files:**
- Modify: `engine/processor.go`
- Test: `engine/processor_test.go`

- [ ] **Step 1: Write the failing processor tests**

Add tests covering:

```go
func TestFingerprintProcessorSkipsExcludedSourceIP(t *testing.T)
func TestFingerprintProcessorSkipsExcludedDestinationIP(t *testing.T)
func TestFingerprintProcessorEmitsForNonExcludedIPs(t *testing.T)
```

The excluded cases should build packet events with IPv4 source/destination addresses matching configured exclusions and assert that no result is emitted and no error is returned.

- [ ] **Step 2: Run the processor tests to verify they fail**

Run: `go test ./engine`
Expected: FAIL because the processor does not yet know about exclude-IP lists.

- [ ] **Step 3: Implement minimal live-only exclusion logic**

In `engine/processor.go`:

- add exclusion sets to `FingerprintProcessor`
- add helpers that inspect IPv4/IPv6 packet layers before calling `decoder.DecodeTLSClientHello`
- skip packets when:
  - source IP is in the source exclusion set
  - destination IP is in the destination exclusion set
- keep `pcap` behavior unchanged by only wiring exclusions through the live run path

- [ ] **Step 4: Run the processor tests to verify they pass**

Run: `go test ./engine`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add engine/processor.go engine/processor_test.go
git commit -m "Skip excluded IPs in live processing"
```

### Task 3: Wire end-to-end behavior and document it

**Files:**
- Modify: `cmd/ja4finger/main.go`
- Modify: `README.md`
- Test: `cmd/ja4finger/main_test.go`

- [ ] **Step 1: Write the failing end-to-end tests**

Add or extend CLI tests to assert:

- `live --config` passes exclude lists into the live runner
- `--interface` still overrides config interface while leaving exclude lists intact

- [ ] **Step 2: Run the targeted tests to verify they fail or remain red from earlier steps**

Run: `go test ./cmd/ja4finger ./engine`
Expected: FAIL until wiring is complete

- [ ] **Step 3: Wire the live runner and update docs**

- extend the live runner signature to accept exclude IP settings
- pass parsed exclude lists from CLI into `engine.RunLive`
- document YAML examples in `README.md`

- [ ] **Step 4: Run full verification**

Run: `go test ./cmd/ja4finger ./engine`
Expected: PASS

Run: `go test ./...`
Expected: PASS

Run: `go build ./cmd/ja4finger`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/ja4finger/main.go cmd/ja4finger/main_test.go engine/processor.go engine/processor_test.go README.md
git commit -m "Document live exclude IP configuration"
```
