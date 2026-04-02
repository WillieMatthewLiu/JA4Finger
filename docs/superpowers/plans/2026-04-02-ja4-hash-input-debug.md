# JA4 Hash Input Debug Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--debug-hash-inputs` CLI mode that emits the exact normalized JA4 hash input strings without changing the default output contract.

**Architecture:** Extend the fingerprint result model to optionally carry debug-only pre-hash strings, thread a boolean option from CLI into the processing path, and verify behavior with focused CLI and fingerprint tests. The default JSON stays unchanged by using omitted fields unless debug mode is enabled.

**Tech Stack:** Go, existing `cmd/ja4finger`, `engine`, `fingerprint`, `output` packages, `go test`

---

### Task 1: Lock Debug Output Behavior with Tests

**Files:**
- Modify: `cmd/ja4finger/main_test.go`
- Modify: `fingerprint/ja4_test.go`
- Test: `cmd/ja4finger/main_test.go`
- Test: `fingerprint/ja4_test.go`

- [ ] **Step 1: Write the failing CLI assertions for debug fields**

Add assertions so the default `pcap` regression test confirms the output does **not** contain `cipher_hash_input` or `ext_hash_input`, and add a new test that runs `pcap --debug-hash-inputs --file <fixture>` and expects:

```go
if strings.Contains(out, "\"cipher_hash_input\"") || strings.Contains(out, "\"ext_hash_input\"") {
	t.Fatalf("did not expect debug fields in default output: %q", out)
}
```

and

```go
if !strings.Contains(out, "\"cipher_hash_input\":\"1301,1302,c02f\"") {
	t.Fatalf("expected cipher hash input in debug output, got %q", out)
}
if !strings.Contains(out, "\"ext_hash_input\":\"0000,000d,0010,002b,0403,0804\"") {
	t.Fatalf("expected ext hash input in debug output, got %q", out)
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `go test ./cmd/ja4finger ./fingerprint`
Expected: FAIL because the CLI and fingerprint result do not expose debug hash inputs yet.

- [ ] **Step 3: Write the failing fingerprint-level assertions**

Add a fingerprint test that expects the JA4 result to expose:

```go
if result.CipherHashInput != "1301,1302,c02f" {
	t.Fatalf("unexpected cipher hash input: %s", result.CipherHashInput)
}
if result.ExtHashInput != "0000,000d,0010,002b,0403,0804" {
	t.Fatalf("unexpected ext hash input: %s", result.ExtHashInput)
}
```

- [ ] **Step 4: Re-run the focused tests to keep the suite red**

Run: `go test ./cmd/ja4finger ./fingerprint`
Expected: FAIL because the result model still lacks those fields.

### Task 2: Expose Exact Pre-Hash Strings from the Fingerprinter

**Files:**
- Modify: `fingerprint/ja4.go`
- Test: `fingerprint/ja4_test.go`

- [ ] **Step 1: Extend the result model with optional debug fields**

Update `fingerprint.Result` to add omitted-by-default JSON fields:

```go
CipherHashInput string `json:"cipher_hash_input,omitempty"`
ExtHashInput    string `json:"ext_hash_input,omitempty"`
```

- [ ] **Step 2: Refactor JA4 hashing helpers to return both input strings and hashes**

Extract the normalized strings before hashing so the implementation can reuse them:

```go
cipherInput := strings.Join(formatHexList(ciphers), ",")
extInput := strings.Join(extInputs, ",")
```

and then derive hashes from those exact strings.

- [ ] **Step 3: Populate the debug fields in the JA4 result**

Set:

```go
CipherHashInput: cipherInput,
ExtHashInput:    extInput,
```

without changing the actual fingerprint string.

- [ ] **Step 4: Run the fingerprint tests to verify they pass**

Run: `go test ./fingerprint`
Expected: PASS

### Task 3: Thread `--debug-hash-inputs` Through CLI and Engine

**Files:**
- Modify: `cmd/ja4finger/main.go`
- Modify: `engine/processor.go`
- Test: `cmd/ja4finger/main_test.go`
- Test: `engine/processor_test.go`

- [ ] **Step 1: Add the new CLI flag to both subcommands**

Update the flag parsing so both `live` and `pcap` accept:

```go
debugHashInputs := fs.Bool("debug-hash-inputs", false, "include JA4 pre-hash input strings in output")
```

- [ ] **Step 2: Add a processor option that controls debug field emission**

Introduce a processor constructor or config like:

```go
type ProcessorOptions struct {
	DebugHashInputs bool
}
```

and pass it into `NewFingerprintProcessor(...)`.

- [ ] **Step 3: Strip debug fields when the flag is disabled**

Before emitting the result, clear the optional fields unless debug mode is enabled:

```go
if !p.debugHashInputs {
	result.CipherHashInput = ""
	result.ExtHashInput = ""
}
```

- [ ] **Step 4: Run the focused CLI and engine tests**

Run: `go test ./cmd/ja4finger ./engine`
Expected: PASS

### Task 4: Verify End-to-End Behavior and Document the Flag

**Files:**
- Modify: `README.md`
- Test: `cmd/ja4finger/main_test.go`

- [ ] **Step 1: Document the debug flag in README**

Add a short example like:

```bash
go run ./cmd/ja4finger pcap --debug-hash-inputs --file ./capture.pcap
```

and explain that it adds `cipher_hash_input` / `ext_hash_input` to each JSON record for Wireshark comparison.

- [ ] **Step 2: Run the full repository test suite**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 3: Run a build check**

Run: `go build ./cmd/ja4finger`
Expected: PASS
