# Aggregate Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an offline `aggregate` command that reads daemon logs or pcap text output and emits JA4-anchored src/dst correlations within a configurable time window.

**Architecture:** Extend the CLI with an `aggregate` subcommand, implement parsing and JA4-anchored correlation in a focused `src/aggregate.rs` module, and verify behavior with module tests plus CLI integration tests. The command will ignore non-fingerprint lines, group by full `src` and `dst` endpoints, and output only records that contain a `ja4` plus at least one correlated `ja4h` or `ja4t`.

**Tech Stack:** Rust 2024, clap, std collections/io, cargo test

---

### Task 1: Add failing CLI coverage

**Files:**
- Modify: `tests/cli.rs`

- [ ] **Step 1: Write the failing test**

Add integration tests that create input text files containing mixed daemon/pcap-style lines and assert `aggregate --file ... --window-secs ...` emits JA4-anchored correlations while skipping status/summary lines.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test aggregate_ -- --nocapture`
Expected: FAIL because `aggregate` command is not implemented yet.

- [ ] **Step 3: Write minimal implementation**

Implement the CLI surface and enough aggregation logic to satisfy the integration tests.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test aggregate_ -- --nocapture`
Expected: PASS

### Task 2: Add focused module tests

**Files:**
- Create: `src/aggregate.rs`

- [ ] **Step 1: Write the failing test**

Add unit tests for line parsing, de-duplication, JA4-required filtering, and out-of-window exclusion.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test aggregate:: --lib -- --nocapture`
Expected: FAIL because parser/aggregator functions do not exist yet.

- [ ] **Step 3: Write minimal implementation**

Implement the parser, grouping, anchor-window correlation, and rendering functions.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test aggregate:: --lib -- --nocapture`
Expected: PASS

### Task 3: Wire command and document usage

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Modify: `src/lib.rs`
- Modify: `README.md`

- [ ] **Step 1: Write the failing test**

Rely on the existing integration tests to keep this task red until CLI wiring is complete.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test aggregate_ help_lists_supported_subcommands -- --nocapture`
Expected: FAIL until `aggregate` appears in the CLI and help output.

- [ ] **Step 3: Write minimal implementation**

Add the subcommand, dispatch to the aggregate module, and document the new usage in the README.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test`
Expected: PASS
