# CLI Command Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize the CLI code so `daemon`, `pcap`, and `aggregate` live under `src/commands/` while preserving current behavior and test coverage.

**Architecture:** Keep `src/main.rs` as a thin entrypoint that only initializes logging, parses the CLI, dispatches subcommands, and converts `Result<(), String>` into `ExitCode`. Move each command runner into its own file under `src/commands/`, rename the existing aggregation engine module to avoid the `aggregate` name collision, and keep shared logic changes minimal so this remains a structural refactor rather than a behavior change.

**Tech Stack:** Rust 2024, clap, std modules/filesystem, cargo test, cargo fmt

---

## File Structure

- Create: `src/commands/mod.rs`
- Create: `src/commands/daemon.rs`
- Create: `src/commands/pcap.rs`
- Create: `src/commands/aggregate.rs`
- Create: `src/aggregator.rs`
- Modify: `src/main.rs`
- Modify: `src/lib.rs`
- Modify: `README.md`
- Modify: `tests/cli.rs`
- Delete: `src/aggregate.rs`

### Responsibility Map

- `src/main.rs`
  - Own `fn main() -> ExitCode`
  - Call `output::init_logging()`
  - Parse CLI and dispatch to `commands::*::run(...)`
  - Print error text and return failure exit code

- `src/commands/mod.rs`
  - Re-export subcommand modules only

- `src/commands/daemon.rs`
  - Own daemon runtime loop and daemon-only helpers
  - Keep daemon unit tests next to daemon code

- `src/commands/pcap.rs`
  - Own pcap runtime loop and pcap/daemon shared packet-processing helpers

- `src/commands/aggregate.rs`
  - Own file reading and aggregate result printing
  - Call pure aggregation logic from `src/aggregator.rs`

- `src/aggregator.rs`
  - Own text parsing, event correlation, and aggregate output rendering
  - Keep pure aggregation unit tests

### Task 1: Lock In Refactor Expectations With Failing Tests

**Files:**
- Modify: `tests/cli.rs`

- [ ] **Step 1: Write the failing test**

Add a CLI smoke test that asserts `--help` still lists all three subcommands after the refactor and that the existing `aggregate` command still behaves as before. Extend the existing integration coverage instead of inventing a new harness.

```rust
#[test]
fn help_lists_supported_subcommands() {
    let output = run(&["--help"]);

    assert!(output.status.success(), "--help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("daemon"), "missing daemon: {stdout}");
    assert!(stdout.contains("pcap"), "missing pcap: {stdout}");
    assert!(stdout.contains("aggregate"), "missing aggregate: {stdout}");
}

#[test]
fn aggregate_correlates_pcap_output_records_within_window() {
    let input_path = unique_temp_text_path("aggregate-pcap");
    write_text_fixture(
        &input_path,
        "\
ts=20.000000 mode=pcap kind=ja4 value=ja4-beta src=10.0.0.1:50000 dst=10.0.0.2:443
ts=24.000000 mode=pcap kind=ja4t value=ja4t-beta src=10.0.0.1:50000 dst=10.0.0.2:443
mode=pcap packets_seen=2 flows_tracked=1 fingerprints_emitted=2 parse_failures=0 extraction_failures=0
",
    );
    let input_arg = input_path.to_string_lossy().to_string();

    let output = run(&["aggregate", "--file", &input_arg, "--window-secs", "10"]);

    let _ = std::fs::remove_file(&input_path);

    assert!(output.status.success(), "aggregate should still succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ja4=ja4-beta ja4h= ja4t=ja4t-beta"),
        "aggregate output changed unexpectedly: {stdout}"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test help_lists_supported_subcommands aggregate_correlates_pcap_output_records_within_window -- --nocapture`

Expected: FAIL after you start moving modules, because imports or dispatch paths are temporarily broken. If the tests still pass before any code movement, proceed immediately to the implementation step; the red phase is the first broken compile caused by the structural move.

- [ ] **Step 3: Write minimal implementation**

Do not change user-facing behavior. Only update module paths and imports as needed to keep the existing tests meaningful while files move.

```rust
use ja4finger::commands::{aggregate, daemon, pcap};

let result = match cli.command {
    Command::Daemon { config } => daemon::run(config, &runtime_state),
    Command::Pcap { file } => pcap::run(file, &runtime_state),
    Command::Aggregate { file, window_secs } => aggregate::run(file, window_secs),
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test help_lists_supported_subcommands aggregate_correlates_pcap_output_records_within_window -- --nocapture`

Expected: PASS with the same output assertions as before the refactor.

- [ ] **Step 5: Commit**

```bash
git add tests/cli.rs src/main.rs src/lib.rs src/commands src/aggregator.rs README.md
git commit -m "refactor: move CLI command runners into commands module"
```

### Task 2: Rename The Aggregation Engine Module

**Files:**
- Create: `src/aggregator.rs`
- Modify: `src/lib.rs`
- Modify: `src/main.rs`
- Delete: `src/aggregate.rs`

- [ ] **Step 1: Write the failing test**

Add or preserve a unit test that compiles against `ja4finger::aggregator` so the refactor has a concrete compile target after renaming.

```rust
use ja4finger::aggregator::aggregate_text;

#[test]
fn aggregate_text_requires_ja4_anchor_and_deduplicates_matching_values() {
    let input = "\
ts=10.000000 mode=pcap kind=ja4 value=ja4-a src=1.1.1.1:1111 dst=2.2.2.2:443
ts=11.000000 mode=pcap kind=ja4h value=ja4h-a src=1.1.1.1:1111 dst=2.2.2.2:443
ts=13.000000 mode=pcap kind=ja4t value=ja4t-a src=1.1.1.1:1111 dst=2.2.2.2:443
";

    let rendered = aggregate_text(input, 10)
        .expect("aggregation should succeed")
        .into_iter()
        .map(|record| record.render())
        .collect::<Vec<_>>();

    assert!(rendered.iter().any(|line| line.contains("ja4=ja4-a")));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test aggregate_text_requires_ja4_anchor_and_deduplicates_matching_values --lib -- --nocapture`

Expected: FAIL with an unresolved import for `ja4finger::aggregator` or a missing module error until the rename is complete.

- [ ] **Step 3: Write minimal implementation**

Copy the current aggregation engine from `src/aggregate.rs` into `src/aggregator.rs`, switch all imports to the new module name, then remove the old module file once all references are updated.

```rust
// src/lib.rs
pub mod aggregator;
pub mod capture;
pub mod cli;
pub mod commands;

// src/commands/aggregate.rs
use crate::aggregator;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test aggregate_text_requires_ja4_anchor_and_deduplicates_matching_values --lib -- --nocapture`

Expected: PASS with no behavior changes in aggregate rendering.

- [ ] **Step 5: Commit**

```bash
git add src/aggregator.rs src/lib.rs src/commands/aggregate.rs
git rm src/aggregate.rs
git commit -m "refactor: rename aggregate engine module"
```

### Task 3: Move The Aggregate Command Runner Into `src/commands/aggregate.rs`

**Files:**
- Create: `src/commands/aggregate.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write the failing test**

Keep the existing aggregate CLI integration tests as the red/green contract for this move.

```rust
#[test]
fn aggregate_correlates_daemon_log_records_within_window() {
    let input_path = unique_temp_text_path("aggregate-daemon");
    write_text_fixture(
        &input_path,
        "\
mode=daemon status=ready iface=eth0
ts=10.000000 mode=daemon kind=ja4 value=ja4-alpha src=192.168.1.10:42424 dst=192.168.1.20:443
ts=11.000000 mode=daemon kind=ja4h value=ja4h-alpha src=192.168.1.10:42424 dst=192.168.1.20:443
",
    );

    let input_arg = input_path.to_string_lossy().to_string();
    let output = run(&["aggregate", "--file", &input_arg, "--window-secs", "5"]);

    let _ = std::fs::remove_file(&input_path);

    assert!(output.status.success(), "aggregate command should succeed");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test aggregate_ -- --nocapture`

Expected: FAIL immediately after you remove `run_aggregate` from `src/main.rs` and before `src/commands/aggregate.rs` is wired in.

- [ ] **Step 3: Write minimal implementation**

Move the runner body into `src/commands/aggregate.rs` and expose a single `run(...)` function.

```rust
use crate::aggregator;

pub fn run(path: String, window_secs: u64) -> Result<(), String> {
    let input = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read aggregate input file {path}: {err}"))?;
    let records = aggregator::aggregate_text(&input, window_secs)?;

    for record in records {
        println!("{}", record.render());
    }

    Ok(())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test aggregate_ -- --nocapture`

Expected: PASS with the same daemon/pcap aggregate assertions as before.

- [ ] **Step 5: Commit**

```bash
git add src/commands/aggregate.rs src/main.rs src/aggregator.rs tests/cli.rs
git commit -m "refactor: move aggregate command into commands module"
```

### Task 4: Move The Pcap Command Runner Into `src/commands/pcap.rs`

**Files:**
- Create: `src/commands/pcap.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write the failing test**

Use the existing pcap integration tests as the contract. If needed, add one direct smoke assertion that still checks `pcap` summary output after the move.

```rust
#[test]
fn pcap_emits_ja4t_and_summary_for_syn_packets() {
    let pcap_path = unique_temp_pcap_path("ja4t-success");
    write_pcap(&pcap_path, &[tcp_syn_frame()]);
    let pcap_arg = pcap_path.to_string_lossy().to_string();

    let output = run(&["pcap", "--file", &pcap_arg]);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(output.status.success(), "pcap should still succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("kind=ja4t"), "missing JA4T: {stdout}");
    assert!(stdout.contains("packets_seen=1"), "missing summary: {stdout}");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test pcap_ -- --nocapture`

Expected: FAIL right after removing `run_pcap` from `src/main.rs` and before the new command module is connected.

- [ ] **Step 3: Write minimal implementation**

Move `run_pcap`, `extract_fingerprint`, `render_packet_fingerprint`, `emit_recoverable_parse_warning`, and `process_runtime_record` into `src/commands/pcap.rs`. Keep them private except for `run(...)`.

```rust
pub fn run(path: String, runtime_state: &RuntimeState) -> Result<(), String> {
    let source = CaptureSource::PcapFile(path);
    let pipeline = Pipeline::new(source);
    let source = pipeline.source().clone();
    let mut adapter = CaptureAdapter::from_source(source)
        .open()
        .map_err(|err| err.to_string())?;
    let mut runtime = PipelineRuntime::default();

    loop {
        match adapter.next_record().map_err(|err| err.to_string())? {
            Some(record) => {
                process_runtime_record(
                    runtime_state,
                    &mut runtime,
                    RuntimeMode::Pcap,
                    record,
                    None,
                    &mut |line| {
                        println!("{line}");
                        Ok(())
                    },
                )?;
            }
            None => break,
        }
    }

    let summary = runtime_state.summary(RuntimeMode::Pcap, runtime.counters().clone());
    println!("{}", summary.render());
    Ok(())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test pcap_ -- --nocapture`

Expected: PASS with identical fingerprint and summary output.

- [ ] **Step 5: Commit**

```bash
git add src/commands/pcap.rs src/main.rs tests/cli.rs
git commit -m "refactor: move pcap command into commands module"
```

### Task 5: Move The Daemon Command Runner Into `src/commands/daemon.rs`

**Files:**
- Create: `src/commands/daemon.rs`
- Modify: `src/main.rs`
- Modify: `src/commands/pcap.rs`

- [ ] **Step 1: Write the failing test**

Use the existing daemon integration tests and daemon unit tests as the contract for the move.

```rust
#[test]
fn daemon_with_valid_yaml_config_writes_default_dated_log_with_lifecycle_records() {
    let workdir = unique_temp_dir("daemon-valid-config-logs");
    let config_path = write_daemon_yaml_config(&workdir, &default_daemon_yaml("test-only-iface"));
    let config_arg = config_path.to_string_lossy().to_string();

    let output = run_with_env_and_current_dir(
        &["daemon", "--config", &config_arg],
        &[
            ("JA4FINGER_TEST_ONLY_DAEMON_SKIP_CAPTURE_OPEN", "1"),
            ("JA4FINGER_TEST_ONLY_DAEMON_REQUEST_SHUTDOWN", "1"),
        ],
        &workdir,
    );

    let _ = std::fs::remove_dir_all(&workdir);

    assert!(output.status.success(), "daemon should still exit cleanly");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test daemon_ -- --nocapture`

Expected: FAIL right after removing `run_daemon` from `src/main.rs` and before `src/commands/daemon.rs` is wired in.

- [ ] **Step 3: Write minimal implementation**

Move daemon-only code into `src/commands/daemon.rs`. Import `process_runtime_record` from `src/commands/pcap.rs` instead of building a new shared layer.

```rust
use super::pcap::process_runtime_record;

pub fn run(config_path: String, runtime_state: &RuntimeState) -> Result<(), String> {
    let config = load_daemon_config(std::path::Path::new(&config_path))?;
    let source = CaptureSource::Interface(config.iface.clone());
    let pipeline = Pipeline::new(source);
    let source = pipeline.source().clone();
    let skip_capture_open = env_flag(TEST_ONLY_DAEMON_SKIP_CAPTURE_OPEN_ENV);
    let mut adapter = if skip_capture_open {
        None
    } else {
        Some(
            CaptureAdapter::from_source(source)
                .open()
                .map_err(|err| err.to_string())?,
        )
    };
    let mut output = DaemonFileOutput::open(&config.log_dir, &config.log_file)?;
    let mut runtime = PipelineRuntime::default();

    // lifecycle handling unchanged
    Ok(())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test daemon_ -- --nocapture`

Expected: PASS with the same lifecycle log records and summary assertions.

- [ ] **Step 5: Commit**

```bash
git add src/commands/daemon.rs src/commands/pcap.rs src/main.rs
git commit -m "refactor: move daemon command into commands module"
```

### Task 6: Thin Down `src/main.rs` And Finalize Module Wiring

**Files:**
- Create: `src/commands/mod.rs`
- Modify: `src/main.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the failing test**

Use compile errors plus the existing CLI tests as the red phase. The contract is that `main.rs` becomes a thin entrypoint without changing user-facing behavior.

```rust
// src/commands/mod.rs
pub mod aggregate;
pub mod daemon;
pub mod pcap;

// src/main.rs
use ja4finger::commands::{aggregate, daemon, pcap};
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test help_lists_supported_subcommands daemon_ pcap_ aggregate_ -- --nocapture`

Expected: FAIL until `src/commands/mod.rs`, `src/lib.rs`, and `src/main.rs` all agree on module paths.

- [ ] **Step 3: Write minimal implementation**

Reduce `src/main.rs` to entrypoint-only code.

```rust
use std::process::ExitCode;

use ja4finger::cli::{self, Command};
use ja4finger::commands::{aggregate, daemon, pcap};
use ja4finger::output;
use ja4finger::runtime::RuntimeState;

fn main() -> ExitCode {
    output::init_logging();

    let cli = cli::parse();
    let runtime_state = RuntimeState::default();

    let result = match cli.command {
        Command::Daemon { config } => daemon::run(config, &runtime_state),
        Command::Pcap { file } => pcap::run(file, &runtime_state),
        Command::Aggregate { file, window_secs } => aggregate::run(file, window_secs),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test help_lists_supported_subcommands daemon_ pcap_ aggregate_ -- --nocapture`

Expected: PASS with unchanged CLI behavior.

- [ ] **Step 5: Commit**

```bash
git add src/commands/mod.rs src/main.rs src/lib.rs
git commit -m "refactor: make main entrypoint command-dispatch only"
```

### Task 7: Update Docs And Run Full Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Write the failing test**

There is no doc test harness here, so the failing signal is a manual review mismatch: the README should describe the same commands, and no command examples should change. Capture that explicitly before editing.

```markdown
CLI structure note:
- command runners live under `src/commands/`
- command names and examples stay the same
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo fmt --check`

Expected: This may fail while files are mid-move. Treat any formatting or compile failure here as the red phase before final cleanup.

- [ ] **Step 3: Write minimal implementation**

Add a short developer-facing note to `README.md` only if the repository already includes implementation-structure notes; otherwise keep README command examples unchanged and skip user-facing wording changes beyond what is needed for accuracy.

```markdown
开发验证：

```bash
cargo test
cargo fmt --check
```
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo fmt --check`
Expected: PASS

Run: `cargo test`
Expected: PASS with all existing integration and unit tests green.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: refresh notes after CLI command refactor"
```
