use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use etherparse::{PacketBuilder, TcpOptionElement};
use pcap_file::pcap::{PcapPacket, PcapWriter};

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ja4finger"))
        .args(args)
        .output()
        .expect("failed to run ja4finger")
}

fn run_with_env(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ja4finger"));
    cmd.args(args);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("failed to run ja4finger with env")
}

fn run_with_env_and_current_dir(
    args: &[&str],
    envs: &[(&str, &str)],
    current_dir: &Path,
) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ja4finger"));
    cmd.args(args).current_dir(current_dir);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output()
        .expect("failed to run ja4finger with env/current_dir")
}

fn spawn_with_env_and_current_dir(
    args: &[&str],
    envs: &[(&str, &str)],
    current_dir: &Path,
) -> std::process::Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ja4finger"));
    cmd.args(args)
        .current_dir(current_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.spawn()
        .expect("failed to spawn ja4finger with env/current_dir")
}

fn unique_temp_pcap_path(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();

    std::env::temp_dir().join(format!(
        "ja4finger-{tag}-{}-{nanos}.pcap",
        std::process::id()
    ))
}

fn unique_temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ja4finger-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp directory should be creatable");
    dir
}

fn write_daemon_yaml_config(current_dir: &Path, yaml: &str) -> PathBuf {
    let config_path = current_dir.join("daemon-config.yaml");
    std::fs::write(&config_path, yaml).expect("yaml config should be writable");
    config_path
}

fn default_daemon_yaml(iface: &str) -> String {
    format!("daemon:\n  iface: {iface}\n  src_excludes: []\n  dst_excludes: []\n")
}

fn today_yyyymmdd() -> String {
    let output = Command::new("date")
        .arg("+%Y%m%d")
        .output()
        .expect("date command should be available");
    assert!(
        output.status.success(),
        "date command should succeed: {:?}",
        output.status
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn read_single_log_file(logs_dir: &Path) -> (PathBuf, String) {
    let mut log_files = std::fs::read_dir(logs_dir)
        .expect("logs directory should be readable")
        .map(|entry| entry.expect("log dir entry should be readable").path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();

    log_files.sort();
    let log_file = log_files
        .pop()
        .expect("logs directory should contain at least one file");

    let content =
        std::fs::read_to_string(&log_file).expect("log file should be readable as UTF-8 text");
    (log_file, content)
}

fn write_pcap(path: &Path, frames: &[Vec<u8>]) {
    let file = File::create(path).expect("pcap file should be creatable");
    let mut writer = PcapWriter::new(file).expect("pcap writer should initialize");

    for (idx, frame) in frames.iter().enumerate() {
        let packet = PcapPacket::new_owned(
            Duration::from_secs(1 + idx as u64),
            frame.len() as u32,
            frame.clone(),
        );
        writer
            .write_packet(&packet)
            .expect("pcap packet should be writable");
    }

    writer.flush().expect("pcap writer should flush");
}

fn tcp_syn_frame() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
        .tcp(42424, 443, 1, 64240)
        .syn()
        .options(&[
            TcpOptionElement::MaximumSegmentSize(1460),
            TcpOptionElement::Noop,
            TcpOptionElement::WindowScale(8),
            TcpOptionElement::Noop,
            TcpOptionElement::Noop,
            TcpOptionElement::SelectiveAcknowledgementPermitted,
        ])
        .expect("tcp syn options should be valid");

    let payload = [];
    let mut frame = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut frame, &payload)
        .expect("frame should serialize");
    frame
}

fn tls_client_hello_payload() -> Vec<u8> {
    vec![
        0x16, 0x03, 0x01, 0x00, 0x61, 0x01, 0x00, 0x00, 0x5d, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00,
        0x06, 0x13, 0x01, 0x0a, 0x0a, 0x13, 0x02, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x0a,
        0x00, 0x08, 0x00, 0x00, 0x05, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x2b, 0x00, 0x05, 0x04,
        0x03, 0x04, 0x03, 0x03, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x05, 0x03, 0x00,
        0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32, 0x0a, 0x0a, 0x00, 0x00,
    ]
}

fn tls_client_hello_frame() -> Vec<u8> {
    let payload = tls_client_hello_payload();
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
        .tcp(42424, 443, 1, 4096);

    let mut frame = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut frame, &payload)
        .expect("frame should serialize");
    frame
}

fn http1_request_payload() -> Vec<u8> {
    b"GET /index.html HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: curl/8.0\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
Referer: https://example.com/\r\n\
Cookie: session=abc123; theme=light\r\n\
X-Trace-Id: abc\r\n\
\r\n"
        .to_vec()
}

fn http1_request_frame() -> Vec<u8> {
    let payload = http1_request_payload();
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
        .tcp(42424, 80, 1, 4096);

    let mut frame = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut frame, &payload)
        .expect("frame should serialize");
    frame
}

fn h2c_prior_knowledge_payload() -> Vec<u8> {
    let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    payload.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // empty SETTINGS
        0x00, 0x00, 0x43, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, // HEADERS frame
        0x82, 0x84, 0x86, // :method GET, :path /, :scheme http
        0x01, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
        b'm', // :authority: example.com
        0x0f, 0x2b, 0x08, b'h', b'2', b'c', b'-', b't', b'e', b's',
        b't', // user-agent: h2c-test
        0x0f, 0x02, 0x0e, b'f', b'r', b'-', b'C', b'A', b',', b'f', b'r', b';', b'q', b'=', b'0',
        b'.', b'8', // accept-language: fr-CA,fr;q=0.8
        0x0f, 0x11, 0x08, b'b', b'=', b'2', b';', b' ', b'a', b'=', b'1', // cookie: b=2; a=1
        0x00, 0x08, b'x', b'-', b'c', b'u', b's', b't', b'o', b'm', 0x01, b'z', // x-custom: z
    ]);
    payload
}

fn h2c_upgrade_with_following_h2_payload() -> Vec<u8> {
    let mut payload = b"GET / HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: Upgrade, HTTP2-Settings\r\n\
Upgrade: h2c\r\n\
HTTP2-Settings: AAMAAABkAAQAAAP_\r\n\
\r\n"
        .to_vec();
    payload.extend_from_slice(&h2c_prior_knowledge_payload());
    payload
}

fn h2c_prior_knowledge_frame() -> Vec<u8> {
    let payload = h2c_prior_knowledge_payload();
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
        .tcp(42424, 80, 1, 4096);

    let mut frame = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut frame, &payload)
        .expect("frame should serialize");
    frame
}

fn h2c_upgrade_with_following_h2_frame() -> Vec<u8> {
    let payload = h2c_upgrade_with_following_h2_payload();
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
        .tcp(42424, 80, 1, 4096);

    let mut frame = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut frame, &payload)
        .expect("frame should serialize");
    frame
}

fn undecodable_client_payload_frame() -> Vec<u8> {
    let payload = b"this-is-not-http-or-tls".to_vec();
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([192, 168, 1, 10], [192, 168, 1, 20], 32)
        .tcp(42424, 8080, 1, 4096);

    let mut frame = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut frame, &payload)
        .expect("frame should serialize");
    frame
}

#[test]
fn daemon_requires_config_argument() {
    let output = run(&["daemon"]);

    assert!(
        !output.status.success(),
        "daemon without --config should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--config"),
        "stderr should mention missing --config, got: {stderr}"
    );
}

#[test]
fn pcap_requires_file_argument() {
    let output = run(&["pcap"]);

    assert!(!output.status.success(), "pcap without --file should fail");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--file"),
        "stderr should mention missing --file, got: {stderr}"
    );
}

#[test]
fn help_lists_supported_subcommands() {
    let output = run(&["--help"]);

    assert!(output.status.success(), "--help should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("daemon"),
        "help output should mention daemon, got: {stdout}"
    );
    assert!(
        stdout.contains("pcap"),
        "help output should mention pcap, got: {stdout}"
    );
}

#[test]
fn pcap_returns_non_zero_for_missing_file() {
    let output = run(&["pcap", "--file", "fixtures/does-not-exist.pcap"]);

    assert!(
        !output.status.success(),
        "pcap should fail for a missing input file"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does-not-exist.pcap"),
        "stderr should mention the missing file, got: {stderr}"
    );
}

#[test]
fn daemon_returns_non_zero_for_missing_yaml_config_file() {
    let output = run(&["daemon", "--config", "fixtures/does-not-exist.yaml"]);

    assert!(
        !output.status.success(),
        "daemon should fail for a missing yaml config file"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does-not-exist.yaml"),
        "stderr should mention the missing config file, got: {stderr}"
    );
}

#[test]
fn daemon_returns_non_zero_for_malformed_yaml_config() {
    let workdir = unique_temp_dir("daemon-invalid-yaml");
    let config_path = write_daemon_yaml_config(
        &workdir,
        "daemon:\n  iface: test-only-iface\n  src_excludes: [not-closed\n",
    );
    let config_arg = config_path.to_string_lossy().to_string();

    let output = run_with_env_and_current_dir(&["daemon", "--config", &config_arg], &[], &workdir);

    let _ = std::fs::remove_dir_all(&workdir);

    assert!(
        !output.status.success(),
        "daemon should fail for malformed yaml config"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("yaml")
            || stderr.to_lowercase().contains("config")
            || stderr.to_lowercase().contains("parse"),
        "stderr should mention config parse failure: {stderr}"
    );
}

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

    let logs_dir = workdir.join("logs");
    assert!(logs_dir.is_dir(), "daemon should create ./logs by default");
    let (log_file, log_content) = read_single_log_file(&logs_dir);
    let log_filename = log_file
        .file_name()
        .and_then(|name| name.to_str())
        .expect("log file name should be valid UTF-8");
    let date_prefix = today_yyyymmdd();
    assert!(
        log_filename.starts_with(&date_prefix),
        "default log file should start with yyyyMMdd={date_prefix}, got: {log_filename}"
    );

    let _ = std::fs::remove_dir_all(&workdir);

    assert!(
        output.status.success(),
        "daemon should exit cleanly when shutdown is requested in foreground lifecycle with valid yaml config"
    );
    assert!(
        log_content.contains("mode=daemon status=ready"),
        "daemon log should include ready lifecycle record: {log_content}"
    );
    assert!(
        log_content.contains("mode=daemon status=stopped"),
        "daemon log should include stopped lifecycle record: {log_content}"
    );
    assert!(
        log_content.contains("mode=daemon"),
        "daemon log should include daemon summary mode line: {log_content}"
    );
    assert!(
        log_content.contains("packets_seen=0"),
        "daemon summary should include packets_seen=0 in controlled shutdown test: {log_content}"
    );
    assert!(
        log_content.contains("parse_failures=0"),
        "daemon summary should include parse_failures=0 in controlled shutdown test: {log_content}"
    );
    assert!(
        log_content.contains("extraction_failures=0"),
        "daemon summary should include extraction_failures=0 in controlled shutdown test: {log_content}"
    );
}

#[test]
fn daemon_handles_sigterm_with_clean_shutdown_and_summary() {
    let workdir = unique_temp_dir("daemon-sigterm");
    let config_path = write_daemon_yaml_config(&workdir, &default_daemon_yaml("test-only-iface"));
    let config_arg = config_path.to_string_lossy().to_string();

    let child = spawn_with_env_and_current_dir(
        &["daemon", "--config", &config_arg],
        &[("JA4FINGER_TEST_ONLY_DAEMON_SKIP_CAPTURE_OPEN", "1")],
        &workdir,
    );

    std::thread::sleep(Duration::from_millis(150));
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("failed to send SIGTERM to daemon process");
    assert!(
        status.success(),
        "kill -TERM should succeed for daemon process pid={pid}"
    );

    let output = child
        .wait_with_output()
        .expect("failed to wait for daemon process output");

    let logs_dir = workdir.join("logs");
    assert!(
        logs_dir.is_dir(),
        "daemon should create ./logs directory in configured current_dir"
    );
    let (_, log_content) = read_single_log_file(&logs_dir);

    let _ = std::fs::remove_dir_all(&workdir);

    assert!(
        output.status.success(),
        "daemon should handle SIGTERM as a clean shutdown"
    );
    assert!(
        log_content.contains("mode=daemon status=ready"),
        "daemon log should report ready status before signal shutdown: {log_content}"
    );
    assert!(
        log_content.contains("mode=daemon status=stopped"),
        "daemon log should report signal-driven shutdown reason: {log_content}"
    );
    assert!(
        log_content.contains("mode=daemon"),
        "daemon log should emit final summary after signal shutdown: {log_content}"
    );
    assert!(
        log_content.contains("packets_seen=0"),
        "daemon summary should include packets_seen=0 in signal shutdown test: {log_content}"
    );
    assert!(
        log_content.contains("parse_failures=0"),
        "daemon summary should include parse_failures=0 in signal shutdown test: {log_content}"
    );
    assert!(
        log_content.contains("extraction_failures=0"),
        "daemon summary should include extraction_failures=0 in signal shutdown test: {log_content}"
    );
}

#[test]
fn pcap_emits_ja4t_and_summary_for_syn_packets() {
    let pcap_path = unique_temp_pcap_path("ja4t-success");
    write_pcap(&pcap_path, &[tcp_syn_frame()]);
    let pcap_arg = pcap_path.to_string_lossy().to_string();

    let output = run(&["pcap", "--file", &pcap_arg]);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(
        output.status.success(),
        "pcap should succeed for valid input"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("mode=pcap"),
        "stdout should include pcap mode: {stdout}"
    );
    assert!(
        stdout.contains("kind=ja4t"),
        "stdout should include JA4T emission: {stdout}"
    );
    assert!(
        stdout.contains("value=64240_2-1-3-1-1-4_1460_8"),
        "stdout should include expected JA4T value: {stdout}"
    );
    assert!(
        stdout.contains("packets_seen=1"),
        "summary should include packets_seen=1: {stdout}"
    );
    assert!(
        stdout.contains("flows_tracked=1"),
        "summary should include flows_tracked=1: {stdout}"
    );
    assert!(
        stdout.contains("fingerprints_emitted=1"),
        "summary should include fingerprints_emitted=1: {stdout}"
    );
    assert!(
        stdout.contains("parse_failures=0"),
        "summary should include parse_failures=0: {stdout}"
    );
}

#[test]
fn pcap_continues_after_parse_failure_and_still_summarizes() {
    let pcap_path = unique_temp_pcap_path("recoverable-parse-failure");
    write_pcap(&pcap_path, &[vec![1, 2, 3], tcp_syn_frame()]);
    let pcap_arg = pcap_path.to_string_lossy().to_string();

    let output = run_with_env(&["pcap", "--file", &pcap_arg], &[("RUST_LOG", "warn")]);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(
        output.status.success(),
        "pcap should continue for recoverable parse failures and finish successfully"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ja4t_lines = stdout.matches("kind=ja4t").count();

    assert_eq!(
        ja4t_lines, 1,
        "exactly one JA4T emission expected: {stdout}"
    );
    assert!(
        stdout.contains("packets_seen=2"),
        "summary should include packets_seen=2: {stdout}"
    );
    assert!(
        stdout.contains("flows_tracked=1"),
        "summary should include flows_tracked=1: {stdout}"
    );
    assert!(
        stdout.contains("fingerprints_emitted=1"),
        "summary should include fingerprints_emitted=1: {stdout}"
    );
    assert!(
        stdout.contains("parse_failures=1"),
        "summary should include parse_failures=1: {stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("skipping packet parse failure"),
        "stderr should include recoverable parse warning: {stderr}"
    );
}

#[test]
fn pcap_malformed_then_valid_packets_keep_emitting_ja4_ja4h_and_ja4t() {
    let pcap_path = unique_temp_pcap_path("malformed-then-mixed-valid");
    write_pcap(
        &pcap_path,
        &[
            vec![1, 2, 3],
            tls_client_hello_frame(),
            http1_request_frame(),
            tcp_syn_frame(),
        ],
    );
    let pcap_arg = pcap_path.to_string_lossy().to_string();

    let output = run_with_env(&["pcap", "--file", &pcap_arg], &[("RUST_LOG", "warn")]);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(
        output.status.success(),
        "pcap should keep processing valid packets after malformed traffic"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("value=t13d0204h2_62ed6f6ca7ad_0442b87b8999"),
        "stdout should include JA4 from valid TLS packet after malformed packet: {stdout}"
    );
    assert!(
        stdout.contains("value=ge11cr04enus_33f7519adbc8_6263fd0189b4_230379c57c15"),
        "stdout should include JA4H from valid HTTP/1.x packet after malformed packet: {stdout}"
    );
    assert!(
        stdout.contains("value=64240_2-1-3-1-1-4_1460_8"),
        "stdout should include JA4T from valid SYN packet after malformed packet: {stdout}"
    );
    assert!(
        stdout.contains("packets_seen=4"),
        "summary should include packets_seen=4: {stdout}"
    );
    assert!(
        stdout.contains("fingerprints_emitted=3"),
        "summary should include fingerprints_emitted=3: {stdout}"
    );
    assert!(
        stdout.contains("parse_failures=1"),
        "summary should include parse_failures=1: {stdout}"
    );
    assert!(
        stdout.contains("extraction_failures=0"),
        "summary should include extraction_failures=0: {stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("skipping packet parse failure"),
        "stderr should include recoverable parse warning: {stderr}"
    );
}

#[test]
fn pcap_returns_explicit_non_zero_for_unsupported_file_format() {
    let pcap_path = unique_temp_pcap_path("unsupported-format");
    std::fs::write(&pcap_path, b"not-a-pcap-header")
        .expect("invalid pcap fixture should be writable");
    let pcap_arg = pcap_path.to_string_lossy().to_string();

    let output = run(&["pcap", "--file", &pcap_arg]);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(
        !output.status.success(),
        "pcap should fail for unsupported file formats"
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "unsupported file format should return an explicit non-zero status"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("mode=pcap"),
        "stdout should not include pcap summary when startup fails: {stdout}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "stderr should provide an error for unsupported file format"
    );
}

#[test]
fn pcap_summary_includes_extraction_failures_for_recoverable_feature_misses() {
    let pcap_path = unique_temp_pcap_path("extraction-failure-summary");
    write_pcap(&pcap_path, &[undecodable_client_payload_frame()]);
    let pcap_arg = pcap_path.to_string_lossy().to_string();

    let output = run(&["pcap", "--file", &pcap_arg]);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(
        output.status.success(),
        "pcap should succeed when packet decode succeeds but feature extraction fails"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("packets_seen=1"),
        "summary should include packets_seen=1: {stdout}"
    );
    assert!(
        stdout.contains("fingerprints_emitted=0"),
        "summary should include fingerprints_emitted=0: {stdout}"
    );
    assert!(
        stdout.contains("parse_failures=0"),
        "summary should include parse_failures=0: {stdout}"
    );
    assert!(
        stdout.contains("extraction_failures=1"),
        "summary should include extraction_failures=1: {stdout}"
    );
}

#[test]
fn pcap_emits_ja4_for_tls_client_hello_payload() {
    let pcap_path = unique_temp_pcap_path("ja4-success");
    write_pcap(&pcap_path, &[tls_client_hello_frame()]);
    let pcap_arg = pcap_path.to_string_lossy().to_string();

    let output = run(&["pcap", "--file", &pcap_arg]);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(
        output.status.success(),
        "pcap should succeed for valid TLS clienthello input"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("kind=ja4"),
        "stdout should include JA4 emission: {stdout}"
    );
    assert!(
        stdout.contains("value=t13d0204h2_62ed6f6ca7ad_0442b87b8999"),
        "stdout should include expected JA4 value: {stdout}"
    );
    assert!(
        stdout.contains("packets_seen=1"),
        "summary should include packets_seen=1: {stdout}"
    );
    assert!(
        stdout.contains("fingerprints_emitted=1"),
        "summary should include fingerprints_emitted=1: {stdout}"
    );
}

#[test]
fn pcap_emits_ja4h_for_http1_client_request_payload() {
    let pcap_path = unique_temp_pcap_path("ja4h-http1");
    write_pcap(&pcap_path, &[http1_request_frame()]);
    let pcap_arg = pcap_path.to_string_lossy().to_string();

    let output = run(&["pcap", "--file", &pcap_arg]);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(
        output.status.success(),
        "pcap should succeed for valid HTTP/1.1 request payload"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("kind=ja4h"),
        "stdout should include JA4H emission: {stdout}"
    );
    assert!(
        stdout.contains("value=ge11cr04enus_33f7519adbc8_6263fd0189b4_230379c57c15"),
        "stdout should include expected JA4H value: {stdout}"
    );
    assert!(
        stdout.contains("fingerprints_emitted=1"),
        "summary should include fingerprints_emitted=1: {stdout}"
    );
}

#[test]
fn pcap_emits_ja4h_for_h2c_prior_knowledge_request_payload() {
    let pcap_path = unique_temp_pcap_path("ja4h-h2c");
    write_pcap(&pcap_path, &[h2c_prior_knowledge_frame()]);
    let pcap_arg = pcap_path.to_string_lossy().to_string();

    let output = run(&["pcap", "--file", &pcap_arg]);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(
        output.status.success(),
        "pcap should succeed for valid h2c prior-knowledge request payload"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("kind=ja4h"),
        "stdout should include JA4H emission: {stdout}"
    );
    assert!(
        stdout.contains("value=ge20cn03frca_acc1f387590f_1eb7c54d5283_06beefe2b477"),
        "stdout should include expected JA4H value for h2c request: {stdout}"
    );
    assert!(
        stdout.contains("fingerprints_emitted=1"),
        "summary should include fingerprints_emitted=1: {stdout}"
    );
}

#[test]
fn pcap_emits_upgraded_h2c_ja4h_instead_of_http1_upgrade_request_ja4h() {
    let pcap_path = unique_temp_pcap_path("ja4h-h2c-upgrade");
    write_pcap(&pcap_path, &[h2c_upgrade_with_following_h2_frame()]);
    let pcap_arg = pcap_path.to_string_lossy().to_string();

    let output = run(&["pcap", "--file", &pcap_arg]);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(
        output.status.success(),
        "pcap should succeed for valid upgrade-based h2c request payload"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("kind=ja4h"),
        "stdout should include JA4H emission: {stdout}"
    );
    assert!(
        stdout.contains("value=ge20cn03frca_acc1f387590f_1eb7c54d5283_06beefe2b477"),
        "stdout should include upgraded h2c JA4H value: {stdout}"
    );
    assert!(
        !stdout.contains("value=ge11cr04enus_33f7519adbc8_6263fd0189b4_230379c57c15"),
        "stdout should not include HTTP/1.x upgrade request JA4H value: {stdout}"
    );
    assert!(
        stdout.contains("fingerprints_emitted=1"),
        "summary should include fingerprints_emitted=1: {stdout}"
    );
}
