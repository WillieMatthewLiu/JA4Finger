use std::process::ExitCode;
use std::time::Duration;

use ja4finger::capture::{CaptureAdapter, CaptureSource, PacketRecord};
use ja4finger::cli::{self, Command};
use ja4finger::config::{DaemonRuntimeConfig, load_daemon_config};
use ja4finger::fingerprint::{
    FingerprintKind, HttpClientFeatures, TcpClientFeatures, TlsClientHelloFeatures,
};
use ja4finger::output::{self, DaemonFileOutput, FingerprintEmission, RuntimeMode};
use ja4finger::pipeline::{DecodedPacket, Pipeline, PipelineRuntime};
use ja4finger::runtime::{
    OsSignalShutdownHook, RuntimeState, install_shutdown_hook, wait_for_shutdown,
};

const DAEMON_POLL_INTERVAL: Duration = Duration::from_millis(50);
const TEST_ONLY_DAEMON_SKIP_CAPTURE_OPEN_ENV: &str = "JA4FINGER_TEST_ONLY_DAEMON_SKIP_CAPTURE_OPEN";
const TEST_ONLY_DAEMON_REQUEST_SHUTDOWN_ENV: &str = "JA4FINGER_TEST_ONLY_DAEMON_REQUEST_SHUTDOWN";

fn main() -> ExitCode {
    output::init_logging();

    let cli = cli::parse();
    let runtime_state = RuntimeState::default();

    let result = match cli.command {
        Command::Daemon { config } => run_daemon(config, &runtime_state),
        Command::Pcap { file } => run_pcap(file, &runtime_state),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run_daemon(config_path: String, runtime_state: &RuntimeState) -> Result<(), String> {
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

    if let Err(err) = install_shutdown_hook(&OsSignalShutdownHook, runtime_state) {
        tracing::warn!(error = %err, "failed to install shutdown hook");
    }

    output.write_line(&format!("mode=daemon status=ready iface={}", config.iface))?;
    if env_flag(TEST_ONLY_DAEMON_REQUEST_SHUTDOWN_ENV) {
        runtime_state.request_shutdown();
    }

    if let Some(adapter) = adapter.as_mut() {
        while !runtime_state.shutdown_requested() {
            match adapter.next_record().map_err(|err| err.to_string())? {
                Some(record) => {
                    process_runtime_record(
                        runtime_state,
                        &mut runtime,
                        RuntimeMode::Daemon,
                        record,
                        Some(&config),
                        &mut |line| output.write_line(&line),
                    )?;
                }
                None => continue,
            }
        }
    } else {
        wait_for_shutdown(runtime_state, DAEMON_POLL_INTERVAL);
    }

    output.write_line(&format!(
        "mode=daemon status=stopped iface={} reason=shutdown",
        config.iface
    ))?;
    let summary = runtime_state.summary(RuntimeMode::Daemon, runtime.counters().clone());
    output.write_line(&summary.render())?;
    Ok(())
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn extract_fingerprint(
    record: &PacketRecord,
    decoded: &DecodedPacket,
) -> Option<(FingerprintKind, String)> {
    if let Ok(features) = TcpClientFeatures::extract(record) {
        return Some((FingerprintKind::Ja4T, features.fingerprint_string()));
    }

    if let Ok(features) = HttpClientFeatures::extract(&decoded.payload) {
        return Some((FingerprintKind::Ja4H, features.fingerprint_string()));
    }

    if let Ok(features) = TlsClientHelloFeatures::extract(&decoded.payload) {
        return Some((FingerprintKind::Ja4, features.fingerprint_string()));
    }

    None
}

fn emit_recoverable_parse_warning<E: std::fmt::Display>(err: E) {
    tracing::warn!(error = %err, "skipping packet parse failure");
    eprintln!("skipping packet parse failure: {err}");
}

fn render_packet_fingerprint(
    record: &PacketRecord,
    decoded: &DecodedPacket,
    mode: RuntimeMode,
    kind: FingerprintKind,
    value: impl Into<String>,
) -> String {
    FingerprintEmission::from_packet_context(record, decoded, mode, kind, value).render()
}

fn excluded_by_daemon_config(config: &DaemonRuntimeConfig, decoded: &DecodedPacket) -> bool {
    let Ok(src_ip) = decoded.flow_key.src_ip.parse() else {
        return false;
    };
    let Ok(dst_ip) = decoded.flow_key.dst_ip.parse() else {
        return false;
    };

    config.src_excludes.matches(src_ip) || config.dst_excludes.matches(dst_ip)
}

fn process_runtime_record<F>(
    runtime_state: &RuntimeState,
    runtime: &mut PipelineRuntime,
    mode: RuntimeMode,
    record: PacketRecord,
    daemon_config: Option<&DaemonRuntimeConfig>,
    emit_line: &mut F,
) -> Result<(), String>
where
    F: FnMut(String) -> Result<(), String>,
{
    let decoded = match runtime.process_record(&record) {
        Ok(Some(decoded)) => decoded,
        Ok(None) => return Ok(()),
        Err(err) => {
            emit_recoverable_parse_warning(err);
            return Ok(());
        }
    };

    if daemon_config.is_some_and(|config| excluded_by_daemon_config(config, &decoded)) {
        return Ok(());
    }

    match extract_fingerprint(&record, &decoded) {
        Some((kind, value)) => {
            let rendered = match mode {
                RuntimeMode::Pcap => {
                    render_packet_fingerprint(&record, &decoded, mode, kind, value)
                }
                RuntimeMode::Daemon => {
                    render_packet_fingerprint(&record, &decoded, mode, kind, value)
                }
            };
            emit_line(rendered)?;
            runtime_state.record_fingerprint_emitted();
        }
        None => runtime.record_extraction_failure(),
    }

    Ok(())
}

fn run_pcap(path: String, runtime_state: &RuntimeState) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;
    use ja4finger::capture::PacketRecord;
    use ja4finger::config::parse_daemon_config;

    use super::{RuntimeMode, RuntimeState, process_runtime_record};
    use ja4finger::pipeline::PipelineRuntime;

    fn http1_record(src: [u8; 4], dst: [u8; 4]) -> PacketRecord {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4(src, dst, 32)
            .tcp(42424, 80, 1, 4096);

        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut packet, payload)
            .expect("packet should serialize");

        PacketRecord {
            timestamp_secs: 1,
            timestamp_micros: 2,
            captured_len: packet.len() as u32,
            original_len: packet.len() as u32,
            data: packet,
        }
    }

    #[test]
    fn daemon_src_exclusion_skips_output_without_counting_failures() {
        let config = parse_daemon_config(
            "daemon:\n  iface: eth0\n  src_excludes: [192.168.1.10]\n  dst_excludes: []\n",
        )
        .expect("config should parse");
        let state = RuntimeState::default();
        let mut runtime = PipelineRuntime::default();
        let mut lines = Vec::new();

        process_runtime_record(
            &state,
            &mut runtime,
            RuntimeMode::Daemon,
            http1_record([192, 168, 1, 10], [203, 0, 113, 10]),
            Some(&config),
            &mut |line| {
                lines.push(line);
                Ok(())
            },
        )
        .expect("excluded packet should be processed cleanly");

        let counters = runtime.counters().clone();
        let summary = state.summary(RuntimeMode::Daemon, counters.clone());

        assert!(
            lines.is_empty(),
            "excluded source packet should not emit output"
        );
        assert_eq!(counters.packets_seen, 1);
        assert_eq!(counters.parse_failures, 0);
        assert_eq!(counters.extraction_failures, 0);
        assert_eq!(summary.fingerprints_emitted, 0);
    }

    #[test]
    fn daemon_destination_cidr_exclusion_skips_output_without_counting_failures() {
        let config = parse_daemon_config(
            "daemon:\n  iface: eth0\n  src_excludes: []\n  dst_excludes: [198.51.100.0/24]\n",
        )
        .expect("config should parse");
        let state = RuntimeState::default();
        let mut runtime = PipelineRuntime::default();
        let mut lines = Vec::new();

        process_runtime_record(
            &state,
            &mut runtime,
            RuntimeMode::Daemon,
            http1_record([203, 0, 113, 10], [198, 51, 100, 20]),
            Some(&config),
            &mut |line| {
                lines.push(line);
                Ok(())
            },
        )
        .expect("excluded packet should be processed cleanly");

        let counters = runtime.counters().clone();
        let summary = state.summary(RuntimeMode::Daemon, counters.clone());

        assert!(
            lines.is_empty(),
            "excluded destination packet should not emit output"
        );
        assert_eq!(counters.packets_seen, 1);
        assert_eq!(counters.parse_failures, 0);
        assert_eq!(counters.extraction_failures, 0);
        assert_eq!(summary.fingerprints_emitted, 0);
    }
}
