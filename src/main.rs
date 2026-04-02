use std::process::ExitCode;
use std::time::Duration;

use ja4finger::capture::{CaptureAdapter, CaptureSource, PacketRecord};
use ja4finger::cli::{self, Command};
use ja4finger::fingerprint::{
    FingerprintKind, HttpClientFeatures, TcpClientFeatures, TlsClientHelloFeatures,
};
use ja4finger::output::{self, FingerprintEmission, RuntimeMode};
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
        Command::Daemon { iface } => run_daemon(iface, &runtime_state),
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

fn run_daemon(iface: String, runtime_state: &RuntimeState) -> Result<(), String> {
    let source = CaptureSource::Interface(iface.clone());
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
    let mut runtime = PipelineRuntime::default();

    if let Err(err) = install_shutdown_hook(&OsSignalShutdownHook, runtime_state) {
        tracing::warn!(error = %err, "failed to install shutdown hook");
    }

    println!("mode=daemon status=ready iface={iface}");
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
                    );
                }
                None => continue,
            }
        }
    } else {
        wait_for_shutdown(runtime_state, DAEMON_POLL_INTERVAL);
    }

    println!("mode=daemon status=stopped iface={iface} reason=shutdown");
    let summary = runtime_state.summary(RuntimeMode::Daemon, runtime.counters().clone());
    println!("{}", summary.render());
    Ok(())
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn emit_fingerprint(runtime_state: &RuntimeState, emission: FingerprintEmission) {
    println!("{}", emission.render());
    runtime_state.record_fingerprint_emitted();
}

fn emit_packet_fingerprint(
    runtime_state: &RuntimeState,
    record: &PacketRecord,
    decoded: &DecodedPacket,
    mode: RuntimeMode,
    kind: FingerprintKind,
    value: impl Into<String>,
) {
    let emission = FingerprintEmission::from_packet_context(record, decoded, mode, kind, value);
    emit_fingerprint(runtime_state, emission);
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

fn process_runtime_record(
    runtime_state: &RuntimeState,
    runtime: &mut PipelineRuntime,
    mode: RuntimeMode,
    record: PacketRecord,
) {
    let decoded = match runtime.process_record(&record) {
        Ok(Some(decoded)) => decoded,
        Ok(None) => return,
        Err(err) => {
            emit_recoverable_parse_warning(err);
            return;
        }
    };

    match extract_fingerprint(&record, &decoded) {
        Some((kind, value)) => {
            emit_packet_fingerprint(runtime_state, &record, &decoded, mode, kind, value);
        }
        None => runtime.record_extraction_failure(),
    }
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
                process_runtime_record(runtime_state, &mut runtime, RuntimeMode::Pcap, record);
            }
            None => break,
        }
    }

    let summary = runtime_state.summary(RuntimeMode::Pcap, runtime.counters().clone());
    println!("{}", summary.render());
    Ok(())
}
