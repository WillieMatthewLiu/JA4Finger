use crate::capture::{CaptureAdapter, CaptureSource, PacketRecord};
use crate::config::DaemonRuntimeConfig;
use crate::fingerprint::{
    FingerprintKind, HttpClientFeatures, TcpClientFeatures, TlsClientHelloFeatures,
};
use crate::output::{FingerprintEmission, RuntimeMode};
use crate::pipeline::{DecodedPacket, Pipeline, PipelineRuntime};
use crate::runtime::RuntimeState;

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

pub(crate) fn process_runtime_record<F>(
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
            let rendered = render_packet_fingerprint(&record, &decoded, mode, kind, value);
            emit_line(rendered)?;
            runtime_state.record_fingerprint_emitted();
        }
        None => runtime.record_extraction_failure(),
    }

    Ok(())
}
