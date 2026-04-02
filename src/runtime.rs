use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::output::{RuntimeMode, SummaryReport};
use crate::pipeline::RuntimeCounters;

pub trait ShutdownHook {
    fn install(&self, state: RuntimeState) -> Result<(), String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopShutdownHook;

impl ShutdownHook for NoopShutdownHook {
    fn install(&self, _state: RuntimeState) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OsSignalShutdownHook;

#[cfg(unix)]
impl ShutdownHook for OsSignalShutdownHook {
    fn install(&self, state: RuntimeState) -> Result<(), String> {
        signal_hook::flag::register(
            signal_hook::consts::signal::SIGINT,
            state.shutdown_requested.clone(),
        )
        .map_err(|err| format!("failed to register SIGINT handler: {err}"))?;

        signal_hook::flag::register(
            signal_hook::consts::signal::SIGTERM,
            state.shutdown_requested.clone(),
        )
        .map_err(|err| format!("failed to register SIGTERM handler: {err}"))?;

        Ok(())
    }
}

#[cfg(not(unix))]
impl ShutdownHook for OsSignalShutdownHook {
    fn install(&self, _state: RuntimeState) -> Result<(), String> {
        Ok(())
    }
}

pub fn install_shutdown_hook(hook: &dyn ShutdownHook, state: &RuntimeState) -> Result<(), String> {
    hook.install(state.clone())
}

pub fn wait_for_shutdown(state: &RuntimeState, poll_interval: Duration) {
    while !state.shutdown_requested() {
        std::thread::sleep(poll_interval);
    }
}

#[derive(Clone, Default)]
pub struct RuntimeState {
    shutdown_requested: Arc<AtomicBool>,
    fingerprints_emitted: Arc<AtomicU64>,
}

impl RuntimeState {
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    pub fn record_fingerprint_emitted(&self) {
        self.fingerprints_emitted.fetch_add(1, Ordering::SeqCst);
    }

    pub fn summary(&self, mode: RuntimeMode, counters: RuntimeCounters) -> SummaryReport {
        SummaryReport {
            mode,
            counters,
            fingerprints_emitted: self.fingerprints_emitted.load(Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use crate::output::RuntimeMode;
    use crate::pipeline::RuntimeCounters;

    use super::{RuntimeState, ShutdownHook, install_shutdown_hook, wait_for_shutdown};

    struct MarkShutdownHook {
        called: Arc<AtomicBool>,
    }

    impl ShutdownHook for MarkShutdownHook {
        fn install(&self, state: RuntimeState) -> Result<(), String> {
            self.called.store(true, Ordering::SeqCst);
            state.request_shutdown();
            Ok(())
        }
    }

    #[test]
    fn runtime_state_tracks_shutdown_requests() {
        let state = RuntimeState::default();

        assert!(!state.shutdown_requested(), "shutdown should start cleared");

        state.request_shutdown();

        assert!(state.shutdown_requested(), "shutdown should become set");
    }

    #[test]
    fn runtime_state_counts_emitted_fingerprints_in_summary() {
        let mut counters = RuntimeCounters::default();
        counters.packets_seen = 10;
        counters.flows_tracked = 2;
        counters.parse_failures = 1;

        let state = RuntimeState::default();
        state.record_fingerprint_emitted();
        state.record_fingerprint_emitted();

        let summary = state.summary(RuntimeMode::Pcap, counters);

        assert_eq!(summary.fingerprints_emitted, 2);
        assert_eq!(summary.counters.packets_seen, 10);
        assert_eq!(summary.counters.flows_tracked, 2);
        assert_eq!(summary.counters.parse_failures, 1);
    }

    #[test]
    fn install_shutdown_hook_invokes_hook_with_runtime_state() {
        let called = Arc::new(AtomicBool::new(false));
        let hook = MarkShutdownHook {
            called: called.clone(),
        };
        let state = RuntimeState::default();

        install_shutdown_hook(&hook, &state).expect("hook installation should succeed");

        assert!(
            called.load(Ordering::SeqCst),
            "hook should be called during installation"
        );
        assert!(
            state.shutdown_requested(),
            "hook should be able to request shutdown via runtime state"
        );
    }

    #[test]
    fn wait_for_shutdown_returns_immediately_when_shutdown_already_requested() {
        let state = RuntimeState::default();
        state.request_shutdown();

        wait_for_shutdown(&state, Duration::from_millis(1));

        assert!(state.shutdown_requested(), "shutdown should stay requested");
    }
}
