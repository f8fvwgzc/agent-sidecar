//! OpenTelemetry wiring (design §9): the exporter starts with the first charter that turns traces
//! or metrics on (at start-up or on a reload), later reloads only change its flags (the endpoint
//! is restart-only), and it is shut down with the sidecar.
use attache_charter::Charter;
use attache_otel::{ExportFlags, Exporter, OtelConfig, process_env, sidecar_resource};

use crate::state::{AppState, lock};

/// Apply a charter's `telemetry` to the exporter: set the flags of a running one, or start one
/// if the charter now resolves to an endpoint.
pub fn on_charter(state: &AppState, charter: &Charter) {
    let mut handle = lock(&state.otel);
    if let Some(h) = handle.as_ref() {
        h.set_flags(ExportFlags::from_telemetry(charter.telemetry.as_ref()));
        return;
    }
    let resource = sidecar_resource(
        &state.service,
        &state.namespace,
        env!("CARGO_PKG_VERSION"),
        &state.self_identity,
    );
    let Some(config) = OtelConfig::resolve(
        charter.telemetry.as_ref(),
        process_env,
        &state.config.otlp_allow(),
        resource,
    ) else {
        return;
    };
    if tokio::runtime::Handle::try_current().is_err() {
        tracing::warn!("no async runtime: OpenTelemetry export not started");
        return;
    }
    tracing::info!(config = ?config, "OpenTelemetry export started");
    *handle = Some(Exporter::spawn(config, state.audit.subscribe()));
}

/// Flush and stop the exporter, if one runs.
pub async fn shutdown(state: &AppState) {
    let handle = lock(&state.otel).take();
    if let Some(h) = handle {
        let dropped = h.shutdown().await;
        if dropped > 0 {
            tracing::warn!(dropped, "OpenTelemetry export dropped audit records");
        }
    }
}
