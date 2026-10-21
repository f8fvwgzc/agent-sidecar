//! OpenTelemetry wiring (design §9): the exporter starts with the first charter that turns traces
//! or metrics on (at start-up or on a reload), later reloads only change its flags (the endpoint
//! is restart-only), and it is shut down with the sidecar. The one exception is the first
//! control-plane charter after start-up, which takes the start-up charter's place as a restart
//! would (see [`crate::reload::apply_charter`]): an exporter for another endpoint is replaced.
use attache_charter::{Charter, TelemetrySpec};
use attache_otel::{ExportFlags, Exporter, ExporterHandle, OtelConfig, sidecar_resource};

use crate::state::{AppState, lock};

/// The running exporter and the configuration it was started with.
pub struct RunningExporter {
    pub handle: ExporterHandle,
    pub config: OtelConfig,
}

/// The endpoint (and headers, resource) a charter's `telemetry` exports to, resolved as if
/// traces were on, with the charter's real flags.
fn resolve(state: &AppState, charter: &Charter, flags: ExportFlags) -> Option<OtelConfig> {
    let probe = TelemetrySpec {
        traces: true,
        ..charter.telemetry_or_default()
    };
    let resource = sidecar_resource(
        &state.service,
        &state.namespace,
        env!("CARGO_PKG_VERSION"),
        &state.self_identity,
    );
    OtelConfig::resolve(
        Some(&probe),
        |name| state.config.otel_env_var(name),
        &state.config.otlp_allow(),
        resource,
    )
    .map(|c| OtelConfig {
        traces: flags.traces,
        metrics: flags.metrics,
        export_payloads: flags.export_payloads,
        ..c
    })
}

/// Apply a charter's `telemetry` to the exporter: set the flags of a running one, or start one
/// if the charter now resolves to an endpoint. With `restart` (the first control-plane charter
/// replacing the start-up one), a running exporter whose endpoint or headers differ from the
/// charter's is stopped (flushed in the background) and the charter's started instead.
pub fn on_charter(state: &AppState, charter: &Charter, restart: bool) {
    let flags = ExportFlags::from_telemetry(charter.telemetry.as_ref());
    let mut running = lock(&state.otel);
    if let Some(r) = running.as_ref()
        && !restart
    {
        r.handle.set_flags(flags);
        return;
    }
    if running.is_none() && !flags.traces && !flags.metrics {
        return;
    }
    let config = resolve(state, charter, flags);
    if let Some(r) = running.as_ref() {
        let same = config
            .as_ref()
            .is_some_and(|c| c.endpoint == r.config.endpoint && c.headers == r.config.headers);
        if same {
            r.handle.set_flags(flags);
            return;
        }
        if let Some(old) = running.take() {
            tracing::info!(
                config = ?old.config,
                "the control plane's charter names another OpenTelemetry endpoint; stopping this exporter"
            );
            match tokio::runtime::Handle::try_current() {
                Ok(rt) => {
                    rt.spawn(async move {
                        old.handle.shutdown().await;
                    });
                }
                Err(_) => drop(old),
            }
        }
    }
    let Some(config) = config.filter(|c| c.traces || c.metrics) else {
        return;
    };
    if tokio::runtime::Handle::try_current().is_err() {
        tracing::warn!("no async runtime: OpenTelemetry export not started");
        return;
    }
    tracing::info!(config = ?config, "OpenTelemetry export started");
    *running = Some(RunningExporter {
        handle: Exporter::spawn(config.clone(), state.audit.subscribe()),
        config,
    });
}

/// Flush and stop the exporter, if one runs.
pub async fn shutdown(state: &AppState) {
    let running = lock(&state.otel).take();
    if let Some(r) = running {
        let dropped = r.handle.shutdown().await;
        if dropped > 0 {
            tracing::warn!(dropped, "OpenTelemetry export dropped audit records");
        }
    }
}
