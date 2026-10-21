//! OpenTelemetry export for the agentsc sidecar (design `docs/design/agent-platform.md` §9).
//!
//! The sidecar's audit records — after redaction and truncation, exactly as written — become
//! OTLP/HTTP JSON traces (`POST <endpoint>/v1/traces`) and cumulative metrics
//! (`POST <endpoint>/v1/metrics`):
//!
//! - [`OtelConfig::resolve`] decides whether and where to export (environment endpoint with its
//!   headers, or an allow-listed charter endpoint without them, or nothing).
//! - [`Exporter::spawn`] subscribes to the audit stream and exports in the background; it never
//!   blocks the audit writer and counts what it loses ([`ExporterHandle::dropped`],
//!   `agentsc.otel.dropped`). A hot reload's `traces`, `metrics` and `export_payloads` go to
//!   [`ExporterHandle::set_flags`]; the endpoint is restart-only.
//! - [`spans`] holds the stateless record → span rule, [`metrics`] the aggregation and
//!   [`otlp`] the hand-written wire types.
//!
//! ```no_run
//! # async fn example(writer: &agentsc_common::AuditWriter, charter: &agentsc_charter::Charter) {
//! use agentsc_otel::{ExportFlags, Exporter, OtelConfig, process_env, sidecar_resource};
//! let resource = sidecar_resource("orders", "shop", "0.2.0", "spiffe://agentsc/ns/shop/svc/orders");
//! let allow = vec!["http://otel-collector.*:4318".to_string()]; // --otlp-endpoint-allow
//! if let Some(config) = OtelConfig::resolve(charter.telemetry.as_ref(), process_env, &allow, resource) {
//!     let handle = Exporter::spawn(config, writer.subscribe());
//!     // ... on a hot reload (`new` is the reloaded charter):
//!     # let new = charter;
//!     handle.set_flags(ExportFlags::from_telemetry(new.telemetry.as_ref()));
//!     // ... on shutdown:
//!     handle.shutdown().await;
//! }
//! # }
//! ```
pub mod config;
pub mod exporter;
pub mod metrics;
pub mod otlp;
pub mod spans;

pub use config::{ExportFlags, OtelConfig, process_env, sidecar_resource};
pub use exporter::{ExportTiming, Exporter, ExporterHandle};
