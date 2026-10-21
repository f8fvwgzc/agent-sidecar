//! OpenTelemetry export for the attache sidecar (design `docs/design/agent-platform.md` §9).
//!
//! The sidecar's audit records — after redaction and truncation, exactly as written — become
//! OTLP/HTTP JSON traces (`POST <endpoint>/v1/traces`) and cumulative metrics
//! (`POST <endpoint>/v1/metrics`):
//!
//! - [`OtelConfig::resolve`] decides whether and where to export (environment endpoint with its
//!   headers, or an allow-listed charter endpoint without them, or nothing).
//! - [`Exporter::spawn`] subscribes to the audit stream and exports in the background; it never
//!   blocks the audit writer and counts what it loses ([`ExporterHandle::dropped`],
//!   `attache.otel.dropped`).
//! - [`spans`] holds the stateless record → span rule, [`metrics`] the aggregation and
//!   [`otlp`] the hand-written wire types.
//!
//! ```no_run
//! # async fn example(writer: &attache_common::AuditWriter, charter: &attache_charter::Charter) {
//! use attache_otel::{Exporter, OtelConfig, process_env, sidecar_resource};
//! let resource = sidecar_resource("orders", "shop", "0.2.0", "spiffe://attache/ns/shop/svc/orders");
//! let allow = vec!["http://otel-collector.*:4318".to_string()]; // --otlp-endpoint-allow
//! if let Some(config) = OtelConfig::resolve(charter.telemetry.as_ref(), process_env, &allow, resource) {
//!     let handle = Exporter::spawn(config, writer.subscribe());
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

pub use config::{OtelConfig, process_env, sidecar_resource};
pub use exporter::{ExportTiming, Exporter, ExporterHandle};
