//! The REST/SSE API under `/api/v1` (design §10; contract: `docs/api/openapi.yaml`).
//!
//! The routes, the graph builder, the event ring and the SSE stream are added by the control-plane
//! core unit (B3a). What exists now is the vocabulary they share:
//!
//! - [`types`]: every JSON shape of the OpenAPI document, checked against `ui/fixtures/` by
//!   `tests/fixtures.rs`;
//! - [`ids`]: graph node and edge ids (design §3, §10.1).
pub mod ids;
pub mod types;
