//! Shared building blocks. CONTRACT.md §5 (identity, authz) and §6 (audit) are normative.
pub mod audit;
pub mod authz;
pub mod budget;
pub mod guardrails;
pub mod identity;
pub mod llm_contract;
pub mod pricing;
pub mod principal;
pub mod trace;

pub use audit::{AuditRecord, AuditWriter, Direction, Kind};
pub use authz::Verdict;
pub use trace::TraceContext;
