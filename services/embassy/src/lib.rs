//! `embassy` — the attache control plane (docs/design/agent-platform.md §2, §7–§10).
//!
//! One binary, `embassy serve --components <list>`, runs any of the components `ca`
//! (IssueCertificate), `webhook` (admission), `controlplane` (Connect), `api` (REST/SSE) and
//! `ui` (static files). The v0.1 subcommands `ca-init`, `cert-issue` and `bootstrap` live in
//! `main.rs` and are unchanged.
//!
//! | Module | Owner | What |
//! | --- | --- | --- |
//! | [`api`] | B3a | REST routes; [`api::types`] holds every JSON shape of `docs/api/openapi.yaml` |
//! | [`auth`] | B3a | tokens, sessions, CSRF, Host check, security headers |
//! | [`config`] | B3a | `ControlPlaneConfig` (§8.2): types, validation, loader |
//! | [`controlplane`] | B3a | `ControlPlane.Connect` (§7) |
//! | [`events`] | B3a | the live events (SSE) and the ring of recent audit records |
//! | [`graph`] | B3a | the node graph, its stats and the record → edge mapping (§10.1) |
//! | [`hub`] | B3a | the state `controlplane`, `api` and `ui` share, and its tasks |
//! | [`registry`] | B3a | the connected sidecar instances |
//! | [`serve`] | B3a | `embassy serve` flags (§8.1) and the wiring of the components |
//! | [`store`] | B3a | the `Store` trait (§8.4) and the file store |
//! | [`traces`] | B3a | runs for the agent timeline (§10.1.1) |
//! | [`ui_assets`] | B3a | the console files, embedded or from `--ui-dir` |
//! | [`k8s`] | B3b | the Kubernetes store, caBundle reconcile |
//! | [`issuance`] | B3b | `IssueCertificate` (§7) |
//! | [`webhook`] | B3b | mutating and validating admission (§13) |
//! | [`servingcert`] | B3b | the control-plane serving certificate (§7) |
//! | [`token`] | A2 | `embassy token create` |
//! | [`names`] | A2 | DNS-1123 names and hex checks shared by the modules above |
pub mod api;
pub mod auth;
pub mod ca;
pub mod ca_components;
pub mod config;
pub mod context;
pub mod controlplane;
pub mod cp_audit;
pub mod events;
pub mod graph;
pub mod hub;
pub mod issuance;
pub mod k8s;
pub mod names;
pub mod registry;
pub mod serve;
pub mod servingcert;
pub mod store;
pub mod token;
pub mod traces;
pub mod ui_assets;
pub mod webhook;
