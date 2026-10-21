//! Admission webhooks (design §13, component `webhook`). Empty for now.
//!
//! TODO(B3b): `/mutate` (sidecar injection for pods labelled `attache.io/inject: "true"`: the
//! native-sidecar `attached` init container, its env, volumes and projected token; idempotent;
//! `attache.io/injected: skipped-existing` for pods that already have one) and
//! `/validate-charter` (charter validator + policy for `Charter` CREATE/UPDATE, audited as
//! `cr_external_edit`), served on `--webhook-addr` with the serving certificate.
