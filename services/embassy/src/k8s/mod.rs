//! Kubernetes integration (design §8.4 `kubernetes` store, §13). Empty for now.
//!
//! TODO(B3b): the `kubernetes` implementation of [`crate::store::Store`] over `Charter` custom
//! resources (list+watch with bookmarks, resync 10 min; version in annotation
//! `attache.io/version`, epoch = `metadata.uid`; history as `ControllerRevision`s, keep 20;
//! memory and proposals in the `status` subresource; `Valid`/`Synced` conditions; kubectl edits
//! audited with `actor: k8s:<field manager>`), and the caBundle reconcile of both webhook
//! configurations every 30 s.
