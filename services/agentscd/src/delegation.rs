//! Delegated agent tokens for `http` tools (CONTRACT.md §5.3, #25): a tool with `delegation`
//! acts for the person whose token came with the invocation.
//!
//! - **The person's token.** An app sends it with `X-Agentsc-Subject-Token` (HTTP) or the
//!   metadata `x-agentsc-subject-token` (gRPC) on an invocation. The sidecar keeps it in memory for
//!   that run only (every agent of the run may use it), never writes it to a record, a log or the
//!   runtime, and forgets it when the invocation ends.
//! - **A call.** For each call of a tool with `delegation`, the sidecar asks embassy on its
//!   `Connect` stream (`DelegationRequest`) for a token of the tool's audience, and sends it as
//!   `Authorization: Bearer` in place of any the model wrote. A token is kept for the run until
//!   10 s before it ends, so a run's calls to one audience share one.
//! - **Refusals** (it fails closed): no control plane (`delegation.unavailable`), no person's
//!   token with the invocation (`delegation.no_subject`), embassy refused or did not answer within
//!   10 s (`delegation.refused`, `delegation.unavailable`). The call is denied; it never goes out
//!   without the token, and never with the person's own.
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use agentsc_proto::{DelegationRequest, DelegationResponse};
use tokio::sync::{Notify, oneshot};

use crate::state::lock;

/// The invocation carried no person's token.
pub const RULE_NO_SUBJECT: &str = "delegation.no_subject";
/// No control plane, or it did not answer.
pub const RULE_UNAVAILABLE: &str = "delegation.unavailable";
/// embassy (or Tutela) refused the token.
pub const RULE_REFUSED: &str = "delegation.refused";
/// The header an app sends the person's token in.
pub const SUBJECT_HEADER: &str = "x-agentsc-subject-token";
/// The longest person's token taken (Tutela's limit).
pub const MAX_SUBJECT_BYTES: usize = 8192;
/// How long a call waits for embassy.
pub const WAIT: Duration = Duration::from_secs(10);
/// A kept token is not used in its last seconds.
const MARGIN: Duration = Duration::from_secs(10);

type CacheKey = (String, String, String);

/// The person's tokens of the runs in flight, the requests to embassy, and the tokens it gave.
#[derive(Default)]
pub struct Delegations {
    subjects: Mutex<HashMap<String, String>>,
    waiting: Mutex<HashMap<String, (DelegationRequest, oneshot::Sender<DelegationResponse>)>>,
    queue: Mutex<VecDeque<DelegationRequest>>,
    notify: Notify,
    tokens: Mutex<HashMap<CacheKey, (String, Instant)>>,
}

impl std::fmt::Debug for Delegations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delegations")
            .field("runs", &lock(&self.subjects).len())
            .field("waiting", &lock(&self.waiting).len())
            .finish_non_exhaustive()
    }
}

impl Delegations {
    /// Keep the person's token of run `request_id` until [`Delegations::end_run`]. `false` for a
    /// token that is empty or too large (it is not kept).
    pub fn set_subject(&self, request_id: &str, token: &str) -> bool {
        let token = token.trim();
        if token.is_empty() || token.len() > MAX_SUBJECT_BYTES {
            return false;
        }
        lock(&self.subjects).insert(request_id.to_string(), token.to_string());
        true
    }

    /// The person's token of run `request_id`.
    pub fn subject(&self, request_id: &str) -> Option<String> {
        lock(&self.subjects).get(request_id).cloned()
    }

    /// The invocation of `request_id` ended: forget its person's token and its tokens.
    pub fn end_run(&self, request_id: &str) {
        lock(&self.subjects).remove(request_id);
        lock(&self.tokens).retain(|(r, _, _), _| r != request_id);
    }

    /// A token embassy gave for this run, agent and audience, while it has more than 10 s left.
    pub fn kept(&self, request_id: &str, agent: &str, audience: &str) -> Option<String> {
        let key = (request_id.into(), agent.into(), audience.into());
        let tokens = lock(&self.tokens);
        tokens
            .get(&key)
            .filter(|(_, until)| Instant::now() < *until)
            .map(|(t, _)| t.clone())
    }

    /// Keep `token` (it ends in `expires_in` seconds) for this run, agent and audience.
    pub fn keep(
        &self,
        request_id: &str,
        agent: &str,
        audience: &str,
        token: &str,
        expires_in: u64,
    ) {
        let until = Instant::now() + Duration::from_secs(expires_in).saturating_sub(MARGIN);
        let mut tokens = lock(&self.tokens);
        let now = Instant::now();
        tokens.retain(|_, (_, u)| *u > now);
        tokens.insert(
            (request_id.into(), agent.into(), audience.into()),
            (token.to_string(), until),
        );
    }

    /// Ask embassy for a token: `req` is queued for the `Connect` stream.
    pub fn ask(&self, req: DelegationRequest) -> oneshot::Receiver<DelegationResponse> {
        let (tx, rx) = oneshot::channel();
        lock(&self.waiting).insert(req.id.clone(), (req.clone(), tx));
        lock(&self.queue).push_back(req);
        self.notify.notify_one();
        rx
    }

    /// embassy's answer: the waiting call gets it (an unknown id is ignored).
    pub fn answer(&self, r: DelegationResponse) {
        if let Some((_, tx)) = lock(&self.waiting).remove(&r.id) {
            let _ = tx.send(r);
        }
    }

    /// Stop waiting on `id`.
    pub fn forget(&self, id: &str) {
        lock(&self.waiting).remove(id);
    }

    /// Queue every request still waiting again (a new `Connect` stream).
    pub fn resend_all(&self) {
        let reqs: Vec<DelegationRequest> = lock(&self.waiting)
            .values()
            .map(|(r, _)| r.clone())
            .collect();
        if reqs.is_empty() {
            return;
        }
        let mut q = lock(&self.queue);
        q.clear();
        q.extend(reqs);
        drop(q);
        self.notify.notify_one();
    }

    /// The requests to send now; waits until there is one. Cancel-safe.
    pub async fn next_requests(&self) -> Vec<DelegationRequest> {
        loop {
            let taken: Vec<DelegationRequest> = lock(&self.queue).drain(..).collect();
            if !taken.is_empty() {
                return taken;
            }
            self.notify.notified().await;
        }
    }
}

/// Forgets the person's token of a run when the invocation ends, however it ends.
pub struct SubjectGuard<'a> {
    delegations: &'a Delegations,
    request_id: String,
}

impl<'a> SubjectGuard<'a> {
    /// Keep `token` (if any) for run `request_id` until the guard drops.
    pub fn new(delegations: &'a Delegations, request_id: &str, token: Option<&str>) -> Self {
        if let Some(t) = token {
            delegations.set_subject(request_id, t);
        }
        SubjectGuard {
            delegations,
            request_id: request_id.to_string(),
        }
    }
}

impl Drop for SubjectGuard<'_> {
    fn drop(&mut self) {
        self.delegations.end_run(&self.request_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runs_token_lives_with_its_invocation() {
        let d = Delegations::default();
        {
            let _g = SubjectGuard::new(&d, "r1", Some(" tok "));
            assert_eq!(d.subject("r1").as_deref(), Some("tok"));
            d.keep("r1", "ops", "symphony", "delegated", 90);
            assert_eq!(
                d.kept("r1", "ops", "symphony").as_deref(),
                Some("delegated")
            );
            assert!(d.kept("r1", "ops", "crm-api").is_none());
            d.keep("r1", "ops", "crm-api", "short", 5);
            assert!(
                d.kept("r1", "ops", "crm-api").is_none(),
                "within the margin"
            );
        }
        assert!(d.subject("r1").is_none());
        assert!(d.kept("r1", "ops", "symphony").is_none());
        assert!(!d.set_subject("r2", ""));
        assert!(!d.set_subject("r2", &"x".repeat(MAX_SUBJECT_BYTES + 1)));
        assert!(!format!("{d:?}").contains("tok"));
    }
}
