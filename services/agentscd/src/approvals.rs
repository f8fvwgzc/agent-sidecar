//! Human approvals of tool calls (CONTRACT.md §5.4): a tool with `approval` in the charter waits,
//! for each call, until a person decides in embassy.
//!
//! The call's request goes to the control plane as `SidecarMessage.approval_request`; embassy
//! answers with `ControlMessage.approval_decision` for every instance of the service (each
//! ignores ids it does not wait on). A request is sent again after every reconnect until it is
//! decided or given up, and embassy treats a request it already has as the same one. The wait is
//! the approval's `timeout_s`, or less when the run's own deadline comes first.
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use agentsc_proto::{ApprovalDecision, ApprovalRequest};
use tokio::sync::{Notify, oneshot};

use crate::state::lock;

/// The call may run: a person approved it.
pub const RULE_GRANTED: &str = "approval.granted";
/// A person refused the call.
pub const RULE_DENIED: &str = "approval.denied";
/// Nobody decided in time (or embassy expired the request).
pub const RULE_EXPIRED: &str = "approval.expired";
/// The tool needs an approval and the sidecar has no control plane to ask.
pub const RULE_UNAVAILABLE: &str = "approval.unavailable";

/// The approvals this sidecar waits on, and the requests still to send.
#[derive(Default)]
pub struct Approvals {
    waiting: Mutex<HashMap<String, (ApprovalRequest, oneshot::Sender<ApprovalDecision>)>>,
    queue: Mutex<VecDeque<ApprovalRequest>>,
    notify: Notify,
}

impl Approvals {
    /// Wait on `req`: it is queued for the control plane; the receiver gets the decision.
    pub fn ask(&self, req: ApprovalRequest) -> oneshot::Receiver<ApprovalDecision> {
        let (tx, rx) = oneshot::channel();
        lock(&self.waiting).insert(req.id.clone(), (req.clone(), tx));
        lock(&self.queue).push_back(req);
        self.notify.notify_one();
        rx
    }

    /// A decision from the control plane: the waiting call gets it (an unknown id is ignored).
    pub fn decide(&self, d: ApprovalDecision) {
        if let Some((_, tx)) = lock(&self.waiting).remove(&d.id) {
            let _ = tx.send(d);
        }
    }

    /// Stop waiting on `id` (the call gave up).
    pub fn forget(&self, id: &str) {
        lock(&self.waiting).remove(id);
    }

    /// How many calls wait now.
    pub fn waiting(&self) -> usize {
        lock(&self.waiting).len()
    }

    /// Queue every request still waiting again (a new `Connect` stream).
    pub fn resend_all(&self) {
        let reqs: Vec<ApprovalRequest> = lock(&self.waiting)
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
    pub async fn next_requests(&self) -> Vec<ApprovalRequest> {
        loop {
            let taken: Vec<ApprovalRequest> = lock(&self.queue).drain(..).collect();
            if !taken.is_empty() {
                return taken;
            }
            self.notify.notified().await;
        }
    }
}
