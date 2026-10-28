//! Taint-aware policy (docs/design/taint-policy.md). The sidecar remembers, per request, which
//! labels the run has read (`untrusted`, `sensitive`) and from which tools, and refuses tool calls
//! a rule forbids:
//!
//! - `taint.untrusted_write`: after untrusted data, no tool whose effect is `write`;
//! - `taint.sensitive_egress`: after sensitive data, no `http` tool (data leaving);
//! - `taint.untrusted_learning`: a lesson drawn from a run that read untrusted data is refused
//!   (with an enforcing policy) and never becomes a note on its own: `learning.mode: auto` waits
//!   for review for such a run (learning.rs). Memory outlives the run, so an injected note would
//!   reach every later run;
//! - inbound, with `authz.taint` in the callee's charter: a peer's `Mesh.InvokeService` whose run
//!   read untrusted data may not write ([`check_inbound`], mesh.rs).
//!
//! The labels travel with agent-to-agent calls in the `x-agentsc-taint` gRPC metadata, both ways,
//! so a run's taint is the union over every pod it touched. Labels only ever accumulate.
use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use agentsc_charter::{AgentSpec, Charter, TaintLabel, TaintMode, ToolEffect, ToolSpec, ToolType};
use agentsc_common::authz::Verdict;

/// gRPC metadata key carrying a run's labels between sidecars: `untrusted,sensitive`.
pub const HEADER: &str = "x-agentsc-taint";
pub const RULE_UNTRUSTED_WRITE: &str = "taint.untrusted_write";
pub const RULE_SENSITIVE_EGRESS: &str = "taint.sensitive_egress";
pub const RULE_UNTRUSTED_LEARNING: &str = "taint.untrusted_learning";
/// A run's labels are forgotten this long after their last change.
const TTL: Duration = Duration::from_secs(15 * 60);
const PRUNE_EVERY: Duration = Duration::from_secs(1);
/// At most this many sources are kept per label (for the denial reason).
const MAX_SOURCES: usize = 8;

#[derive(Debug, Default, Clone)]
struct Entry {
    /// label -> the tools (or `input`, `peer:<svc>`) it came from
    labels: HashMap<TaintLabel, Vec<String>>,
    touched: Option<Instant>,
}

pub struct TaintStore {
    runs: Mutex<HashMap<String, Entry>>,
    last_prune: Mutex<Instant>,
}

impl Default for TaintStore {
    fn default() -> Self {
        Self {
            runs: Mutex::new(HashMap::new()),
            last_prune: Mutex::new(Instant::now()),
        }
    }
}

impl TaintStore {
    fn prune(&self, runs: &mut HashMap<String, Entry>, now: Instant) {
        let mut last = self
            .last_prune
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if now.duration_since(*last) < PRUNE_EVERY {
            return;
        }
        *last = now;
        runs.retain(|_, e| e.touched.is_some_and(|t| now.duration_since(t) < TTL));
    }

    /// Add `label` to `request_id`'s run, from `source`. `trusted` adds nothing.
    pub fn add(&self, request_id: &str, label: TaintLabel, source: &str) {
        if label == TaintLabel::Trusted || request_id.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        self.prune(&mut runs, now);
        let e = runs.entry(request_id.to_string()).or_default();
        e.touched = Some(now);
        let sources = e.labels.entry(label).or_default();
        if sources.len() < MAX_SOURCES && !sources.iter().any(|s| s == source) {
            sources.push(source.to_string());
        }
    }

    /// Add every label of a peer's `x-agentsc-taint` value.
    pub fn add_header(&self, request_id: &str, header: &str, source: &str) {
        for l in parse(header) {
            self.add(request_id, l, source);
        }
    }

    /// The labels of `request_id`'s run.
    pub fn labels(&self, request_id: &str) -> BTreeSet<TaintLabel> {
        let runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        runs.get(request_id)
            .map(|e| e.labels.keys().copied().collect())
            .unwrap_or_default()
    }

    /// The `x-agentsc-taint` value for `request_id` ("" when the run is clean).
    pub fn header(&self, request_id: &str) -> String {
        self.labels(request_id)
            .into_iter()
            .map(TaintLabel::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn sources(&self, request_id: &str, label: TaintLabel) -> String {
        let runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        runs.get(request_id)
            .and_then(|e| e.labels.get(&label))
            .map(|s| s.join(", "))
            .unwrap_or_default()
    }

    /// The verdict of the taint rules for `agent` calling `tool` in `request_id`'s run: `None`
    /// when the agent has no taint policy or no rule applies. In `audit` mode a rule that would
    /// deny gives an allow verdict with rule `taint.would_deny.<rule>` (to be recorded).
    pub fn check(&self, agent: &AgentSpec, tool: &ToolSpec, request_id: &str) -> Option<Verdict> {
        let policy = agent.taint.as_ref()?;
        let labels = self.labels(request_id);
        let (rule, label, why) = if labels.contains(&TaintLabel::Untrusted)
            && tool.effective_effect() == ToolEffect::Write
        {
            (RULE_UNTRUSTED_WRITE, TaintLabel::Untrusted, "writes")
        } else if labels.contains(&TaintLabel::Sensitive) && tool.tool_type == ToolType::Http {
            (
                RULE_SENSITIVE_EGRESS,
                TaintLabel::Sensitive,
                "sends data outside",
            )
        } else {
            return None;
        };
        let reason = format!(
            "this run read {} data (from {}) and tool {} {why}",
            label.as_str(),
            self.sources(request_id, label),
            tool.name
        );
        Some(verdict(policy.mode, rule, reason))
    }
}

impl TaintStore {
    /// Where `request_id`'s run read untrusted data from, if it did.
    pub fn untrusted(&self, request_id: &str) -> Option<String> {
        self.labels(request_id)
            .contains(&TaintLabel::Untrusted)
            .then(|| self.sources(request_id, TaintLabel::Untrusted))
    }

    /// The verdict on a lesson from `request_id`'s run: `None` when the run is clean or the
    /// agent has no taint policy; else a deny (`enforce`) or an allow naming
    /// `taint.would_deny.untrusted_learning` (`audit`).
    pub fn check_learning(&self, agent: &AgentSpec, request_id: &str) -> Option<Verdict> {
        let policy = agent.taint.as_ref()?;
        let sources = self.untrusted(request_id)?;
        let reason = format!(
            "this run read untrusted data (from {sources}); a lesson drawn from it could carry an injected instruction into every later run"
        );
        Some(verdict(policy.mode, RULE_UNTRUSTED_LEARNING, reason))
    }
}

fn verdict(mode: TaintMode, rule: &str, reason: String) -> Verdict {
    match mode {
        TaintMode::Enforce => Verdict::deny(rule, reason),
        TaintMode::Audit => Verdict {
            allow: true,
            rule: rule.replacen("taint.", "taint.would_deny.", 1),
            reason,
        },
    }
}

/// The verdict of `authz.taint` on an inbound service call from `caller` whose sidecar sent
/// `header` (`x-agentsc-taint`): `None` without the rule, from a clean run, or for a read (GET,
/// HEAD, OPTIONS); else a deny (`enforce`) or an allow naming
/// `taint.would_deny.untrusted_write` (`audit`).
pub fn check_inbound(
    charter: &Charter,
    header: Option<&str>,
    method: &str,
    caller: &str,
) -> Option<Verdict> {
    let policy = charter.authz.taint.as_ref()?;
    if !parse(header?).contains(&TaintLabel::Untrusted)
        || matches!(method, "GET" | "HEAD" | "OPTIONS")
    {
        return None;
    }
    let reason = format!("the calling run ({caller}) read untrusted data and {method} writes");
    Some(verdict(policy.mode, RULE_UNTRUSTED_WRITE, reason))
}

/// The labels in an `x-agentsc-taint` value; unknown words are ignored.
pub fn parse(header: &str) -> Vec<TaintLabel> {
    header
        .split(',')
        .filter_map(|w| match w.trim() {
            "untrusted" => Some(TaintLabel::Untrusted),
            "sensitive" => Some(TaintLabel::Sensitive),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsc_charter::{TaintSpec, ToolType};

    fn tool(name: &str, ty: ToolType, method: &str) -> ToolSpec {
        ToolSpec {
            name: name.into(),
            description: "t".into(),
            tool_type: ty,
            parameters: None,
            service: Some("svc".into()),
            method: Some(method.into()),
            path: Some("/x".into()),
            agent: None,
            url: (ty == ToolType::Http).then(|| "https://api.example.com/x".into()),
            label: None,
            effect: None,
            approval: None,
        }
    }

    fn agent(mode: Option<TaintMode>) -> AgentSpec {
        let mut a: AgentSpec = serde_json::from_value(serde_json::json!({
            "name": "support", "model": "mock"
        }))
        .unwrap();
        a.taint = mode.map(|mode| TaintSpec {
            mode,
            input: TaintLabel::Trusted,
        });
        a
    }

    #[test]
    fn untrusted_data_blocks_writes_but_not_reads() {
        let s = TaintStore::default();
        let a = agent(Some(TaintMode::Enforce));
        let refund = tool("issue_refund", ToolType::Service, "POST");
        let read = tool("get_order", ToolType::Service, "GET");
        assert!(s.check(&a, &refund, "r1").is_none(), "clean run");
        s.add("r1", TaintLabel::Untrusted, "read_ticket");
        let v = s.check(&a, &refund, "r1").expect("denied");
        assert!(!v.allow);
        assert_eq!(v.rule, RULE_UNTRUSTED_WRITE);
        assert!(v.reason.contains("read_ticket") && v.reason.contains("issue_refund"));
        assert!(s.check(&a, &read, "r1").is_none(), "reads stay allowed");
        assert!(
            s.check(&a, &refund, "r2").is_none(),
            "other runs are not affected"
        );
    }

    #[test]
    fn sensitive_data_blocks_http_tools() {
        let s = TaintStore::default();
        let a = agent(Some(TaintMode::Enforce));
        s.add("r1", TaintLabel::Sensitive, "get_customer");
        let v = s
            .check(&a, &tool("post_webhook", ToolType::Http, "GET"), "r1")
            .expect("denied");
        assert_eq!(v.rule, RULE_SENSITIVE_EGRESS);
    }

    #[test]
    fn audit_mode_allows_and_names_the_rule() {
        let s = TaintStore::default();
        s.add("r1", TaintLabel::Untrusted, "read_ticket");
        let v = s
            .check(
                &agent(Some(TaintMode::Audit)),
                &tool("w", ToolType::Service, "PUT"),
                "r1",
            )
            .expect("a would-deny verdict");
        assert!(v.allow);
        assert_eq!(v.rule, "taint.would_deny.untrusted_write");
    }

    #[test]
    fn lessons_and_inbound_writes_after_untrusted_data() {
        let s = TaintStore::default();
        let enforce = agent(Some(TaintMode::Enforce));
        assert!(s.check_learning(&enforce, "r1").is_none(), "clean run");
        s.add("r1", TaintLabel::Untrusted, "read_ticket");
        let v = s.check_learning(&enforce, "r1").unwrap();
        assert_eq!((v.allow, v.rule.as_str()), (false, RULE_UNTRUSTED_LEARNING));
        assert!(v.reason.contains("read_ticket"));
        let v = s
            .check_learning(&agent(Some(TaintMode::Audit)), "r1")
            .unwrap();
        assert_eq!(
            (v.allow, v.rule.as_str()),
            (true, "taint.would_deny.untrusted_learning")
        );
        assert!(s.check_learning(&agent(None), "r1").is_none());
        assert!(s.untrusted("r1").is_some() && s.untrusted("r2").is_none());

        let mut c: Charter = serde_json::from_value(serde_json::json!({
            "apiVersion": "agentsc.io/v1alpha1", "kind": "Charter",
            "service": {"name": "inventory", "namespace": "n", "app_port": 8000}
        }))
        .unwrap();
        let caller = "spiffe://agentsc/ns/n/svc/orders";
        assert!(
            check_inbound(&c, Some("untrusted"), "POST", caller).is_none(),
            "no rule"
        );
        c.authz.taint = Some(agentsc_charter::InboundTaintSpec {
            mode: TaintMode::Enforce,
        });
        let v = check_inbound(&c, Some("sensitive,untrusted"), "POST", caller).unwrap();
        assert_eq!((v.allow, v.rule.as_str()), (false, RULE_UNTRUSTED_WRITE));
        assert!(
            check_inbound(&c, Some("untrusted"), "GET", caller).is_none(),
            "reads pass"
        );
        assert!(check_inbound(&c, Some("sensitive"), "POST", caller).is_none());
        assert!(
            check_inbound(&c, None, "DELETE", caller).is_none(),
            "a clean run"
        );
    }

    #[test]
    fn no_policy_no_verdict_and_headers_round_trip() {
        let s = TaintStore::default();
        s.add("r1", TaintLabel::Untrusted, "t");
        assert!(
            s.check(&agent(None), &tool("w", ToolType::Service, "POST"), "r1")
                .is_none()
        );
        s.add("r1", TaintLabel::Sensitive, "t");
        s.add("r1", TaintLabel::Trusted, "t");
        assert_eq!(s.header("r1"), "untrusted,sensitive");
        s.add_header("r2", "sensitive, bogus,untrusted", "peer:inventory");
        assert_eq!(s.header("r2"), "untrusted,sensitive");
        assert_eq!(s.header("none"), "");
    }
}
