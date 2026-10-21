//! `SidecarTools.ProposeLesson` (design §6.5): a lesson the runtime drew from a finished run.
//!
//! Accepted only within the run window after the run's Execute returned, not while it runs: the
//! note is scrubbed of what the whole run remembered and withheld. The sidecar checks that
//! learning is enabled for the agent, that the run's caller was `local` unless `from_peers`,
//! the hourly rate limit and the note's length; it scrubs the note (every value remembered for
//! the run by `audit.redact`, every withheld guardrail-denied input, then PII), runs
//! `guardrails.input_deny` on it, and writes a `learning` record. Managed, the note goes to the
//! control plane (the only writer of memory) as a `LearningProposal`; unmanaged with
//! `mode: auto` it becomes a local note (persisted in the state dir); unmanaged with
//! `mode: review` it is only audited.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use agentsc_charter::LearningMode;
use agentsc_common::audit::{AuditRecord, Direction, Kind, now_rfc3339};
use agentsc_common::authz::Verdict;
use agentsc_common::guardrails::{INPUT_DENY, redact_pii};
use agentsc_common::trace::TraceContext;
use agentsc_proto::{LearningProposal, LessonRequest, LessonResponse};
use serde_json::json;
use tonic::Status;

use crate::loaded::{MemoryNote, Source};
use crate::state::{AppState, lock};

pub const RULE_PROPOSED: &str = "learning.proposed";
pub const RULE_APPLIED: &str = "learning.applied";
pub const RULE_DENIED: &str = "learning.denied";
pub const RULE_RATE_LIMITED: &str = "learning.rate_limited";
const HOUR: Duration = Duration::from_secs(3600);

fn response(v: &Verdict) -> LessonResponse {
    LessonResponse {
        decision: v.decision().to_string(),
        rule: v.rule.clone(),
        reason: v.reason.clone(),
    }
}

/// One proposal per call within the hour, per agent; records the proposal when allowed.
fn rate_allows(state: &AppState, agent: &str, per_hour: u32) -> bool {
    let mut lessons = lock(&state.lessons);
    let q: &mut VecDeque<Instant> = lessons.entry(agent.to_string()).or_default();
    let now = Instant::now();
    while q.front().is_some_and(|t| now.duration_since(*t) >= HOUR) {
        q.pop_front();
    }
    if q.len() >= per_hour as usize {
        return false;
    }
    q.push_back(now);
    true
}

/// The text as it may leave the sidecar: the run's remembered and withheld values, then PII.
fn scrub(state: &AppState, run_request_id: &str, text: &str) -> String {
    redact_pii(&state.audit.scrub_text(run_request_id, text)).0
}

pub fn propose(state: &AppState, req: LessonRequest) -> Result<LessonResponse, Status> {
    let ctx = req
        .ctx
        .clone()
        .ok_or_else(|| Status::invalid_argument("ctx is required"))?;
    if ctx.agent.is_empty() {
        return Err(Status::invalid_argument("ctx.agent is required"));
    }
    let run_request_id = if req.run_request_id.is_empty() {
        ctx.request_id.clone()
    } else {
        req.run_request_id.clone()
    };
    let agent = ctx.agent.clone();
    let run = match state.runs.lookup(&run_request_id, &agent) {
        Some(run) if !run.in_flight => run,
        found => {
            let reason = if found.is_some() {
                format!(
                    "the Execute of {agent} for request {run_request_id:?} is still running; a lesson is proposed after it returned"
                )
            } else {
                format!(
                    "no Execute of {agent} for request {run_request_id:?} finished in the last {}s",
                    state.runs.window().as_secs()
                )
            };
            return Err(crate::tools::reject_report(
                state,
                &run_request_id,
                &ctx.trace_id,
                Some(&agent),
                json!({"kind": "learning", "run_request_id": run_request_id}),
                reason,
            ));
        }
    };
    let snap = state
        .loaded()
        .ok_or_else(|| Status::unavailable("no charter loaded"))?;
    let trace_id =
        if TraceContext::parse(&format!("00-{}-00f067aa0ba902b7-01", ctx.trace_id)).is_some() {
            ctx.trace_id.clone()
        } else {
            run.trace_id.clone()
        };
    let trace = TraceContext {
        trace_id: trace_id.clone(),
        span_id: TraceContext::new_root().span_id,
        parent_span_id: (!ctx.span_id.is_empty()).then(|| ctx.span_id.clone()),
    };
    let note = scrub(state, &run_request_id, &req.note);
    let rationale = scrub(state, &run_request_id, &req.rationale);
    let record = |v: &Verdict| {
        AuditRecord::new(
            Kind::Learning,
            Direction::Internal,
            &run_request_id,
            &trace,
            Some(&agent),
            agentsc_charter::LOCAL_IDENTITY,
            None,
            "learning",
            json!({ "request_id_of_run": run_request_id }),
            json!({ "note": note, "rationale": rationale }),
        )
        .verdict(v)
    };
    let deny = |rule: &str, reason: String| {
        let v = Verdict::deny(rule, reason);
        state.audit.write(record(&v));
        Ok(response(&v))
    };

    let Some(spec) = snap.charter.agent(&agent) else {
        return deny(RULE_DENIED, format!("agent {agent:?} is not declared"));
    };
    let learning = spec.learning_or_default();
    if !learning.enabled {
        return deny(
            RULE_DENIED,
            format!("learning is not enabled for agent {agent}"),
        );
    }
    if run.caller != agentsc_charter::LOCAL_IDENTITY && !learning.from_peers {
        return deny(
            RULE_DENIED,
            format!(
                "the run's caller {} is a peer and learning.from_peers is off",
                run.caller
            ),
        );
    }
    if !rate_allows(state, &agent, learning.max_proposals_per_hour) {
        return deny(
            RULE_RATE_LIMITED,
            format!(
                "agent {agent} already proposed {} lessons in the last hour",
                learning.max_proposals_per_hour
            ),
        );
    }
    let chars = req.note.chars().count();
    if req.note.trim().is_empty() || chars > learning.max_note_chars as usize {
        return deny(
            RULE_DENIED,
            format!(
                "the note has {chars} characters (1..={})",
                learning.max_note_chars
            ),
        );
    }
    for text in [&note, &rationale] {
        let v = snap.guardrails.check_input(text);
        if !v.allow && v.rule.starts_with(INPUT_DENY) {
            let d = Verdict::deny(RULE_DENIED, format!("{}: {}", v.rule, v.reason));
            // the text a content rule matched is withheld, its hash kept (CONTRACT.md §6)
            state.audit.write(record(&d).withhold_output(&v.rule));
            return Ok(response(&d));
        }
    }

    let auto = learning.mode == LearningMode::Auto;
    let v = if state.managed {
        state.outbox.propose(LearningProposal {
            dedup_key: uuid::Uuid::new_v4().to_string(),
            agent: agent.clone(),
            note: note.clone(),
            rationale: rationale.clone(),
            request_id: run_request_id.clone(),
            trace_id: trace_id.clone(),
            auto,
        });
        Verdict::allow(RULE_PROPOSED)
    } else if auto {
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::days(i64::from(learning.note_ttl_days));
        let fresh = MemoryNote {
            id: uuid::Uuid::new_v4().to_string(),
            text: note.clone(),
            source: "auto".into(),
            request_id: run_request_id.clone(),
            trace_id: trace_id.clone(),
            approved_by: String::new(),
            ts: now_rfc3339(),
            expires_at: expires.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        };
        let max = learning.max_notes as usize;
        let agent_name = agent.clone();
        crate::reload::update_memory(state, Source::Learning, move |current| {
            let mut m = current.clone();
            let notes = m.agents.entry(agent_name).or_default();
            notes.retain(|n| n.active_at(now));
            notes.push(fresh);
            let excess = notes.len().saturating_sub(max);
            notes.drain(..excess);
            m.version = (m.version_number() + 1).to_string();
            m
        });
        Verdict::allow(RULE_APPLIED)
    } else {
        Verdict::allow(RULE_PROPOSED)
    };
    state.audit.write(record(&v));
    Ok(response(&v))
}
