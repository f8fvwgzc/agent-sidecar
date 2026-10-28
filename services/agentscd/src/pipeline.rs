//! The invocation pipeline (CONTRACT.md §5.1): authz → budgets → guardrails → run → guardrails,
//! behind the fail-closed audit gate (audit.rs, `audit.unavailable`).
use std::sync::Arc;
use std::time::Instant;

use agentsc_charter::Clarify;
use agentsc_common::audit::{AuditRecord, Direction, Kind, Tokens};
use agentsc_common::authz::{self, Verdict};
use agentsc_common::guardrails::{CompiledGuardrails, INPUT_DENY};
use agentsc_common::trace::TraceContext;
use agentsc_proto::{ExecuteRequest, ExecuteResponse, InvokeAgentResponse, Question, Step, Usage};
use serde_json::{Value, json};

use crate::deadline;
use crate::outbox;
use crate::runs::{Meter, RunInfo};
use crate::state::{AppState, MAX_DEPTH};

/// One inbound request to run an agent, from the app, a peer sidecar or a local agent tool.
#[derive(Debug, Clone)]
pub struct Invocation {
    pub agent: String,
    pub input: String,
    pub context_json: String,
    pub request_id: String,
    pub trace: TraceContext,
    pub caller: String,
    pub caller_agent: Option<String>,
    pub depth: u32,
    /// When the caller stops waiting (its `grpc-timeout`); the runtime gets what is left of it.
    pub deadline: Option<Instant>,
}

pub const RULE_UNKNOWN_AGENT: &str = "agent.unknown";
pub const RULE_RUNTIME: &str = "runtime.unavailable";
pub const RULE_NO_CHARTER: &str = crate::tools::RULE_NO_CHARTER;
/// Fail-closed mode refused the invocation: the audit sink is failing (audit.rs).
pub const RULE_AUDIT_UNAVAILABLE: &str = crate::audit::RULE_UNAVAILABLE;
/// On the `agent_invocation` record of a run that asked the caller (agent-practices design, Wire).
pub const RULE_CLARIFY_ASKED: &str = "clarify.asked";
/// The longest `question` or `recommended` the sidecar returns, in characters.
pub const MAX_QUESTION_CHARS: usize = 1000;

/// The first `max` characters of `s`, cut on a character boundary.
fn cut_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// The first line of the `output` of a run that asked (CONTRACT.md §9).
pub const QUESTIONS_INTRO: &str = "I need these decisions from you before I go on:";

/// The questions of a run that asked, as its `output` (CONTRACT.md §4.1, §9): the intro, then
/// per question, after a blank line, `<k>. <question>` and `   Recommended: <recommended>`.
/// It must match the runtime's `prompts.render_questions` byte for byte, so an app sees the same
/// text whether the runtime or the sidecar wrote it.
pub fn render_questions(questions: &[Question]) -> String {
    let mut out = String::from(QUESTIONS_INTRO);
    for (k, q) in questions.iter().enumerate() {
        out.push_str(&format!(
            "\n\n{}. {}\n   Recommended: {}",
            k + 1,
            q.question,
            q.recommended
        ));
    }
    out
}

/// The `question` and `recommended` strings of `questions`, in order.
fn question_strings(questions: &[Question]) -> impl Iterator<Item = &str> {
    questions
        .iter()
        .flat_map(|q| [q.question.as_str(), q.recommended.as_str()])
}

/// The first `output_deny` match in what the caller gets, with the payload it matched
/// (agent-practices design, Wire). For a run that did not ask, `output` is the runtime's output.
/// For a run that asked, `raw` holds the questions it keeps, `delivered` the same questions
/// redacted and cut, and `output` the rendering of `delivered`, which the caller gets in place of
/// the runtime's. Checked in turn: each raw string, the rendering of the raw strings, each
/// delivered string and `output`. The raw texts catch a match that the redaction or the cut
/// would hide, the delivered ones a match that they make, and each rendering a match that spans
/// two strings.
fn output_deny(
    g: &CompiledGuardrails,
    output: &str,
    raw: &[Question],
    delivered: &[Question],
) -> Option<(Verdict, String)> {
    if raw.is_empty() {
        let v = g.check_output(output);
        return (!v.allow).then(|| (v, output.to_string()));
    }
    let raw_output = render_questions(raw);
    question_strings(raw)
        .chain([raw_output.as_str()])
        .chain(question_strings(delivered))
        .chain([output])
        .find_map(|text| {
            let v = g.check_output(text);
            (!v.allow).then(|| (v, text.to_string()))
        })
}

fn denied(inv: &Invocation, v: &Verdict, steps: Vec<Step>) -> InvokeAgentResponse {
    InvokeAgentResponse {
        status: "denied".into(),
        request_id: inv.request_id.clone(),
        trace_id: inv.trace.trace_id.clone(),
        agent: inv.agent.clone(),
        output: String::new(),
        usage: Some(Usage::default()),
        steps,
        rule: v.rule.clone(),
        reason: v.reason.clone(),
        questions: Vec::new(),
    }
}

fn errored(inv: &Invocation, rule: &str, reason: String, steps: Vec<Step>) -> InvokeAgentResponse {
    InvokeAgentResponse {
        status: "error".into(),
        request_id: inv.request_id.clone(),
        trace_id: inv.trace.trace_id.clone(),
        agent: inv.agent.clone(),
        output: String::new(),
        usage: Some(Usage::default()),
        steps,
        rule: rule.into(),
        reason,
        questions: Vec::new(),
    }
}

fn step(kind: &str, name: &str, v: &Verdict, latency_ms: u32, summary: &str) -> Step {
    Step {
        kind: kind.into(),
        name: name.into(),
        decision: v.decision().into(),
        rule: if v.allow && summary.is_empty() {
            String::new()
        } else {
            v.rule.clone()
        },
        latency_ms,
        summary: summary.into(),
    }
}

/// HTTP status for a response envelope (CONTRACT.md §4.1).
pub fn http_status(resp: &InvokeAgentResponse) -> u16 {
    match resp.status.as_str() {
        "ok" => 200,
        _ if resp.rule == RULE_AUDIT_UNAVAILABLE => 503,
        "denied" if resp.rule.starts_with("budget.") => 429,
        "denied" => 403,
        _ if resp.rule == RULE_UNKNOWN_AGENT => 404,
        _ => 502,
    }
}

/// gRPC status for a non-ok envelope.
pub fn grpc_status(resp: &InvokeAgentResponse) -> Option<tonic::Status> {
    let msg = format!("{}: {}", resp.rule, resp.reason);
    let mut st = match resp.status.as_str() {
        "ok" => return None,
        _ if resp.rule == RULE_AUDIT_UNAVAILABLE => tonic::Status::unavailable(msg),
        "denied" if resp.rule.starts_with("budget.") => tonic::Status::resource_exhausted(msg),
        "denied" => tonic::Status::permission_denied(msg),
        _ if resp.rule == RULE_UNKNOWN_AGENT => tonic::Status::not_found(msg),
        _ => tonic::Status::unavailable(msg),
    };
    if let Ok(v) = resp.rule.parse() {
        st.metadata_mut().insert("x-agentsc-rule", v);
    }
    if let Ok(v) = resp.request_id.parse() {
        st.metadata_mut().insert("x-agentsc-request-id", v);
    }
    Some(st)
}

pub fn response_json(resp: &InvokeAgentResponse) -> Value {
    let usage = resp.usage.unwrap_or_default();
    let steps: Vec<Value> = resp
        .steps
        .iter()
        .map(|s| {
            let mut v = json!({
                "kind": s.kind, "name": s.name, "decision": s.decision, "latency_ms": s.latency_ms,
            });
            if !s.rule.is_empty() {
                v["rule"] = json!(s.rule);
            }
            if !s.summary.is_empty() {
                v["summary"] = json!(s.summary);
            }
            v
        })
        .collect();
    let mut v = json!({
        "status": resp.status,
        "request_id": resp.request_id,
        "trace_id": resp.trace_id,
        "agent": resp.agent,
        "output": resp.output,
    });
    // only when the run asked (CONTRACT.md §4.1): an app that knows nothing of questions sees none
    if !resp.questions.is_empty() {
        let questions: Vec<Value> = resp
            .questions
            .iter()
            .map(|q| json!({ "question": q.question, "recommended": q.recommended }))
            .collect();
        v["questions"] = json!(questions);
    }
    v["usage"] = json!({ "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens, "cost_usd": usage.cost_usd });
    v["steps"] = json!(steps);
    if resp.status != "ok" {
        v["rule"] = json!(resp.rule);
        v["reason"] = json!(resp.reason);
    }
    v
}

/// What the run used. Cost is always what the model gateway measured (the runtime's figure is
/// never used); tokens too once the gateway saw a call, else the runtime's count (the `mock`
/// model, which runs in the runtime and costs nothing).
pub fn metered_usage(meter: &Meter, reported: Usage) -> Usage {
    let clamp = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
    let (input_tokens, output_tokens) = if meter.calls + meter.reflections > 0 {
        (clamp(meter.input_tokens), clamp(meter.output_tokens))
    } else {
        (reported.input_tokens, reported.output_tokens)
    };
    Usage {
        input_tokens,
        output_tokens,
        cost_usd: (meter.cost_usd * 1_000_000.0).round() / 1_000_000.0,
    }
}

/// Run the full pipeline for one invocation. Always writes exactly one `agent_invocation` record,
/// also when the caller drops this future while the runtime runs (`error: "cancelled: …"`).
pub async fn invoke(state: &Arc<AppState>, inv: Invocation) -> InvokeAgentResponse {
    let started = Instant::now();
    let input_value = if inv.context_json.trim().is_empty() {
        Value::String(inv.input.clone())
    } else {
        json!({ "input": inv.input, "context": serde_json::from_str::<Value>(&inv.context_json).unwrap_or(Value::String(inv.context_json.clone())) })
    };
    let record = |output: Value| {
        AuditRecord::new(
            Kind::AgentInvocation,
            Direction::Inbound,
            &inv.request_id,
            &inv.trace,
            Some(&inv.agent),
            &inv.caller,
            inv.caller_agent.as_deref(),
            &inv.agent,
            input_value.clone(),
            output,
        )
    };

    // The timeline draws the invocation from now on (design §6.4): before any check, so a denial
    // closes a red bar. The span is the one the agent_invocation record carries.
    state.outbox.span_start(outbox::span(
        Kind::AgentInvocation.as_str(),
        &inv.request_id,
        &inv.trace,
        &inv.agent,
        &inv.caller,
        inv.caller_agent.as_deref(),
        &state.audit.redact_text(&inv.request_id, &inv.agent),
        Direction::Inbound,
    ));
    // Fail-closed (audit.rs): no new work while the audit sink fails. The refusal's own record
    // is written (or kept) like any other, and is a retry of the sink.
    if let Err(v) = state.audit.check() {
        state
            .audit
            .write(record(Value::Null).verdict(&v).latency(started));
        return denied(&inv, &v, vec![]);
    }
    // One snapshot of the charter, its guardrails and memory for the whole request (design §6.2).
    let Some(snap) = state.loaded() else {
        let reason = "no charter is loaded yet".to_string();
        let mut rec = record(Value::Null).latency(started);
        rec.error = Some(reason.clone());
        rec.rule = Some(RULE_NO_CHARTER.into());
        state.audit.write(rec);
        return errored(&inv, RULE_NO_CHARTER, reason, vec![]);
    };

    // Values at audit.redact paths of the input must not reappear in this request's later records.
    state.audit.remember(&inv.request_id, "input", &input_value);

    // 1. authz.callers — before the agent lookup, so an unauthorized peer cannot probe agent names
    let v = authz::authorize_caller(
        &snap.charter,
        &inv.caller,
        inv.caller_agent.as_deref(),
        &inv.agent,
    );
    if !v.allow {
        state
            .audit
            .write(record(Value::Null).verdict(&v).latency(started));
        return denied(&inv, &v, vec![step("authz", &inv.agent, &v, 0, "")]);
    }
    let Some(agent) = snap.charter.agent(&inv.agent) else {
        let v = Verdict::deny(
            RULE_UNKNOWN_AGENT,
            format!("agent {:?} is not declared in the charter", inv.agent),
        );
        let mut rec = record(Value::Null).latency(started);
        rec.error = Some(v.reason.clone());
        rec.rule = Some(RULE_UNKNOWN_AGENT.into());
        state.audit.write(rec);
        return errored(&inv, RULE_UNKNOWN_AGENT, v.reason, vec![]);
    };
    if inv.depth > MAX_DEPTH {
        let v = Verdict::deny(
            "budget.max_depth",
            format!("agent-call depth {} exceeds {MAX_DEPTH}", inv.depth),
        );
        state
            .audit
            .write(record(Value::Null).verdict(&v).latency(started));
        return denied(&inv, &v, vec![step("budget", &inv.agent, &v, 0, "")]);
    }

    // 2. budgets
    for v in [
        state
            .budgets
            .check_rate(&inv.agent, agent.budgets.max_calls_per_minute),
        state
            .budgets
            .check_cost(&inv.agent, agent.budgets.max_cost_usd_per_day),
    ] {
        if !v.allow {
            let mut rec = AuditRecord::new(
                Kind::Budget,
                Direction::Internal,
                &inv.request_id,
                &inv.trace,
                Some(&inv.agent),
                &inv.caller,
                inv.caller_agent.as_deref(),
                &inv.agent,
                Value::Null,
                Value::Null,
            );
            rec = rec.verdict(&v);
            state.audit.write(rec);
            state
                .audit
                .write(record(Value::Null).verdict(&v).latency(started));
            return denied(&inv, &v, vec![step("budget", &inv.agent, &v, 0, "")]);
        }
    }

    // 3. input guardrails
    let v = snap
        .guardrails
        .check_input_with_context(&inv.input, &inv.context_json);
    if !v.allow {
        let mut rec = AuditRecord::new(
            Kind::Guardrail,
            Direction::Internal,
            &inv.request_id,
            &inv.trace,
            Some(&inv.agent),
            &inv.caller,
            inv.caller_agent.as_deref(),
            &inv.agent,
            input_value.clone(),
            Value::Null,
        )
        .verdict(&v);
        let mut inv_rec = record(Value::Null).verdict(&v).latency(started);
        // A content rule matched: the log keeps the input's hash, never the secret it may hold
        // (CONTRACT.md §6) — here, and in this request's later records (the caller's next prompt).
        if v.rule.starts_with(INPUT_DENY) {
            state.audit.withhold(
                &inv.request_id,
                [inv.input.clone(), inv.context_json.clone()],
            );
            rec = rec.withhold_input(&v.rule);
            inv_rec = inv_rec.withhold_input(&v.rule);
        }
        state.audit.write(rec);
        state.audit.write(inv_rec);
        return denied(&inv, &v, vec![step("guardrail", &inv.agent, &v, 0, "")]);
    }

    // 4. run
    let spec = snap.runtime_spec(&agent.name);
    let req = ExecuteRequest {
        request_id: inv.request_id.clone(),
        trace_id: inv.trace.trace_id.clone(),
        span_id: inv.trace.span_id.clone(),
        agent_spec_json: serde_json::to_string(&spec).unwrap_or_default(),
        input: inv.input.clone(),
        context_json: inv.context_json.clone(),
        caller: inv.caller.clone(),
        caller_agent: inv.caller_agent.clone().unwrap_or_default(),
        depth: inv.depth,
    };
    let mut req = tonic::Request::new(req);
    req.set_timeout(deadline::budget(inv.deadline, deadline::RUN_TIMEOUT));
    let mut client = state.runtime.clone();
    // From here the runtime acts (model calls, tools). If the caller drops this future — client
    // gone, deadline passed — the record is still written, as cancelled.
    let pending = state.audit.on_cancel(vec![record(Value::Null)], started);
    // ReportEvent, ProposeLesson and model calls are taken for this run while it runs (and the
    // last two for a while after); model calls nest under the invocation's span.
    let run = state.runs.start_run(
        &inv.request_id,
        &inv.agent,
        RunInfo {
            caller: inv.caller.clone(),
            caller_agent: inv.caller_agent.clone(),
            trace_id: inv.trace.trace_id.clone(),
            span_id: inv.trace.span_id.clone(),
            // What the runtime is given: the caller's deadline, else the run timeout.
            deadline: Instant::now()
                .checked_add(deadline::budget(inv.deadline, deadline::RUN_TIMEOUT)),
            depth: inv.depth,
        },
    );
    if let Some(t) = &agent.taint {
        state.taint.add(&inv.request_id, t.input, "input");
    }
    let exec = client.execute(req).await;
    drop(run);
    pending.disarm();
    let exec = match exec {
        Ok(r) => r.into_inner(),
        Err(status) => {
            let reason = format!("runtime: {} {}", status.code(), status.message());
            let mut rec = record(Value::Null).latency(started);
            rec.decision = "allow".into();
            rec.error = Some(reason.clone());
            state.audit.write(rec);
            return errored(&inv, RULE_RUNTIME, reason, vec![]);
        }
    };
    let mut steps = exec.steps.clone();
    let meter = state
        .runs
        .lookup(&inv.request_id, &inv.agent)
        .map(|r| r.meter)
        .unwrap_or_default();
    let usage = metered_usage(&meter, exec.usage.unwrap_or_default());
    let tokens = Some(Tokens {
        input: usage.input_tokens,
        output: usage.output_tokens,
    });

    if exec.status != "ok" {
        // A model call the gateway refused for a budget decides the outcome, whatever the
        // runtime made of the refusal.
        let (status, rule, reason) = match &meter.denial {
            Some(d) if d.rule == agentsc_common::budget::RULE_COST => {
                ("denied", d.rule.clone(), d.reason.clone())
            }
            Some(d) => ("error", d.rule.clone(), d.reason.clone()),
            None => (exec.status.as_str(), exec.rule.clone(), exec.reason.clone()),
        };
        let exec = ExecuteResponse {
            status: status.to_string(),
            rule,
            reason,
            ..exec
        };
        let v = Verdict::deny(exec.rule.clone(), exec.reason.clone());
        let mut rec = record(Value::Null).latency(started);
        rec.tokens = tokens;
        rec.cost_usd = Some(usage.cost_usd);
        if exec.status == "denied" {
            rec = rec.verdict(&v);
            state.audit.write(rec);
            let mut r = denied(&inv, &v, steps);
            r.usage = Some(usage);
            return r;
        }
        rec.error = Some(exec.reason.clone());
        state.audit.write(rec);
        let mut r = errored(&inv, &exec.rule, exec.reason, steps);
        r.usage = Some(usage);
        return r;
    }

    // 5. output guardrails, over the output or the questions of a run that asked: the questions
    //    are model output too (CONTRACT.md §4.1, Questions). An agent with clarify: never
    //    asks nothing, so its questions are dropped and its output passes as usual. Questions
    //    over the agent's max_questions are dropped unseen. When questions remain, the caller
    //    gets an output rendered from them, never the runtime's, so only texts built from them
    //    are checked: every one the caller gets, before and after redaction and the cut.
    let practices = agent.practices_or_default();
    let mut raw = match practices.clarify {
        Clarify::Never => Vec::new(),
        Clarify::Blocking | Clarify::Always => exec.questions,
    };
    raw.truncate(practices.max_questions as usize);
    let mut redactions = 0;
    // Redacted before the cut, so a cut never leaves part of a value a rule would have caught.
    let questions: Vec<Question> = raw
        .iter()
        .map(|q| {
            let mut clean = |s: &str| {
                let (s, n) = snap.guardrails.redact_pii(s);
                redactions += n;
                cut_chars(&s, MAX_QUESTION_CHARS).to_string()
            };
            Question {
                question: clean(&q.question),
                recommended: clean(&q.recommended),
            }
        })
        .collect();
    // The rendered output holds only the fixed frame and strings already redacted, so it is not
    // redacted again: no PII value counts twice in the guardrail record.
    let rendered = (!questions.is_empty()).then(|| render_questions(&questions));
    let checked = rendered.as_deref().unwrap_or(&exec.output);
    if let Some((v, payload)) = output_deny(&snap.guardrails, checked, &raw, &questions) {
        let rec = AuditRecord::new(
            Kind::Guardrail,
            Direction::Internal,
            &inv.request_id,
            &inv.trace,
            Some(&inv.agent),
            &inv.caller,
            inv.caller_agent.as_deref(),
            &inv.agent,
            Value::Null,
            Value::String(payload),
        )
        .verdict(&v)
        .withhold_output(&v.rule);
        state.audit.write(rec);
        let mut rec = record(Value::Null).verdict(&v).latency(started);
        rec.tokens = tokens;
        rec.cost_usd = Some(usage.cost_usd);
        state.audit.write(rec);
        steps.push(step("guardrail", &inv.agent, &v, 0, ""));
        let mut r = denied(&inv, &v, steps);
        r.usage = Some(usage);
        return r;
    }
    let output = match rendered {
        Some(output) => output,
        None => {
            let (output, n) = snap.guardrails.redact_pii(&exec.output);
            redactions += n;
            output
        }
    };
    if redactions > 0 {
        let v = Verdict::allow("guardrail.pii_redact");
        let mut rec = AuditRecord::new(
            Kind::Guardrail,
            Direction::Internal,
            &inv.request_id,
            &inv.trace,
            Some(&inv.agent),
            &inv.caller,
            inv.caller_agent.as_deref(),
            &inv.agent,
            Value::Null,
            json!({ "redactions": redactions }),
        )
        .verdict(&v);
        rec.reason = Some(format!("{redactions} PII value(s) redacted from output"));
        state.audit.write(rec);
        steps.push(step(
            "guardrail",
            &inv.agent,
            &v,
            0,
            &format!("{redactions} redaction(s)"),
        ));
    }

    // A run that asked is still allowed; the record holds the rendered `output`, so the log shows
    // exactly the questions the caller got (CONTRACT.md §4.1, §6).
    let mut rec = record(Value::String(output.clone())).latency(started);
    if !questions.is_empty() {
        rec = rec.verdict(&Verdict::allow(RULE_CLARIFY_ASKED));
    }
    rec.tokens = tokens;
    rec.cost_usd = Some(usage.cost_usd);
    state.audit.write(rec);

    InvokeAgentResponse {
        status: "ok".into(),
        request_id: inv.request_id,
        trace_id: inv.trace.trace_id,
        agent: inv.agent,
        output,
        usage: Some(usage),
        steps,
        rule: String::new(),
        reason: String::new(),
        questions,
    }
}
