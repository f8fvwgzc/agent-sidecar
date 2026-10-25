//! Executes in flight and recently finished (design §6.5): `ReportEvent` and `ProposeLesson` are
//! accepted only for a request id and agent whose Execute is running or returned less than the
//! run window (120 s) ago, and tool calls only while it runs (tools.rs). Keyed by (request id,
//! agent): a local orchestrator and the local agent it calls share the request id. What the
//! sidecar knows of the run (its trace, its agent-call depth) wins over what the runtime says.
//!
//! Each run also carries what the model gateway (gateway.rs) measured for it: the model calls it
//! let through, their usage and cost as the provider reported them, and the rule of a call it
//! refused. The invocation pipeline answers with these numbers, never with the runtime's.
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use agentsc_common::authz::Verdict;

type Key = (String, String);

#[derive(Debug, Clone, Default)]
struct Entry {
    caller: String,
    caller_agent: Option<String>,
    trace_id: String,
    span_id: String,
    deadline: Option<Instant>,
    depth: u32,
    in_flight: u32,
    finished_at: Option<Instant>,
    meter: Meter,
}

/// What the model gateway measured for one run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Meter {
    /// Model calls let through while the Execute ran (every attempt and fallback).
    pub calls: u32,
    /// Reflection calls let through after it returned.
    pub reflections: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    /// The first model call the gateway refused for a budget (`budget.*`), if any.
    pub denial: Option<Verdict>,
}

/// What [`Runs::lookup`] knows about a run.
#[derive(Debug, Clone, PartialEq)]
pub struct RunState {
    pub in_flight: bool,
    /// `local` or the peer's SPIFFE id. When Executes of the same request and agent came from
    /// different callers, a peer wins (learning treats the run as a peer's).
    pub caller: String,
    pub caller_agent: Option<String>,
    pub trace_id: String,
    /// The invocation's span: the parent of the run's model calls.
    pub span_id: String,
    /// When the caller stops waiting for the Execute in flight (`None`: no deadline).
    pub deadline: Option<Instant>,
    /// The Execute's agent-call nesting depth.
    pub depth: u32,
    pub meter: Meter,
}

/// Who started an Execute, for [`Runs::start_run`].
#[derive(Debug, Clone, Default)]
pub struct RunInfo {
    pub caller: String,
    pub caller_agent: Option<String>,
    pub trace_id: String,
    pub span_id: String,
    pub deadline: Option<Instant>,
    pub depth: u32,
}

/// Which model call [`Runs::admit_model_call`] let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// A step of the Execute in flight (an attempt, a retry or the fallback).
    Step,
    /// The reflection on a run that returned (design §12).
    Reflection,
}

/// The model calls one run may make (from the charter, gateway.rs).
#[derive(Debug, Clone, Copy)]
pub struct CallLimits {
    /// Model calls while the Execute runs: `max_steps × (1 + max_retries + fallback)`.
    pub calls: u32,
    /// Reflections after it returned: 1 when the agent learns from this run's caller, else 0.
    pub reflections: u32,
}

pub struct Runs {
    window: Duration,
    inner: Mutex<Inner>,
}

/// The runs, and the finished ones in the order they finished: pruning pops expired entries off
/// the front of `finished` instead of scanning the whole map on every call (which was quadratic
/// under load: the flamegraph showed most sidecar CPU in that scan).
#[derive(Default)]
struct Inner {
    map: HashMap<Key, Entry>,
    finished: VecDeque<(Instant, Key)>,
}

/// Marks the Execute finished when dropped (also when the caller drops the invocation).
#[must_use]
pub struct RunGuard<'a> {
    runs: &'a Runs,
    key: (String, String),
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        let mut inner = self
            .runs
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if let Some(e) = inner.map.get_mut(&self.key) {
            e.in_flight = e.in_flight.saturating_sub(1);
            if e.in_flight == 0 {
                e.finished_at = Some(now);
                inner.finished.push_back((now, self.key.clone()));
            }
        }
    }
}

fn key(request_id: &str, agent: &str) -> Key {
    (request_id.to_string(), agent.to_string())
}

impl Entry {
    fn state(&self) -> RunState {
        RunState {
            in_flight: self.in_flight > 0,
            caller: self.caller.clone(),
            caller_agent: self.caller_agent.clone(),
            trace_id: self.trace_id.clone(),
            span_id: self.span_id.clone(),
            deadline: self.deadline,
            depth: self.depth,
            meter: self.meter.clone(),
        }
    }
}

impl Runs {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        self.prune(&mut inner, Instant::now());
        inner
    }

    /// Drop runs that finished at least the window ago. Amortised O(1): only expired queue
    /// entries are visited; a run that started again since it was queued is left alone (its
    /// newer finish has its own queue entry).
    fn prune(&self, inner: &mut Inner, now: Instant) {
        while let Some((at, _)) = inner.finished.front() {
            if now.duration_since(*at) < self.window {
                break;
            }
            let Some((at, key)) = inner.finished.pop_front() else {
                break;
            };
            if inner
                .map
                .get(&key)
                .is_some_and(|e| e.in_flight == 0 && e.finished_at == Some(at))
            {
                inner.map.remove(&key);
            }
        }
    }

    /// An Execute of `agent` for `request_id` starts.
    pub fn start(
        &self,
        request_id: &str,
        agent: &str,
        caller: &str,
        trace_id: &str,
    ) -> RunGuard<'_> {
        self.start_run(
            request_id,
            agent,
            RunInfo {
                caller: caller.to_string(),
                trace_id: trace_id.to_string(),
                ..RunInfo::default()
            },
        )
    }

    /// An Execute of `agent` for `request_id` starts, with its invocation span and deadline.
    pub fn start_run(&self, request_id: &str, agent: &str, info: RunInfo) -> RunGuard<'_> {
        let key = key(request_id, agent);
        let mut inner = self.lock();
        let e = inner.map.entry(key.clone()).or_insert_with(|| Entry {
            caller: info.caller.clone(),
            caller_agent: info.caller_agent.clone(),
            trace_id: info.trace_id.clone(),
            span_id: info.span_id.clone(),
            ..Entry::default()
        });
        if info.caller != agentsc_charter::LOCAL_IDENTITY {
            e.caller = info.caller;
            e.caller_agent = info.caller_agent;
        }
        // The latest Execute's deadline and span: its model calls are the ones arriving now. Its
        // depth only grows: a nested Execute of the same agent and request is the deeper one.
        e.deadline = info.deadline;
        e.depth = e.depth.max(info.depth);
        if !info.span_id.is_empty() {
            e.span_id = info.span_id;
        }
        e.in_flight += 1;
        e.finished_at = None;
        RunGuard { runs: self, key }
    }

    /// The run, if it is in flight or finished less than the window ago.
    pub fn lookup(&self, request_id: &str, agent: &str) -> Option<RunState> {
        self.lock()
            .map
            .get(&key(request_id, agent))
            .map(Entry::state)
    }

    /// Count a model call against the run's limits: a step while its Execute runs, a reflection
    /// for a while after it returned. `Err(None)`: there is no such run; `Err(Some(v))`: the
    /// run used up what `limits` allow (the rule says which).
    pub fn admit_model_call(
        &self,
        request_id: &str,
        agent: &str,
        limits: CallLimits,
        max_steps: u32,
    ) -> Result<(CallKind, RunState), Option<Verdict>> {
        let mut inner = self.lock();
        let Some(e) = inner.map.get_mut(&key(request_id, agent)) else {
            return Err(None);
        };
        let kind = if e.in_flight > 0 {
            if e.meter.calls >= limits.calls {
                return Err(Some(Verdict::deny(
                    "budget.max_steps",
                    format!(
                        "agent {agent} already made {} model calls in this run, all that max_steps={max_steps} with its retries and fallback allow",
                        e.meter.calls
                    ),
                )));
            }
            e.meter.calls += 1;
            CallKind::Step
        } else {
            if e.meter.reflections >= limits.reflections {
                return Err(Some(Verdict::deny(
                    crate::gateway::RULE_UNBOUND,
                    format!(
                        "the Execute of {agent} for request {request_id:?} returned; it may make {} more model call(s) (the reflection)",
                        limits.reflections.saturating_sub(e.meter.reflections)
                    ),
                )));
            }
            e.meter.reflections += 1;
            CallKind::Reflection
        };
        Ok((kind, e.state()))
    }

    /// Add what a model call used, as the provider reported it, to the run's meter.
    pub fn add_usage(&self, request_id: &str, agent: &str, input: u64, output: u64, cost: f64) {
        if let Some(e) = self.lock().map.get_mut(&key(request_id, agent)) {
            e.meter.input_tokens += input;
            e.meter.output_tokens += output;
            e.meter.cost_usd += cost;
        }
    }

    /// Remember the first budget a model call of the run was refused for.
    pub fn note_denial(&self, request_id: &str, agent: &str, v: &Verdict) {
        if let Some(e) = self.lock().map.get_mut(&key(request_id, agent))
            && e.meter.denial.is_none()
        {
            e.meter.denial = Some(v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_are_known_while_in_flight_and_for_the_window_after() {
        let runs = Runs::new(Duration::from_millis(200));
        assert!(runs.lookup("r1", "a").is_none());
        let g = runs.start("r1", "a", "local", "t1");
        let s = runs.lookup("r1", "a").unwrap();
        assert!(s.in_flight);
        assert_eq!(s.caller, "local");
        assert!(runs.lookup("r1", "b").is_none(), "keyed by agent too");
        // a nested Execute of the same agent and request from a peer
        let g2 = runs.start("r1", "a", "spiffe://agentsc/ns/n/svc/s", "t1");
        drop(g);
        assert!(runs.lookup("r1", "a").unwrap().in_flight);
        drop(g2);
        let s = runs.lookup("r1", "a").unwrap();
        assert!(!s.in_flight);
        assert_eq!(s.caller, "spiffe://agentsc/ns/n/svc/s");
        std::thread::sleep(Duration::from_millis(250));
        assert!(runs.lookup("r1", "a").is_none(), "window passed");
    }

    #[test]
    fn a_run_started_again_outlives_its_old_finish() {
        let runs = Runs::new(Duration::from_millis(100));
        drop(runs.start("r1", "a", "local", "t1"));
        let g = runs.start("r1", "a", "local", "t1"); // runs again
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            runs.lookup("r1", "a").unwrap().in_flight,
            "the old finish does not prune it"
        );
        drop(g);
        assert!(
            runs.lookup("r1", "a").is_some(),
            "known for the window after its new finish"
        );
    }

    #[test]
    fn expired_runs_are_dropped_from_the_map() {
        let runs = Runs::new(Duration::from_millis(50));
        for i in 0..1000 {
            drop(runs.start(&format!("r{i}"), "a", "local", "t"));
        }
        std::thread::sleep(Duration::from_millis(80));
        assert!(runs.lookup("x", "a").is_none());
        let inner = runs.inner.lock().unwrap();
        assert!(inner.map.is_empty() && inner.finished.is_empty());
    }

    #[test]
    fn model_calls_are_counted_against_the_run() {
        let runs = Runs::new(Duration::from_secs(60));
        let limits = CallLimits {
            calls: 2,
            reflections: 1,
        };
        assert_eq!(
            runs.admit_model_call("r1", "a", limits, 2).unwrap_err(),
            None,
            "no run"
        );
        let g = runs.start_run(
            "r1",
            "a",
            RunInfo {
                caller: "local".into(),
                span_id: "00f067aa0ba902b7".into(),
                ..RunInfo::default()
            },
        );
        for _ in 0..2 {
            let (kind, s) = runs.admit_model_call("r1", "a", limits, 2).unwrap();
            assert_eq!(
                (kind, s.span_id.as_str()),
                (CallKind::Step, "00f067aa0ba902b7")
            );
        }
        let v = runs
            .admit_model_call("r1", "a", limits, 2)
            .unwrap_err()
            .unwrap();
        assert_eq!(v.rule, "budget.max_steps");
        runs.add_usage("r1", "a", 10, 5, 0.25);
        runs.add_usage("r1", "a", 1, 1, 0.5);
        runs.note_denial("r1", "a", &v);
        runs.note_denial("r1", "a", &Verdict::deny("budget.other", "later"));
        drop(g);
        let (kind, _) = runs.admit_model_call("r1", "a", limits, 2).unwrap();
        assert_eq!(kind, CallKind::Reflection);
        let v = runs
            .admit_model_call("r1", "a", limits, 2)
            .unwrap_err()
            .unwrap();
        assert_eq!(v.rule, crate::gateway::RULE_UNBOUND, "one reflection");
        let m = runs.lookup("r1", "a").unwrap().meter;
        assert_eq!(
            (m.calls, m.reflections, m.input_tokens, m.output_tokens),
            (2, 1, 11, 6)
        );
        assert_eq!(m.cost_usd, 0.75);
        assert_eq!(m.denial.unwrap().rule, "budget.max_steps", "the first one");
    }
}
