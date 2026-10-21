//! Executes in flight and recently finished (design §6.5): `ReportEvent` and `ProposeLesson` are
//! accepted only for a request id and agent whose Execute is running or returned less than the
//! run window (120 s) ago. Keyed by (request id, agent): a local orchestrator and the local agent
//! it calls share the request id.
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Entry {
    caller: String,
    trace_id: String,
    in_flight: u32,
    finished_at: Option<Instant>,
}

/// What [`Runs::lookup`] knows about a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunState {
    pub in_flight: bool,
    /// `local` or the peer's SPIFFE id. When Executes of the same request and agent came from
    /// different callers, a peer wins (learning treats the run as a peer's).
    pub caller: String,
    pub trace_id: String,
}

pub struct Runs {
    window: Duration,
    map: Mutex<HashMap<(String, String), Entry>>,
}

/// Marks the Execute finished when dropped (also when the caller drops the invocation).
#[must_use]
pub struct RunGuard<'a> {
    runs: &'a Runs,
    key: (String, String),
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        let mut map = self.runs.map.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(e) = map.get_mut(&self.key) {
            e.in_flight = e.in_flight.saturating_sub(1);
            if e.in_flight == 0 {
                e.finished_at = Some(Instant::now());
            }
        }
    }
}

impl Runs {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    fn prune(&self, map: &mut HashMap<(String, String), Entry>, now: Instant) {
        map.retain(|_, e| {
            e.in_flight > 0
                || e.finished_at
                    .is_some_and(|t| now.duration_since(t) < self.window)
        });
    }

    /// An Execute of `agent` for `request_id` starts.
    pub fn start(
        &self,
        request_id: &str,
        agent: &str,
        caller: &str,
        trace_id: &str,
    ) -> RunGuard<'_> {
        let key = (request_id.to_string(), agent.to_string());
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        self.prune(&mut map, Instant::now());
        let e = map.entry(key.clone()).or_insert_with(|| Entry {
            caller: caller.to_string(),
            trace_id: trace_id.to_string(),
            in_flight: 0,
            finished_at: None,
        });
        if caller != agentsc_charter::LOCAL_IDENTITY {
            e.caller = caller.to_string();
        }
        e.in_flight += 1;
        e.finished_at = None;
        RunGuard { runs: self, key }
    }

    /// The run, if it is in flight or finished less than the window ago.
    pub fn lookup(&self, request_id: &str, agent: &str) -> Option<RunState> {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        self.prune(&mut map, Instant::now());
        map.get(&(request_id.to_string(), agent.to_string()))
            .map(|e| RunState {
                in_flight: e.in_flight > 0,
                caller: e.caller.clone(),
                trace_id: e.trace_id.clone(),
            })
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
}
