//! Per-agent budgets kept in memory by one sidecar replica (CONTRACT.md §11).
//!
//! The daily cost budget is held by reservation: before a model call goes out, the sidecar
//! reserves the most that call can cost ([`crate::pricing::worst_case_usd`]) and refuses it when
//! what was spent today, what calls in flight have reserved and this reservation would exceed the
//! limit. When the call ends, its reservation is replaced by what the provider says it used. So
//! concurrent calls cannot overshoot the limit together, and nothing the runtime reports is needed.
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::authz::Verdict;

pub const RULE_COST: &str = "budget.max_cost_usd_per_day";

#[derive(Default)]
pub struct Budgets {
    calls: Mutex<HashMap<String, VecDeque<Instant>>>,
    cost: Mutex<HashMap<String, Cost>>,
}

#[derive(Default)]
struct Cost {
    /// The UTC day `spent` counts, `YYYY-MM-DD`.
    day: String,
    spent: f64,
    /// Held by calls in flight, whatever day they started.
    reserved: f64,
}

impl Cost {
    fn spent_on(&self, today: &str) -> f64 {
        if self.day == today { self.spent } else { 0.0 }
    }
}

/// A model call's hold on an agent's daily cost budget. [`Budgets::settle`] replaces it with the
/// call's real cost; dropped unsettled, it is released and nothing is counted.
#[must_use]
pub struct Reservation {
    budgets: Arc<Budgets>,
    agent: String,
    usd: f64,
    settled: bool,
}

impl Reservation {
    pub fn usd(&self) -> f64 {
        self.usd
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.settled {
            self.budgets.release(&self.agent, self.usd, 0.0);
        }
    }
}

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

impl Budgets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sliding one-minute window; records the call when allowed.
    pub fn check_rate(&self, agent: &str, max_per_minute: u32) -> Verdict {
        self.check_rate_at(agent, max_per_minute, Instant::now())
    }

    pub fn check_rate_at(&self, agent: &str, max_per_minute: u32, now: Instant) -> Verdict {
        let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
        let q = calls.entry(agent.to_string()).or_default();
        while let Some(front) = q.front() {
            if now.duration_since(*front) > Duration::from_secs(60) {
                q.pop_front();
            } else {
                break;
            }
        }
        if q.len() >= max_per_minute as usize {
            return Verdict::deny(
                "budget.max_calls_per_minute",
                format!(
                    "agent {agent} already handled {} calls in the last minute (limit {max_per_minute})",
                    q.len()
                ),
            );
        }
        q.push_back(now);
        Verdict::allow("budget.max_calls_per_minute")
    }

    /// Denied once what the agent spent today plus what its calls in flight hold reaches the limit.
    pub fn check_cost(&self, agent: &str, max_usd_per_day: f64) -> Verdict {
        let today = today();
        let cost = self.cost.lock().unwrap_or_else(PoisonError::into_inner);
        let (spent, reserved) = cost
            .get(agent)
            .map_or((0.0, 0.0), |c| (c.spent_on(&today), c.reserved));
        if spent + reserved >= max_usd_per_day {
            return Verdict::deny(
                RULE_COST,
                format!(
                    "agent {agent} spent ${spent:.4} today and holds ${reserved:.4} for calls in flight (limit ${max_usd_per_day:.2})"
                ),
            );
        }
        Verdict::allow(RULE_COST)
    }

    /// Hold `usd` (the most the call can cost) against the agent's daily limit, or refuse when
    /// spent + held + `usd` would exceed it.
    pub fn reserve(
        self: &Arc<Self>,
        agent: &str,
        usd: f64,
        max_usd_per_day: f64,
    ) -> Result<Reservation, Verdict> {
        let today = today();
        let mut cost = self.cost.lock().unwrap_or_else(PoisonError::into_inner);
        let c = cost.entry(agent.to_string()).or_default();
        let spent = c.spent_on(&today);
        if spent + c.reserved + usd > max_usd_per_day {
            return Err(Verdict::deny(
                RULE_COST,
                format!(
                    "agent {agent} spent ${spent:.4} today and holds ${:.4} for calls in flight; this call may cost up to ${usd:.4} (limit ${max_usd_per_day:.2})",
                    c.reserved
                ),
            ));
        }
        c.reserved += usd;
        Ok(Reservation {
            budgets: self.clone(),
            agent: agent.to_string(),
            usd,
            settled: false,
        })
    }

    /// The call ended and cost `actual_usd`: count that instead of its reservation.
    pub fn settle(&self, mut r: Reservation, actual_usd: f64) {
        r.settled = true;
        self.release(&r.agent, r.usd, actual_usd);
    }

    fn release(&self, agent: &str, reserved: f64, actual: f64) {
        let today = today();
        let mut cost = self.cost.lock().unwrap_or_else(PoisonError::into_inner);
        let c = cost.entry(agent.to_string()).or_default();
        c.reserved = (c.reserved - reserved).max(0.0);
        if actual > 0.0 {
            if c.day != today {
                c.day = today;
                c.spent = 0.0;
            }
            c.spent += actual;
        }
    }

    /// Count `usd` as spent today (a cost the sidecar measured outside a reservation).
    pub fn add_cost(&self, agent: &str, usd: f64) {
        self.release(agent, 0.0, usd);
    }

    pub fn spent_today(&self, agent: &str) -> f64 {
        let today = today();
        self.cost
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(agent)
            .map_or(0.0, |c| c.spent_on(&today))
    }

    /// What the agent's calls in flight hold.
    pub fn reserved(&self, agent: &str) -> f64 {
        self.cost
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(agent)
            .map_or(0.0, |c| c.reserved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_slides() {
        let b = Budgets::new();
        let t0 = Instant::now();
        assert!(b.check_rate_at("a", 2, t0).allow);
        assert!(b.check_rate_at("a", 2, t0).allow);
        let v = b.check_rate_at("a", 2, t0);
        assert_eq!(v.rule, "budget.max_calls_per_minute");
        assert!(!v.allow);
        assert!(b.check_rate_at("b", 2, t0).allow, "limits are per agent");
        assert!(b.check_rate_at("a", 2, t0 + Duration::from_secs(61)).allow);
    }

    #[test]
    fn cost_budget() {
        let b = Budgets::new();
        assert!(b.check_cost("a", 1.0).allow);
        b.add_cost("a", 0.6);
        b.add_cost("a", 0.5);
        let v = b.check_cost("a", 1.0);
        assert!(!v.allow);
        assert_eq!(v.rule, RULE_COST);
        assert!((b.spent_today("a") - 1.1).abs() < 1e-9);
    }

    #[test]
    fn reservations_keep_concurrent_calls_inside_the_limit() {
        let b = Arc::new(Budgets::new());
        let first = b.reserve("a", 0.6, 1.0).expect("fits");
        let refused = b.reserve("a", 0.6, 1.0).err().expect("0.6 + 0.6 > 1.0");
        assert_eq!(refused.rule, RULE_COST);
        assert!(b.reserve("b", 0.6, 1.0).is_ok(), "per agent");
        assert!(!b.check_cost("a", 0.5).allow, "a hold counts like spend");
        b.settle(first, 0.25);
        assert!((b.spent_today("a") - 0.25).abs() < 1e-9);
        assert_eq!(b.reserved("a"), 0.0);
        let second = b.reserve("a", 0.6, 1.0).expect("0.25 + 0.6 fits");
        drop(second);
        assert_eq!(b.reserved("a"), 0.0, "an unsettled reservation is released");
        assert!(
            (b.spent_today("a") - 0.25).abs() < 1e-9,
            "and counts nothing"
        );
        assert!(b.reserve("a", 0.75, 1.0).is_ok(), "exactly the limit fits");
    }
}
