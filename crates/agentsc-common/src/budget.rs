//! Per-agent budgets kept in memory by one sidecar replica (CONTRACT.md §11).
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::authz::Verdict;

#[derive(Default)]
pub struct Budgets {
    calls: Mutex<HashMap<String, VecDeque<Instant>>>,
    cost: Mutex<HashMap<String, (String, f64)>>, // agent → (utc day, usd)
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
        let mut calls = self.calls.lock().unwrap();
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

    pub fn check_cost(&self, agent: &str, max_usd_per_day: f64) -> Verdict {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let cost = self.cost.lock().unwrap();
        let spent = match cost.get(agent) {
            Some((day, usd)) if *day == today => *usd,
            _ => 0.0,
        };
        if spent >= max_usd_per_day {
            return Verdict::deny(
                "budget.max_cost_usd_per_day",
                format!("agent {agent} spent ${spent:.4} today (limit ${max_usd_per_day:.2})"),
            );
        }
        Verdict::allow("budget.max_cost_usd_per_day")
    }

    pub fn add_cost(&self, agent: &str, usd: f64) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let mut cost = self.cost.lock().unwrap();
        let entry = cost
            .entry(agent.to_string())
            .or_insert_with(|| (today.clone(), 0.0));
        if entry.0 != today {
            *entry = (today, 0.0);
        }
        entry.1 += usd;
    }

    pub fn spent_today(&self, agent: &str) -> f64 {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        match self.cost.lock().unwrap().get(agent) {
            Some((day, usd)) if *day == today => *usd,
            _ => 0.0,
        }
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
        assert_eq!(v.rule, "budget.max_cost_usd_per_day");
        assert!((b.spent_today("a") - 1.1).abs() < 1e-9);
    }
}
