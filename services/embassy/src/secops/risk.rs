//! Risk scoring of agents (CONTRACT.md §5.5): each agent's part of a run, from the run's ledger
//! records, against the agent's own baseline. A port of nexc-engine's `domain/risk.rs`, with its
//! constants and its rules:
//!
//! - **Features** of a run: model turns, tokens per turn, tool calls per turn, distinct tools,
//!   distinct hosts (`http_call`s), agent calls, denials, egress calls. (nexc's `bytes_out` has no
//!   source here: audit records carry hashes, not sizes.)
//! - **Baselines**: Welford's running mean and variance per feature over every run learned (no
//!   window), the hosts and tools ever seen (at most [`LEARNED_PER_RUN`] new ones per run), and the
//!   MinHash signatures of the last [`SIGNATURES_KEPT`] runs' tool sequences.
//! - **The score**: nothing before [`MIN_RUNS`] runs; a feature counts from z ≥ [`NOTABLE_Z`] and
//!   adds min(z, [`Z_CAP`]); new hosts add min(n, 3), new tools add 1, a tool sequence unlike any
//!   earlier one adds 1; capped at [`SCORE_CAP`]; rounded to 2 places. Only upward deviations
//!   count. The reasons are words. There is no decay.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MIN_RUNS: u64 = 3;
pub const Z_CAP: f64 = 3.0;
pub const SCORE_CAP: f64 = 10.0;
pub const NOTABLE_Z: f64 = 2.0;
pub const NOVEL_BELOW: f64 = 0.2;
pub const NEAR_ZERO: f64 = 0.05;
pub const SIGNATURES_KEPT: usize = 20;
pub const LEARNED_PER_RUN: usize = 64;
/// MinHash functions per signature.
pub const K: usize = 64;

/// The features scored, with the words a reason uses for them.
pub const FEATURES: [(&str, &str); 7] = [
    ("tool_calls_per_turn", "tool calls per turn"),
    ("tokens_per_turn", "tokens per turn"),
    ("distinct_tools", "distinct tools"),
    ("distinct_hosts", "hosts"),
    ("spawns", "agent calls"),
    ("denials", "policy denials"),
    ("egress_calls", "egress calls"),
];

/// What one agent did in one run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunFeatures {
    pub turns: u64,
    pub tokens: u64,
    pub tool_calls: u64,
    pub spawns: u64,
    pub denials: u64,
    pub egress_calls: u64,
    pub tools: BTreeSet<String>,
    pub hosts: BTreeSet<String>,
    /// The tools called, in order.
    pub sequence: Vec<String>,
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let host = host.split(':').next()?.to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

impl RunFeatures {
    /// The features of the records (one agent's, of one run), as the ledger keeps them.
    pub fn of(records: &[&Value]) -> RunFeatures {
        let mut f = RunFeatures::default();
        for r in records {
            let kind = r["kind"].as_str().unwrap_or("");
            let callee = r["callee"].as_str().unwrap_or("");
            match kind {
                "model_call" => {
                    f.turns += 1;
                    f.tokens += r["tokens"]["input"].as_u64().unwrap_or(0)
                        + r["tokens"]["output"].as_u64().unwrap_or(0);
                }
                "tool_call" if r["decision"] == "allow" => {
                    f.tool_calls += 1;
                    f.tools.insert(callee.to_string());
                    f.sequence.push(callee.to_string());
                }
                "http_call" => {
                    f.egress_calls += 1;
                    if let Some(h) = host_of(callee) {
                        f.hosts.insert(h);
                    }
                }
                "agent_call" => f.spawns += 1,
                _ => {}
            }
            if r["decision"] == "deny" {
                f.denials += 1;
            }
        }
        f
    }

    /// The value of feature `name`.
    pub fn get(&self, name: &str) -> f64 {
        let per_turn = |n: u64| n as f64 / self.turns.max(1) as f64;
        match name {
            "tool_calls_per_turn" => per_turn(self.tool_calls),
            "tokens_per_turn" => per_turn(self.tokens),
            "distinct_tools" => self.tools.len() as f64,
            "distinct_hosts" => self.hosts.len() as f64,
            "spawns" => self.spawns as f64,
            "denials" => self.denials as f64,
            "egress_calls" => self.egress_calls as f64,
            _ => 0.0,
        }
    }
}

/// Welford's running moments of one feature.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Moments {
    pub mean: f64,
    pub m2: f64,
    pub n: u64,
}

impl Moments {
    fn learn(&mut self, x: f64) {
        self.n += 1;
        let d = x - self.mean;
        self.mean += d / self.n as f64;
        self.m2 += d * (x - self.mean);
    }

    fn stddev(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            (self.m2 / (self.n - 1) as f64).sqrt()
        }
    }
}

/// An agent's baseline, as the store keeps it (JSON).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    pub runs: u64,
    pub features: BTreeMap<String, Moments>,
    pub hosts: BTreeSet<String>,
    pub tools: BTreeSet<String>,
    pub signatures: Vec<Vec<u64>>,
}

/// One run's score.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Risk {
    pub score: f64,
    pub reasons: Vec<String>,
    /// z per feature scored, rounded to 2 places.
    pub z: BTreeMap<String, f64>,
    /// 1 − the highest similarity to an earlier run's tool sequence (0 with nothing to compare).
    pub novelty: f64,
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

fn tokens(sequence: &[String]) -> Vec<String> {
    sequence
        .iter()
        .flat_map(|t| {
            t.to_ascii_lowercase()
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|w| !w.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// FNV-1a of `bytes` with seed `seed`.
fn fnv(seed: u64, bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// The MinHash signature (K values) of the word bigrams of a tool sequence; `None` when empty.
pub fn signature(sequence: &[String]) -> Option<Vec<u64>> {
    let words = tokens(sequence);
    let grams: Vec<String> = if words.len() < 2 {
        words.clone()
    } else {
        words
            .windows(2)
            .map(|w| format!("{} {}", w[0], w[1]))
            .collect()
    };
    if grams.is_empty() {
        return None;
    }
    Some(
        (0..K as u64)
            .map(|i| {
                grams
                    .iter()
                    .map(|g| fnv(i, g.as_bytes()))
                    .min()
                    .unwrap_or(u64::MAX)
            })
            .collect(),
    )
}

fn similarity(a: &[u64], b: &[u64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    a.iter().zip(b).filter(|(x, y)| x == y).count() as f64 / a.len() as f64
}

fn ratio(value: f64, mean: f64) -> String {
    let r = value / mean;
    if r >= 10.0 {
        format!("{r:.0}x")
    } else {
        format!("{r:.1}x")
    }
}

fn names(set: &BTreeSet<String>) -> String {
    set.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
}

/// Score `run` against `baseline` (module docs).
pub fn score(baseline: &Baseline, run: &RunFeatures) -> Risk {
    let mut risk = Risk::default();
    if let Some(sig) = signature(&run.sequence) {
        let best = baseline
            .signatures
            .iter()
            .map(|s| similarity(s, &sig))
            .fold(0.0f64, f64::max);
        risk.novelty = if baseline.signatures.is_empty() {
            0.0
        } else {
            round2(1.0 - best)
        };
    }
    if baseline.runs < MIN_RUNS {
        return risk;
    }
    let mut total = 0.0f64;
    for (name, what) in FEATURES {
        let Some(m) = baseline.features.get(name).copied() else {
            continue;
        };
        let learned = if m.n == 0 { baseline.runs } else { m.n };
        if learned < MIN_RUNS {
            continue;
        }
        let value = run.get(name);
        let sd = Moments { n: learned, ..m }.stddev();
        let z = if sd < f64::EPSILON {
            if (value - m.mean).abs() < f64::EPSILON {
                0.0
            } else if value > m.mean {
                Z_CAP
            } else {
                -Z_CAP
            }
        } else {
            (value - m.mean) / sd
        };
        risk.z.insert(name.to_string(), round2(z));
        if z >= NOTABLE_Z {
            total += z.min(Z_CAP);
            risk.reasons.push(if m.mean < NEAR_ZERO {
                format!("{value:.0} {what} where it usually has none")
            } else {
                format!("{} its usual {what}", ratio(value, m.mean))
            });
        }
    }
    let new_hosts: BTreeSet<String> = run.hosts.difference(&baseline.hosts).cloned().collect();
    if !new_hosts.is_empty() {
        total += (new_hosts.len() as f64).min(Z_CAP);
        let s = if new_hosts.len() == 1 { "" } else { "s" };
        risk.reasons.push(format!(
            "{} host{s} it never called: {}",
            new_hosts.len(),
            names(&new_hosts)
        ));
    }
    let new_tools: BTreeSet<String> = run.tools.difference(&baseline.tools).cloned().collect();
    if !new_tools.is_empty() {
        total += 1.0;
        let s = if new_tools.len() == 1 { "" } else { "s" };
        risk.reasons.push(format!(
            "{} tool{s} it never used: {}",
            new_tools.len(),
            names(&new_tools)
        ));
    }
    if risk.novelty > 1.0 - NOVEL_BELOW {
        total += 1.0;
        risk.reasons
            .push("a sequence of tool calls unlike any earlier run".into());
    }
    risk.score = round2(total.min(SCORE_CAP));
    risk
}

/// Learn `run` into `baseline`.
pub fn learn(baseline: &mut Baseline, run: &RunFeatures) {
    baseline.runs += 1;
    for (name, _) in FEATURES {
        baseline
            .features
            .entry(name.to_string())
            .or_default()
            .learn(run.get(name));
    }
    for h in run
        .hosts
        .iter()
        .filter(|h| !baseline.hosts.contains(*h))
        .take(LEARNED_PER_RUN)
        .cloned()
        .collect::<Vec<_>>()
    {
        baseline.hosts.insert(h);
    }
    for t in run
        .tools
        .iter()
        .filter(|t| !baseline.tools.contains(*t))
        .take(LEARNED_PER_RUN)
        .cloned()
        .collect::<Vec<_>>()
    {
        baseline.tools.insert(t);
    }
    if let Some(sig) = signature(&run.sequence) {
        baseline.signatures.push(sig);
        let over = baseline.signatures.len().saturating_sub(SIGNATURES_KEPT);
        baseline.signatures.drain(..over);
    }
}

// ---- in embassy ---------------------------------------------------------------------------------

/// The actor of an automatic quarantine.
pub const RISK_ACTOR: &str = "embassy:risk";
/// How often [`scorer`] looks for runs to score.
pub const SCORE_TICK: std::time::Duration = std::time::Duration::from_secs(2);

/// Score every agent of run `chain` once (another replica may have taken it): learn the run into
/// each agent's baseline, keep the score, and quarantine an agent whose score reaches
/// `risk.quarantine_score` (such a run is not learned).
pub async fn score_chain(
    hub: &crate::hub::Hub,
    chain: &str,
) -> Result<(), crate::store::StoreError> {
    let Some(store) = hub.secops() else {
        return Ok(());
    };
    if !store.risk_claim(chain).await? {
        return Ok(());
    }
    let entries = store.ledger_entries(chain).await?;
    let mut by_agent: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for e in &entries {
        if let Some(id) = e.record["agent_id"].as_str() {
            by_agent.entry(id.to_string()).or_default().push(&e.record);
        }
    }
    let threshold = hub.config.load().risk.quarantine_score;
    for (agent_id, records) in by_agent {
        let run = RunFeatures::of(&records);
        let (risk, learned_before) = loop {
            let found = store.get_baseline(&agent_id).await?;
            let mut baseline: Baseline = found
                .as_ref()
                .and_then(|(_, s)| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let risk = score(&baseline, &run);
            let quarantine =
                threshold.is_some_and(|t| risk.score >= t) && baseline.runs >= MIN_RUNS;
            if quarantine {
                break (risk, baseline.runs);
            }
            learn(&mut baseline, &run);
            let state = serde_json::to_string(&baseline).unwrap_or_default();
            let at = crate::cp_audit::now_ts();
            if store
                .put_baseline(&agent_id, found.map(|(n, _)| n), baseline.runs, &state, &at)
                .await?
            {
                break (risk, baseline.runs - 1);
            }
        };
        store
            .put_risk(&super::RiskRow {
                agent_id: agent_id.clone(),
                chain: chain.to_string(),
                score: risk.score,
                reasons: risk.reasons.clone(),
                novelty: risk.novelty,
                scored_at: crate::cp_audit::now_ts(),
            })
            .await?;
        if let Some(t) = threshold
            && risk.score >= t
            && learned_before >= MIN_RUNS
        {
            quarantine_by_score(hub, &agent_id, &risk, t, chain).await;
        }
    }
    Ok(())
}

async fn quarantine_by_score(
    hub: &crate::hub::Hub,
    agent_id: &str,
    risk: &Risk,
    t: f64,
    chain: &str,
) {
    let Some(store) = hub.secops() else {
        return;
    };
    let reason = format!(
        "automatic: risk score {} over {t} in run {chain} ({})",
        risk.score,
        risk.reasons.join("; ")
    );
    let actor = crate::store::Actor {
        name: RISK_ACTOR.into(),
        kind: crate::store::ActorKind::System,
        role: None,
    };
    match store
        .quarantine_agent(agent_id, &reason, &actor, &crate::cp_audit::now_ts())
        .await
    {
        Ok(a) => {
            let mut rec = crate::cp_audit::CpAudit::entry(
                crate::api::types::CpAction::AgentQuarantined,
                &actor,
                crate::api::types::CpResult::Ok,
            );
            rec.namespace = Some(a.namespace.clone());
            rec.service = Some(a.service.clone());
            rec.agent = Some(a.name.clone());
            rec.reason = Some(format!("{}: {reason}", a.principal));
            hub.cp_audit.record(rec).await;
            let key = crate::store::ServiceKey::new(&a.namespace, &a.service);
            crate::controlplane::push_agents(hub, &key).await;
            super::approvals::expire_agent(hub, &a.namespace, &a.service, &a.name).await;
            tracing::warn!(
                agent = a.principal,
                score = risk.score,
                "agent quarantined by its risk score"
            );
        }
        // quarantined already
        Err(crate::store::StoreError::Conflict { .. }) => {}
        Err(e) => tracing::error!(agent_id, error = %e, "quarantining by risk score failed"),
    }
}

/// Score the runs that have been quiet for `quiet`, every [`SCORE_TICK`], until shutdown.
pub async fn scorer(
    hub: std::sync::Arc<crate::hub::Hub>,
    quiet: std::time::Duration,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let Some(store) = hub.secops().cloned() else {
        return;
    };
    let mut tick = tokio::time::interval(SCORE_TICK);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = shutdown.cancelled() => return,
        }
        let before = (chrono::Utc::now()
            - chrono::Duration::from_std(quiet).unwrap_or(chrono::Duration::zero()))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
        let chains = match store.risk_unscored(&before, 100).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "risk scorer: listing the runs failed");
                continue;
            }
        };
        for chain in chains {
            if let Err(e) = score_chain(&hub, &chain).await {
                tracing::warn!(chain, error = %e, "risk scorer: scoring failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(tools: &[&str], hosts: &[&str], denials: u64, egress: u64) -> RunFeatures {
        RunFeatures {
            turns: 2,
            tokens: 270,
            tool_calls: tools.len() as u64,
            denials,
            egress_calls: egress,
            tools: tools.iter().map(|s| s.to_string()).collect(),
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            sequence: tools.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn features_count_what_a_run_did() {
        let recs = [
            json!({"kind": "model_call", "tokens": {"input": 100, "output": 35}, "decision": "allow"}),
            json!({"kind": "tool_call", "callee": "write_file", "decision": "allow"}),
            json!({"kind": "model_call", "tokens": {"input": 120, "output": 15}, "decision": "allow"}),
            json!({"kind": "tool_call", "callee": "finish", "decision": "allow"}),
            json!({"kind": "tool_call", "callee": "http_get", "decision": "allow"}),
            json!({"kind": "http_call", "callee": "https://API.example.com:443/v1?q=1", "decision": "allow"}),
            json!({"kind": "agent_call", "callee": "inventory/stock", "decision": "allow"}),
            json!({"kind": "tool_call", "callee": "admin", "decision": "deny"}),
        ];
        let f = RunFeatures::of(&recs.iter().collect::<Vec<_>>());
        assert_eq!(
            (f.turns, f.tool_calls, f.spawns, f.denials, f.egress_calls),
            (2, 3, 1, 1, 1)
        );
        assert_eq!(f.get("tool_calls_per_turn"), 1.5);
        assert_eq!(f.get("tokens_per_turn"), 135.0);
        assert_eq!(f.get("distinct_tools"), 3.0);
        assert_eq!(f.hosts.iter().collect::<Vec<_>>(), ["api.example.com"]);
        assert_eq!(f.sequence.join(" "), "write_file finish http_get");
    }

    #[test]
    fn a_young_baseline_scores_nothing_and_a_usual_run_scores_low() {
        let mut b = Baseline::default();
        let usual = run(&["lookup", "answer"], &[], 0, 0);
        assert_eq!(score(&b, &usual).score, 0.0);
        for _ in 0..3 {
            learn(&mut b, &usual);
        }
        let r = score(&b, &usual);
        assert_eq!((r.score, r.reasons.len(), r.novelty), (0.0, 0, 0.0));
    }

    #[test]
    fn five_times_the_usual_egress_and_new_hosts_raise_the_score_in_words() {
        let mut b = Baseline::default();
        for e in [9, 10, 11, 10, 9] {
            learn(
                &mut b,
                &run(&["lookup", "answer"], &["api.example.com"], 0, e),
            );
        }
        let odd = run(
            &["lookup", "answer", "http_get"],
            &["a.evil.example", "b.evil.example"],
            6,
            50,
        );
        let r = score(&b, &odd);
        assert!(r.score > 5.0 && r.score <= 10.0, "{r:?}");
        assert!(
            r.reasons
                .iter()
                .any(|x| x.ends_with("its usual egress calls")),
            "{r:?}"
        );
        assert!(
            r.reasons
                .contains(&"2 hosts it never called: a.evil.example, b.evil.example".to_string()),
            "{r:?}"
        );
        assert!(
            r.reasons
                .contains(&"6 policy denials where it usually has none".to_string()),
            "{r:?}"
        );
        assert!(
            r.reasons
                .contains(&"1 tool it never used: http_get".to_string()),
            "{r:?}"
        );
        assert!(r.novelty > 0.0);
        for _ in 0..20 {
            learn(&mut b, &odd);
        }
        assert_eq!(b.signatures.len(), SIGNATURES_KEPT);
    }

    #[test]
    fn an_unseen_tool_sequence_is_novel() {
        let mut b = Baseline::default();
        for _ in 0..4 {
            learn(
                &mut b,
                &run(&["lookup_order", "answer_customer"], &[], 0, 0),
            );
        }
        let r = score(&b, &run(&["delete_records", "export_dump"], &[], 0, 0));
        assert!(r.novelty > 0.8, "{r:?}");
        assert!(
            r.reasons
                .contains(&"a sequence of tool calls unlike any earlier run".to_string())
        );
    }

    #[test]
    fn one_run_teaches_a_bounded_number_of_hosts() {
        let mut b = Baseline::default();
        let hosts: Vec<String> = (0..200).map(|i| format!("h{i}.example")).collect();
        let r = RunFeatures {
            hosts: hosts.into_iter().collect(),
            ..Default::default()
        };
        learn(&mut b, &r);
        assert_eq!(b.hosts.len(), LEARNED_PER_RUN);
    }
}
