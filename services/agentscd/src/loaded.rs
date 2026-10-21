//! What one request sees (design §6.2): the charter, its compiled guardrails, where it came from
//! and the service's memory. Swapped whole on every reload; each request takes one snapshot.
use std::collections::BTreeMap;
use std::sync::Arc;

use agentsc_charter::{Charter, RuntimeNote};
use agentsc_common::guardrails::CompiledGuardrails;
use serde::{Deserialize, Serialize};

/// Where a charter came from (`config` records: `input.source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The `--charter` file.
    File,
    /// A `CharterUpdate` / `MemoryUpdate` on the `Connect` stream.
    ControlPlane,
    /// What the control plane sent earlier, read back from `--state-dir` after a restart.
    State,
    /// A lesson the sidecar applied itself (unmanaged, `learning.mode: auto`).
    Learning,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::File => "file",
            Source::ControlPlane => "control-plane",
            Source::State => "state",
            Source::Learning => "learning",
        }
    }

    /// The `caller` of a `config` record: `file` or `control-plane` (design §5).
    pub fn caller(self) -> &'static str {
        match self {
            Source::File | Source::Learning => "file",
            Source::ControlPlane | Source::State => "control-plane",
        }
    }

    /// Charters the control plane is the source of (directly or persisted).
    pub fn from_control_plane(self) -> bool {
        matches!(self, Source::ControlPlane | Source::State)
    }
}

/// One memory note (proto `Note`), as persisted in `<state-dir>/memory.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MemoryNote {
    pub id: String,
    pub text: String,
    pub source: String,
    pub request_id: String,
    pub trace_id: String,
    pub approved_by: String,
    pub ts: String,
    pub expires_at: String,
}

impl From<&agentsc_proto::Note> for MemoryNote {
    fn from(n: &agentsc_proto::Note) -> Self {
        Self {
            id: n.id.clone(),
            text: n.text.clone(),
            source: n.source.clone(),
            request_id: n.request_id.clone(),
            trace_id: n.trace_id.clone(),
            approved_by: n.approved_by.clone(),
            ts: n.ts.clone(),
            expires_at: n.expires_at.clone(),
        }
    }
}

impl MemoryNote {
    /// Not expired at `now` (an RFC 3339 `expires_at`; empty = never).
    pub fn active_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        if self.expires_at.trim().is_empty() {
            return true;
        }
        match chrono::DateTime::parse_from_rfc3339(self.expires_at.trim()) {
            Ok(t) => t.with_timezone(&chrono::Utc) > now,
            // A note whose expiry cannot be read is not trusted to be current.
            Err(_) => false,
        }
    }
}

/// The service's memory: a full replacement per `MemoryUpdate` (design §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Memory {
    /// The control plane's memory version (a decimal `u64`); empty when none was applied.
    pub version: String,
    pub agents: BTreeMap<String, Vec<MemoryNote>>,
}

impl Memory {
    pub fn from_update(u: &agentsc_proto::MemoryUpdate) -> Self {
        Self {
            version: u.version.clone(),
            agents: u
                .agents
                .iter()
                .map(|(agent, list)| (agent.clone(), list.notes.iter().map(Into::into).collect()))
                .collect(),
        }
    }

    pub fn version_number(&self) -> u64 {
        self.version.parse().unwrap_or(0)
    }

    /// SHA-256 of the canonical JSON (for `config` records).
    pub fn sha256(&self) -> String {
        agentsc_common::audit::sha256_hex(&serde_json::to_vec(self).unwrap_or_default())
    }
}

pub struct Loaded {
    pub charter: Charter,
    pub guardrails: Arc<CompiledGuardrails>,
    /// Store epoch of a control-plane charter; empty for a file charter.
    pub epoch: String,
    /// Charter version (decimal `u64`) of a control-plane charter; empty for a file charter.
    pub version: String,
    /// SHA-256 of the charter text as received.
    pub sha256: String,
    pub source: Source,
    pub memory: Memory,
}

impl Loaded {
    /// The agent's active notes, oldest first, for `ExecuteRequest.agent_spec_json`.
    /// [`Charter::runtime_spec`] passes them on only when the agent has learning enabled; at most
    /// `learning.max_notes` (the newest) are given.
    pub fn runtime_notes(&self, agent: &str) -> Vec<RuntimeNote> {
        let Some(notes) = self.memory.agents.get(agent) else {
            return Vec::new();
        };
        let now = chrono::Utc::now();
        let mut active: Vec<&MemoryNote> = notes.iter().filter(|n| n.active_at(now)).collect();
        // oldest first; notes without a timestamp keep their place before the dated ones
        active.sort_by(|a, b| a.ts.cmp(&b.ts));
        let max = self
            .charter
            .agent(agent)
            .map(|a| a.learning_or_default().max_notes as usize)
            .unwrap_or(0);
        let skip = active.len().saturating_sub(max);
        active
            .into_iter()
            .skip(skip)
            .map(|n| RuntimeNote {
                id: n.id.clone(),
                text: n.text.clone(),
            })
            .collect()
    }

    /// The agent's `agent_spec_json` (design §4: `Charter::runtime_spec` with its memory).
    pub fn runtime_spec(&self, agent: &str) -> serde_json::Value {
        self.charter.runtime_spec(agent, &self.runtime_notes(agent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_expire_and_come_oldest_first() {
        let now = chrono::Utc::now();
        let fmt = |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339();
        let n = |id: &str, ts: &str, expires: &str| MemoryNote {
            id: id.into(),
            text: format!("note {id}"),
            ts: ts.into(),
            expires_at: expires.into(),
            ..Default::default()
        };
        assert!(n("a", "", "").active_at(now));
        assert!(n("a", "", &fmt(now + chrono::Duration::hours(1))).active_at(now));
        assert!(!n("a", "", &fmt(now - chrono::Duration::hours(1))).active_at(now));
        assert!(!n("a", "", "not a time").active_at(now));
    }

    #[test]
    fn memory_round_trips_from_the_update() {
        let mut agents = std::collections::HashMap::new();
        agents.insert(
            "support".to_string(),
            agentsc_proto::NoteList {
                notes: vec![agentsc_proto::Note {
                    id: "n1".into(),
                    text: "Look up the order first.".into(),
                    source: "review".into(),
                    ..Default::default()
                }],
            },
        );
        let m = Memory::from_update(&agentsc_proto::MemoryUpdate {
            version: "7".into(),
            agents,
        });
        assert_eq!(m.version_number(), 7);
        assert_eq!(m.agents["support"][0].text, "Look up the order first.");
        let back: Memory = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.sha256(), m.sha256());
    }
}
