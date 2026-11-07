//! `tutelad`'s agents follow the registry (docs/adr/0005-agents-in-tutelad.md, #24).
//!
//! The registry is the system of record of agents (Tutela INTEGRATION §3 step 5). For each agent:
//!
//! - **Register.** An active agent with no principal in `tutelad` gets one: `RegisterAgent`, and
//!   the `agent:agt_<uuidv7>` `tutelad` made is kept beside the registry's own id.
//! - **Disable and enable.** An agent is enabled in `tutelad` while it is active and not
//!   quarantined, and disabled otherwise (a quarantine, a retirement): `SetDisabled`. Disabling
//!   raises its epoch, so the tokens it held stay refused after it is enabled again.
//! - A retired agent that was never registered is left out.
//!
//! **When.** At start; at once after a registry change, a quarantine or a release (only the agents
//! whose kept state is not what the registry wants); and every `tutela.sync_seconds` in full,
//! which also asks `tutelad` for each registered agent's state and corrects any drift (a race
//! between replicas, a change made at `tutelad` by hand, a lost answer).
//!
//! **Failures.** A failed call is logged with its whole chain, the pass goes on with the next
//! agent, and the next pass (in 5 s while there are failures) tries again. Nothing here is in the
//! way of a registry change or a quarantine: they take effect in attache at once, and `tutelad`
//! follows. Until it does, the agent stays as `tutelad` has it: never registered (it cannot act
//! for anyone), or still enabled after a quarantine (the sidecars refuse it anyway).
//!
//! **Replicas.** Each one runs this. Two replicas may register one new agent at the same time: the
//! store keeps the first principal, and the other replica disables the one it made, so it holds
//! nothing and can do nothing (`tutelad` has no way to delete an agent).
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use super::Connection;
use super::client::{self, PrincipalState};
use crate::hub::Hub;
use crate::secops::{AgentEntry, AgentFilter, AgentStatus, SecOpsStore, TutelaPrincipal};
use crate::store::StoreError;
use agentsc_common::error::chain;

/// How soon a pass with failures runs again.
pub const RETRY: Duration = Duration::from_secs(5);

/// Why one agent could not be synced.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("asking tutelad failed")]
    Tutela(#[from] client::Error),
    #[error("the registry store failed: {0}")]
    Store(StoreError),
}

impl From<StoreError> for SyncError {
    fn from(e: StoreError) -> Self {
        SyncError::Store(e)
    }
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Report {
    pub registered: u32,
    pub disabled: u32,
    pub enabled: u32,
    pub failed: u32,
}

enum Change {
    Registered,
    Disabled,
    Enabled,
}

/// The kept form of what `tutelad` answered.
pub fn kept(s: &PrincipalState) -> TutelaPrincipal {
    TutelaPrincipal {
        principal: s.principal.clone(),
        epoch: s.epoch,
        disabled: s.disabled,
        synced_at: crate::cp_audit::now_ts(),
    }
}

/// `true` when the registry wants agent `a` disabled in `tutelad`.
pub fn wants_disabled(a: &AgentEntry) -> bool {
    a.status != AgentStatus::Active || a.quarantine.is_some()
}

/// One pass over every agent of the registry (module docs). `full` asks `tutelad` for the state
/// of every registered agent too.
pub async fn pass(conn: &Connection, secops: &dyn SecOpsStore, full: bool) -> Report {
    let mut report = Report::default();
    let agents = match secops.list_agents(&AgentFilter::default()).await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "tutela: listing the registry failed; the sync runs again");
            report.failed = 1;
            return report;
        }
    };
    for a in &agents {
        match agent(conn, secops, a, full).await {
            Ok(None) => {}
            Ok(Some(Change::Registered)) => report.registered += 1,
            Ok(Some(Change::Disabled)) => report.disabled += 1,
            Ok(Some(Change::Enabled)) => report.enabled += 1,
            Err(e) => {
                report.failed += 1;
                tracing::warn!(
                    agent_id = %a.id,
                    principal = %a.principal,
                    error = %chain(&e),
                    "tutela: syncing the agent failed; the next pass tries again"
                );
            }
        }
    }
    report
}

/// Register `a` in `tutelad` and keep the principal, replacing `expected`. `None` when another
/// replica kept one first (the one made here is disabled).
async fn register(
    conn: &Connection,
    secops: &dyn SecOpsStore,
    a: &AgentEntry,
    expected: Option<&str>,
) -> Result<Option<TutelaPrincipal>, SyncError> {
    let made = conn.client.register_agent().await?;
    let state = kept(&made);
    if secops.put_tutela_principal(&a.id, expected, &state).await? {
        tracing::info!(
            agent_id = %a.id,
            tutela_principal = %made.principal,
            "tutela: registered the agent in tutelad"
        );
        return Ok(Some(state));
    }
    conn.client.set_disabled(&made.principal, true).await?;
    tracing::warn!(
        agent_id = %a.id,
        tutela_principal = %made.principal,
        "tutela: another replica registered the agent first; disabled the principal made here"
    );
    Ok(None)
}

async fn agent(
    conn: &Connection,
    secops: &dyn SecOpsStore,
    a: &AgentEntry,
    full: bool,
) -> Result<Option<Change>, SyncError> {
    let want_disabled = wants_disabled(a);
    let mut registered = false;
    let known = match &a.tutela {
        None if a.status != AgentStatus::Active => return Ok(None),
        None => match register(conn, secops, a, None).await? {
            Some(k) => {
                registered = true;
                k
            }
            None => return Ok(None),
        },
        Some(k) if full => match conn.client.principal_state(&k.principal).await {
            Ok(s) => {
                let now = kept(&s);
                if (now.epoch, now.disabled) != (k.epoch, k.disabled) {
                    secops.put_tutela_state(&a.id, &now).await?;
                }
                now
            }
            Err(e) if e.status() == Some(404) => {
                tracing::error!(
                    agent_id = %a.id,
                    tutela_principal = %k.principal,
                    "tutela: tutelad does not know the agent's principal (another tutelad or tenant?)"
                );
                if a.status != AgentStatus::Active {
                    return Ok(None);
                }
                match register(conn, secops, a, Some(&k.principal)).await? {
                    Some(k) => {
                        registered = true;
                        k
                    }
                    None => return Ok(None),
                }
            }
            Err(e) => return Err(e.into()),
        },
        Some(k) => k.clone(),
    };
    if known.disabled != want_disabled {
        let s = conn
            .client
            .set_disabled(&known.principal, want_disabled)
            .await?;
        secops.put_tutela_state(&a.id, &kept(&s)).await?;
        tracing::info!(
            agent_id = %a.id,
            tutela_principal = %known.principal,
            disabled = want_disabled,
            epoch = s.epoch,
            "tutela: set the agent's principal in tutelad"
        );
        return Ok(Some(if want_disabled {
            Change::Disabled
        } else {
            Change::Enabled
        }));
    }
    Ok(registered.then_some(Change::Registered))
}

/// Run passes until `shutdown`: at start, on every nudge, in full every `tutela.sync_seconds`,
/// and again in [`RETRY`] while a pass has failures.
pub async fn reconciler(hub: Arc<Hub>, shutdown: CancellationToken) {
    let mut last_full: Option<Instant> = None;
    loop {
        let conn = hub.tutela.connection();
        let every = Duration::from_secs(
            conn.as_ref()
                .map_or(60, |c| u64::from(c.config.sync_seconds)),
        );
        let mut wait = every;
        if let (Some(c), Some(secops)) = (&conn, hub.secops()) {
            let full = last_full.is_none_or(|t| t.elapsed() >= every);
            let report = pass(c, secops.as_ref(), full).await;
            if full {
                last_full = Some(Instant::now());
            }
            if report != Report::default() {
                tracing::info!(
                    registered = report.registered,
                    disabled = report.disabled,
                    enabled = report.enabled,
                    failed = report.failed,
                    full,
                    "tutela: synced the agents with tutelad"
                );
            }
            wait = if report.failed > 0 {
                RETRY
            } else {
                last_full.map_or(every, |t| every.saturating_sub(t.elapsed()))
            };
        }
        tokio::select! {
            () = hub.tutela.nudged() => {}
            () = tokio::time::sleep(wait) => {}
            () = shutdown.cancelled() => return,
        }
    }
}
