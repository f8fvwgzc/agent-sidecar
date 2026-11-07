//! Delegated agent tokens (#25, docs/adr/0006-delegated-agent-tokens.md; Tutela CONTRACTS.md
//! 4.5 and 4.8, ADR-0033).
//!
//! An app invokes an agent with a person's token addressed to attache (`tutela.delegation.
//! audience`). When a tool with `delegation` is called, the sidecar sends that token, the agent
//! and the tool's audience to embassy on its `Connect` stream (`DelegationRequest`), and embassy:
//!
//! 1. checks the request: the agent is one of the stream's service, active, not quarantined and
//!    registered and enabled in `tutelad`; the audience is in `tutela.delegation.audiences`;
//! 2. **verifies the person's token** with `tutela-sdk`: `tutelad`'s issuer for the app's tenant,
//!    attache's audience. A person's access token passes; a delegated token (an agent of another
//!    system acting for a person) passes only when attache's audience is `delegation_aware`, and
//!    then attache's agent becomes one more actor of its chain (at most 4, checked by both);
//! 3. builds the capability snapshot `cap` from the charter: the agent's tools and budgets;
//! 4. exchanges it at `tutelad` as attache's app: the person's token as the subject, an agent
//!    token embassy signs as the actor, the run and the tool as `run_id` and `node_id`, exactly one
//!    audience;
//! 5. answers the token (`DelegationResponse`) on that stream only.
//!
//! Anything that fails is refused with a reason, and the tool call with it (it fails closed): no
//! token, never the person's own. Neither token is logged; the log names the issued token's `jti`.
use std::sync::Arc;

use agentsc_proto::{ControlMessage, DelegationRequest, DelegationResponse, control_message};
use serde_json::json;
use tutela_sdk::Identity;

use super::client::{Exchange, Issued};
use crate::hub::Hub;
use crate::registry::Outbox;
use crate::secops::{AgentFilter, AgentStatus};
use crate::store::ServiceKey;
use agentsc_common::error::chain;

/// The largest capability snapshot Tutela takes, as JSON.
pub const MAX_CAP_BYTES: usize = 4096;
/// The largest token a sidecar may send.
pub const MAX_TOKEN_BYTES: usize = 8192;

/// Why no delegated token is issued: the rule the sidecar's refusal carries, and a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub rule: &'static str,
    pub reason: String,
}

/// `tutelad` cannot be asked, or this embassy does not delegate.
pub const RULE_UNAVAILABLE: &str = "delegation.unavailable";
/// The request is not one embassy may answer (agent, audience, the person's token).
pub const RULE_REFUSED: &str = "delegation.refused";

fn refused(reason: impl Into<String>) -> Refusal {
    Refusal {
        rule: RULE_REFUSED,
        reason: reason.into(),
    }
}

fn unavailable(reason: impl Into<String>) -> Refusal {
    Refusal {
        rule: RULE_UNAVAILABLE,
        reason: reason.into(),
    }
}

/// `tutela.delegation`'s verifier of the tokens apps send: `tutelad`'s issuer for the app's
/// tenant, attache's audience, delegated tokens only when that audience is `delegation_aware`.
pub fn verifier(
    config: &crate::config::TutelaConfig,
    creds: &super::Credentials,
) -> anyhow::Result<Option<Arc<tutela_sdk::Verifier>>> {
    use tutela_contracts::tenant::{Issuer, TenantId, TrustList};
    use tutela_sdk::{
        Alg, CacheRules, IssuerConfig, SafenetSource, SystemClock, Verifier, VerifierConfig,
    };
    let Some(d) = &config.delegation else {
        return Ok(None);
    };
    let iss: Issuer = creds.issuer.parse().map_err(|e| {
        anyhow::anyhow!(
            "the credentials' issuer: {}",
            agentsc_common::error::chain(&e)
        )
    })?;
    let tenant: TenantId = creds.tenant.parse().map_err(|e| {
        anyhow::anyhow!(
            "the credentials' tenant: {}",
            agentsc_common::error::chain(&e)
        )
    })?;
    let mut trust = if config.dev_loopback {
        TrustList::dev_mode()
    } else {
        TrustList::new()
    };
    trust
        .insert(iss.clone(), tenant)
        .map_err(|e| anyhow::anyhow!("the trust list: {}", agentsc_common::error::chain(&e)))?;
    let audience = d.audience.parse().map_err(|e| {
        anyhow::anyhow!(
            "tutela.delegation.audience: {}",
            agentsc_common::error::chain(&e)
        )
    })?;
    let mut policy = tutela_safenet::Policy::new();
    if config.dev_loopback {
        policy = policy.dev_loopback();
    }
    if config.private_host {
        let host = url::Url::parse(&creds.issuer)?
            .host_str()
            .map(str::to_string)
            .unwrap_or_default();
        policy = policy.allow_private_host(&host).map_err(|e| {
            anyhow::anyhow!("tutela.private_host: {}", agentsc_common::error::chain(&e))
        })?;
    }
    let source = SafenetSource::new(policy).map_err(|e| {
        anyhow::anyhow!(
            "build the JWKS client: {}",
            agentsc_common::error::chain(&e)
        )
    })?;
    let config = VerifierConfig {
        audience,
        trust,
        issuers: vec![IssuerConfig {
            jwks_uri: format!(
                "{}/.well-known/jwks.json",
                creds.issuer.trim_end_matches('/')
            ),
            iss,
            algs: vec![Alg::Es256],
            external: false,
            allow_typ_jwt: false,
        }],
        delegation: d.delegation_aware,
        delegation_aware: d.delegation_aware,
        denied_kids: std::collections::HashSet::new(),
        cache: CacheRules::default(),
    };
    Ok(Some(Arc::new(Verifier::with(
        config,
        Arc::new(source),
        Arc::new(SystemClock),
    ))))
}

/// The capability snapshot of `agent` of `key` (Tutela never reads it): its tools and budgets,
/// at most [`MAX_CAP_BYTES`]. A list of tools too long for it is replaced by its count and hash.
pub fn cap(key: &ServiceKey, agent: &agentsc_charter::AgentSpec) -> String {
    let tools: Vec<&str> = agent.tools.iter().map(|t| t.name.as_str()).collect();
    let base = |tools: serde_json::Value| {
        json!({"attache": {
            "service": format!("{}/{}", key.namespace, key.service),
            "agent": agent.name,
            "tools": tools,
            "budgets": {
                "max_steps": agent.budgets.max_steps,
                "max_calls_per_minute": agent.budgets.max_calls_per_minute,
                "max_tokens_per_call": agent.budgets.max_tokens_per_call,
            },
        }})
        .to_string()
    };
    let text = base(json!(tools));
    if text.len() <= MAX_CAP_BYTES {
        return text;
    }
    base(json!({
        "count": tools.len(),
        "sha256": agentsc_common::audit::sha256_hex(tools.join("\n").as_bytes()),
    }))
}

/// Answer `r`, a request of a sidecar of `key`, on its own stream (module docs).
pub fn on_request(hub: &Arc<Hub>, key: &ServiceKey, outbox: &Outbox, r: DelegationRequest) {
    let (hub, key, outbox) = (hub.clone(), key.clone(), outbox.clone());
    tokio::spawn(async move {
        let id = r.id.clone();
        let resp = match delegate(&hub, &key, &r).await {
            Ok(issued) => DelegationResponse {
                id,
                access_token: issued.access_token,
                expires_in: issued.expires_in,
                error: String::new(),
            },
            Err(f) => {
                tracing::info!(
                    service = %key,
                    agent = %r.agent,
                    audience = %r.audience,
                    rule = f.rule,
                    reason = %f.reason,
                    "tutela: no delegated token"
                );
                DelegationResponse {
                    id,
                    access_token: String::new(),
                    expires_in: 0,
                    error: format!("{}: {}", f.rule, f.reason),
                }
            }
        };
        crate::controlplane::send(
            &outbox,
            ControlMessage {
                msg: Some(control_message::Msg::DelegationResponse(resp)),
            },
        );
    });
}

/// A delegated token for `r`, asked by a sidecar of `key` (module docs).
pub async fn delegate(
    hub: &Hub,
    key: &ServiceKey,
    r: &DelegationRequest,
) -> Result<Issued, Refusal> {
    let conn = hub
        .tutela
        .connection()
        .ok_or_else(|| unavailable("this embassy has no tutela section"))?;
    let (Some(d), Some(verifier)) = (&conn.config.delegation, &conn.verifier) else {
        return Err(unavailable("this embassy has no tutela.delegation"));
    };
    if !d.audiences.iter().any(|a| a == &r.audience) {
        return Err(refused(format!(
            "audience {:?} is not in tutela.delegation.audiences",
            r.audience
        )));
    }
    if r.subject_token.is_empty() || r.subject_token.len() > MAX_TOKEN_BYTES {
        return Err(refused("the person's token is missing or too large"));
    }
    let secops = hub
        .secops()
        .ok_or_else(|| unavailable("this embassy keeps no agent registry"))?;
    let agent = secops
        .list_agents(&AgentFilter {
            namespace: Some(key.namespace.clone()),
            service: Some(key.service.clone()),
            status: Some(AgentStatus::Active),
        })
        .await
        .map_err(|e| unavailable(format!("the registry: {e}")))?
        .into_iter()
        .find(|a| a.name == r.agent)
        .ok_or_else(|| refused(format!("{} is not an active agent of {key}", r.agent)))?;

    // the person's token, as attache's audience takes it
    let person = verifier.verify(&r.subject_token).await.map_err(|e| {
        refused(format!(
            "the person's token is not valid for audience {}: {}",
            d.audience,
            e.step().as_str()
        ))
    })?;
    match &person {
        Identity::Access(c) if c.sub.kind() == tutela_contracts::principal::PrincipalKind::User => {
        }
        Identity::Delegated(_) => {}
        _ => return Err(refused("the subject is not a person's token")),
    }

    let stored = hub
        .store
        .get_charter(key)
        .await
        .map_err(|e| unavailable(format!("the charter: {e}")))?;
    let charter = crate::graph::parse_stored(&stored)
        .ok_or_else(|| unavailable("the stored charter does not parse"))?;
    let spec = charter
        .agent(&r.agent)
        .ok_or_else(|| refused(format!("the charter does not declare {}", r.agent)))?;
    let cap = cap(key, spec);
    let actor = super::agent_token(hub, &agent.id)
        .await
        .map_err(|e| refused(format!("no agent token: {e}")))?;
    let issued = conn
        .client
        .exchange(&Exchange {
            subject_token: &r.subject_token,
            audience: &r.audience,
            actor_token: Some(&actor),
            cap: Some(&cap),
            run_id: (!r.run_id.is_empty()).then_some(r.run_id.as_str()),
            node_id: (!r.node_id.is_empty()).then_some(r.node_id.as_str()),
        })
        .await
        .map_err(|e| {
            if e.is_unavailable() {
                unavailable(chain(&e))
            } else {
                refused(chain(&e))
            }
        })?;
    tracing::info!(
        service = %key,
        agent = %r.agent,
        audience = %r.audience,
        jti = %jti(&issued.access_token),
        "tutela: issued a delegated token"
    );
    Ok(issued)
}

/// A token's `jti`, to name it in a log (never the token).
fn jti(token: &str) -> String {
    use base64::Engine as _;
    token
        .split('.')
        .nth(1)
        .and_then(|p| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(p)
                .ok()
        })
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["jti"].as_str().map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_snapshot_fits_tutelas_limit() {
        let mut c = agentsc_charter::Charter::from_yaml(
            "apiVersion: agentsc.io/v1alpha1\nkind: Charter\nservice: {name: a, namespace: b, app_port: 1}\nagents: [{name: x, model: mock}]\n",
        )
        .unwrap();
        let key = ServiceKey::new("b", "a");
        let small = cap(&key, &c.agents[0]);
        let v: serde_json::Value = serde_json::from_str(&small).unwrap();
        assert_eq!(v["attache"]["agent"], "x");
        assert_eq!(v["attache"]["service"], "b/a");
        let tool = c.agents[0].clone();
        let mut many = tool;
        for i in 0..300 {
            many.tools.push(agentsc_charter::ToolSpec {
                name: format!("a_rather_long_tool_name_number_{i}"),
                description: "d".into(),
                tool_type: agentsc_charter::ToolType::Http,
                parameters: None,
                service: None,
                method: Some("GET".into()),
                path: None,
                agent: None,
                url: Some("https://example.test/x".into()),
                label: None,
                effect: None,
                approval: None,
                delegation: None,
            });
        }
        c.agents[0] = many;
        let big = cap(&key, &c.agents[0]);
        assert!(big.len() <= MAX_CAP_BYTES, "{}", big.len());
        let v: serde_json::Value = serde_json::from_str(&big).unwrap();
        assert_eq!(v["attache"]["tools"]["count"], 300);
    }
}
