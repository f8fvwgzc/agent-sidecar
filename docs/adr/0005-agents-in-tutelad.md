# 5. Agents are principals of tutelad, and embassy signs their own tokens

Status: implemented (#24)
Date: 2026-11-07

## Context

Tutela v0.2.0 ships `tutelad` with the admin API `tutela.admin.v1`. Tutela's integration plan
(INTEGRATION §3 steps 5 and 6, MIGRATION-0.2.md "when it bumps") asks attache to register each
agent there, disable it on quarantine, and later obtain delegated tokens in which the agent is the
actor (#25). Until now the registry minted `agent:agt_<uuidv7>` ids that only attache knew.

Four facts shaped the design:

- Tutela makes its own ids: `RegisterAgent` answers a new `agent:agt_<uuidv7>`; attache cannot
  bring its own.
- `RegisterAgent {workload}` binds one SPIFFE workload to one agent per tenant (a second is 409
  `exists`). attache runs several agents per service, and its workload is the service.
- `tutelad` can be down. The registry, quarantine and the sidecars must not depend on it.
- The actor of a delegated token is either a JWT-SVID of a `workloads` issuer (which stands for
  the one agent registered for that workload) or an access token of a trust-list issuer whose
  `sub` is the agent.

## Decision

1. **embassy is an app of tutelad** (Tutela ADR-0044), configured by an optional `tutela` section
   of the ControlPlaneConfig. It reads the app's credentials as `tutelad bootstrap` writes them
   (a mounted Secret or its JSON file), asks for its own `tutela-authz` token with
   `client_credentials` (HTTP Basic), keeps it until 30 s before it ends, and asks again after a
   401. The app's service account holds `org:manage_agents` at the org and nothing else (a role
   of the app manifest, not the seeded `owner`). Every call goes through `tutela-safenet`, as the
   OIDC client's do.
2. **The registry stays the system of record; tutelad follows it.** A reconciler (crate::tutela::
   sync) registers each active agent without a workload and keeps the principal tutelad made
   beside the registry id (SQL migration 9; one principal per agent, unique). An agent is enabled
   in tutelad while it is active and not quarantined, and disabled otherwise (`SetDisabled`), so
   a quarantine or a retirement stops its tokens and its exchanges, and a release or a
   reactivation enables it again with the raised epoch.
3. **Registration is retried, actions fail closed.** The reconciler runs at start, at once after a
   registry change, a quarantine or a release, in full every `tutela.sync_seconds` (it then asks
   tutelad for every registered agent's state and corrects drift), and in 5 s while a pass has
   failures, which it logs with their chain. A registry change or a quarantine never waits for
   tutelad; the sidecars refuse a quarantined agent whatever tutelad says. What needs tutelad's
   answer to be true fails closed: an agent token is signed only for an agent the registry holds
   active, not quarantined, registered and enabled; `POST /agents/{id}/revoke-tokens` answers 503
   `tutela_unavailable` when tutelad cannot be asked.
4. **embassy signs its agents' own tokens.** With `tutela.agent_tokens` it is a Tutela-format
   issuer: ES256 access tokens (`typ: at+jwt`, CONTRACTS.md 4.2) with `sub` the agent's tutelad
   principal, `aud` tutelad's audience, `tid` the app's tenant, `azp` the app's client id,
   `epoch` the agent's epoch as tutelad last answered, a 60 s life. Its JWKS is
   `/.well-known/agent-jwks.json`; tutelad's trust file lists the issuer for the tenant. These are
   the actor tokens of #25. The JWT-SVID route would name a workload, so it cannot tell two agents
   of one service apart.
5. **The four admin calls.** Register is `RegisterAgent`; pause (quarantine) and retire are
   `SetDisabled(true)`, which also raises the epoch; re-enable (release, reactivation) is
   `SetDisabled(false)`; and `RevokeSessions` is the admin action "revoke this agent's tokens",
   which raises the epoch and leaves the agent enabled.
6. **Two replicas, one new agent.** Each replica runs the reconciler. The store keeps the first
   principal registered for an agent (a conditional write); the replica that lost disables the
   principal it made, which holds nothing.

## Consequences

- A new agent cannot act for anyone until tutelad has registered it; after a quarantine, tutelad
  may hold it enabled until the next pass reaches it (seconds while tutelad is up).
- A principal made by a `RegisterAgent` whose answer was lost is left enabled and unmapped in
  tutelad: without a workload there is no way to find it again. It holds nothing, since nothing is
  assigned to it. Tutela has no idempotency key for `RegisterAgent` (f8fvwgzc/tutela#165).
- An operator gives tutelad's trust file embassy's issuer and JWKS, and keeps the agent key file
  as a secret; rotating it means publishing both keys for one JWKS cache period.
- `tutela` is optional: without it attache runs in library mode as before (INTEGRATION §1).

## Alternatives

- **Register with the workload.** One agent per service only; and the lost-answer recovery it
  offers (`ListAgents {workload}`) would not help the second agent of a service.
- **The embassy's JWT-SVID as the actor.** It needs the workload binding above.
- **The seeded `owner` role for the app.** It holds every admin key at the org; attache needs one.
- **Call tutelad inline from the quarantine handler.** A quarantine would then fail or wait when
  tutelad is down; the sidecars already enforce it.
- **Plain `reqwest` instead of `tutela-safenet`.** Its `ListAgents` needs a GET with a header,
  which safenet does not offer; the reconciler uses `GetPrincipal` (a POST) per agent instead, and
  keeps one outbound policy for every Tutela call.
