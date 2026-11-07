# 6. Delegated agent tokens: embassy exchanges, the sidecar carries

Status: implemented (#25)
Date: 2026-11-07

## Context

Tutela v0.2.0's `tutelad` issues delegated agent tokens by RFC 8693 token exchange (CONTRACTS.md
4.5, 4.8, ADR-0033): `typ: agent+jwt`, `sub` the person, `act` the chain of agents (at most 4),
`cap` (attache's capability snapshot, opaque to Tutela), `run_id`, `node_id`, one audience that
Tutela marks `delegation_aware`, 60 to 120 s. A service that receives one never forwards it; it
exchanges it for the next audience. ADR 0005 made attache's agents principals of `tutelad` and
gave embassy an issuer for their own tokens, the actor of an exchange.

What attache had to decide: who holds the person's token, who asks `tutelad`, where tokens are
checked, and which calls carry the result.

## Decision

1. **The app sends the person's token with the invocation** (`X-Agentsc-Subject-Token`, gRPC
   metadata `x-agentsc-subject-token`), addressed to attache's own audience. The sidecar keeps it
   in memory for that run only and never gives it to the runtime, a record or a log. A token
   another app exchanged (its `azp`) cannot be exchanged by attache's app; Tutela enforces that.
2. **embassy exchanges; the sidecar never talks to `tutelad`.** The app credentials and the actor
   key stay in the control plane. The sidecar asks on its mTLS `Connect` stream
   (`DelegationRequest`), and embassy answers that stream only (`DelegationResponse`), so the
   service a request comes from is the certificate's, and a sidecar gets tokens for its own
   agents only.
3. **embassy checks the person's token before it asks.** `tutela-sdk` verifies it against
   `tutelad`'s issuer, the app's tenant and attache's audience. A delegated token (another system's
   agent acting for a person) passes only when attache's audience is configured
   `delegation_aware`, as in `tutelad`'s trust file; attache's agent then becomes one more actor.
   The agent must be active, unquarantined, registered and enabled (ADR 0005), and the audience in
   an operator's allow-list (`tutela.delegation.audiences`), so a charter author cannot point an
   agent at an audience the operator has not approved. `tutelad` checks again (epochs, disabled
   principals, expiry, the chain limit, `delegation_aware`), so a revocation attache has not heard
   of still stops the exchange.
4. **`http` tools carry it, declared in the charter.** `tools[].delegation.audience` (schema
   level 8, admin-only under `edit_authz`): the sidecar sends the token as `Authorization:
   Bearer`, in place of anything the model wrote, and keeps it for the run until 10 s before it
   ends. `service` and `agent` tools stay inside the mesh, where mTLS and the charters decide.
5. **`cap`** is `{"attache": {service, agent, tools, budgets}}` from the stored charter, at most
   4096 bytes (a long tool list becomes its count and hash). A downstream service that knows
   attache can narrow by it; Tutela never reads it.
6. **It fails closed.** No person's token, a refusal, or no answer in 10 s: the call is denied
   (`delegation.no_subject`, `delegation.refused`, `delegation.unavailable`) and never sent
   without the token, nor with the person's own.

## Consequences

- An app that wants delegated calls must obtain a token for audience `attache` for its user
  without naming another app as `azp` (a public client, or attache's own app).
- Revocation reaches a call within its token's life at worst (at most 120 s plus Tutela's skew);
  a new call needs a new exchange, which `tutelad` refuses at once. attache does not listen to
  Tutela's events yet, so its own check of the person's token cannot see a raised epoch.
- Every hop through embassy adds a `tutelad` round trip; the per-run cache keeps it to one per
  (run, agent, audience).
- No `cnf` binding yet (Tutela leaves it open): a stolen delegated token works for its life.

## Alternatives

- **The sidecar exchanges itself.** Every sidecar would hold the app's client secret and the actor
  key, and could speak for any agent.
- **Forward the person's token.** Tutela forbids it, and the downstream would see the person, not
  the agent acting for them.
- **A unary RPC for the exchange.** The `Connect` stream already carries the sidecar's verified
  identity and reconnect logic; approvals use it the same way.
- **Delegation on `service` tools.** Inside the mesh the callee's charter decides from mTLS
  identities; a person's authority there is a later step, if a callee asks for it.
