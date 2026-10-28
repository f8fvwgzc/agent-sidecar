# Approvals of tool calls

Status: implemented (#35). Contract: [CONTRACT.md](../../CONTRACT.md) §5.4. Part of the
AgentSecOps merge ([agentsecops-merge.md](agentsecops-merge.md) §3.1 `engine/approvals.rs`).

## Decisions

1. **The charter says which tools need a person**, as `tools[].approval` (schema level 7), next
   to the tool's other rules. nexc-engine keeps a `require_approval` list in a policy document;
   attache's tool rules live on the tool. Changing it needs admin, and dropping one weakens.
2. **The sidecar holds the call, not the runtime.** The runtime is untrusted and holds no policy.
   The wait happens after every other check (authz, guardrails, taint, quarantine), so a person
   is asked only about a call that would otherwise run.
3. **The request travels on the Connect stream**, like lesson proposals, and the decision comes
   back on it. Decisions go to every instance of the service, and each ignores ids it does not
   wait on, so a decision taken on any replica reaches the sidecar wherever it is connected.
   Requests are sent again after a reconnect, and embassy treats one it has as the same one.
4. **nexc-engine's rules:** decided once; a deny needs a reason; default 600 s, at most 86400;
   an approval after expiry counts as expired; at most 16 pending per agent; a quarantine expires
   the agent's pending approvals; a denial is a tool error the model sees, and the run goes on.
5. **Who decides:** an editor of the namespace, the role that may change the agent's charter
   and approve its lessons. nexc-engine's named approvers wait for Tutela's permission model
   (`tutela-pdp`), which will replace attache's roles.
6. **Never the arguments.** An approval holds the SHA-256 of the call's arguments, so the
   approvals table never becomes a second copy of what the audit redacts.

## What it does not do yet

- A console page and an SSE event for pending approvals (#39): today they are read with
  `GET /api/v1/approvals?status=pending`.
- Named approvers per tool (with Tutela's permission model).
