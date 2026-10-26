# The AgentSecOps merge: nexc-engine's AgentSecOps into attache

_Design. Written 2026-10-26 against attache `main` at `94a6bfb` and nexc-engine `main` at
`9e5adb9` (its `docs/PRODUCT-MIGRATION.md`, which this document follows). The inventory of
nexc-engine is read-only: this document moves no nexc code. Step 1 (§6) ships with it._

nexc-engine becomes a product (issues, projects, cycles, boards) built on four cores. attache is
the AgentSecOps core. Every model call, tool call and policy decision of an agent goes through
trusted attache code: the agent registry, capabilities and policies, the firewall, approvals,
risk and quarantine, DLP, the evidence ledger, the agent runtime, the tool gateway (MCP,
`fetch_url`), A2A, and the model gateway (PRODUCT-MIGRATION.md §1).

This document says:

- what attache already has (§2);
- what each AgentSecOps module of nexc-engine does, and where it lands in attache (§3);
- the architecture they land in (§4);
- how their data moves (§5);
- the order of the work (§6), whose step 1 is the embassy PostgreSQL store (§7).

## 1. Rules

They are nexc-engine's (PRODUCT-MIGRATION.md §2), seen from the receiving side:

1. **attache first.** A capability lands in attache in attache's own PRs, with its tests, before
   nexc switches to it. attache never imports nexc code wholesale: each module is rebuilt on
   attache's model (charters, the sidecar's authorization order, audit records), and the
   behaviour nexc's tests pin is ported as attache tests.
2. **Shadow, flip, remove.** Every decision attache takes over (a firewall decision, a DLP
   verdict, a risk score) first runs beside nexc's, answering the same input with the rule ids it
   used. A mismatch is logged and counted (nexc's `policy_mismatches` counter is reused). Only then
   does attache decide.
3. **Data moves by export and import**, verified by row counts and digests. Evidence moves byte
   for byte, so every seal and bundle made before the move still verifies.
4. **The enforcement point stays in the request path.** An agent's calls go through `agentscd`
   (or the standalone gateway), which needs no network round trip to decide the common case: the
   control plane (embassy) pushes what it decides (charters, policies, quarantines) and receives
   what happened (audit records), as today.
5. **One store for the control plane in production.** What embassy keeps for many replicas
   (registry, policies, approvals, the ledger) lives in PostgreSQL (§7). SQLite and the file store
   stay for development; the Kubernetes store keeps charters as CRs.

## 2. What attache has today

| Capability | Where | State |
| --- | --- | --- |
| Agents, their tools and limits | the charter (`agentsc-charter`), one per service, versioned in embassy's store | shipped |
| Authorization of tool, peer and agent calls | `agentscd` (CONTRACT.md §5: the authz order; taint-aware policy, `authz.taint`) | shipped |
| Workload identity, mTLS between sidecars | embassy-ca (SPIFFE IDs, issuance checks), the mesh | shipped |
| Model gateway: keys, run binding, budgets, one price table | `agentscd` gateway (CONTRACT.md §4.4) | shipped |
| Standalone model gateway, LLM connection contract v1 | `agentsc-gateway`, docs/LLM-CONNECTION.md | open PR (#18) |
| Guardrails | charter `guardrails` (`input_deny`, `output_deny`, `pii_redact`) | shipped, regex-based |
| Audit | `agentscd` audit records (CONTRACT.md §6: payload hashes, redaction, durable sink, fail-closed), control-plane audit in every store | shipped; no hash chain |
| Traces | OpenTelemetry export of audit records (`agentsc-otel`), embassy's trace views | shipped |
| Learning, memory | proposals, approvals of lessons, memory per agent | shipped |
| Control plane | embassy: REST API, SSE, console, Connect streams to sidecars, admission webhooks, the sidecar integrity policy | shipped |
| Stores | `file:`, `sqlite:`, `kubernetes` | shipped; single replica only for file and SQLite |

What attache does not have yet: agents as principals of their own (an agent is a name inside a
service's charter), human approvals of tool calls, risk scores and quarantine, DLP beyond regexes,
injection screening, a hash-chained and signed evidence ledger, MCP and A2A, alert routing, and a
store for many embassy replicas.

## 3. Inventory: nexc-engine's AgentSecOps modules

Sizes are of nexc-engine `main` at `9e5adb9`. "Today" says how much of it attache already
covers: **=** equivalent, **~** partial, **–** nothing yet.

### 3.1 `backend/src/`

| nexc module | Size | What it does | Today | Lands in attache |
| --- | ---: | --- | :---: | --- |
| `firewall/` (`mod`, `live`, `approvals`) | 87 KiB | The Agent Firewall API (`nexc.firewall.v1` gRPC): live decisions on tool, host, model, spawn and read; approvals over gRPC | ~ | Decisions: `agentscd`'s authz order, extended with nexc's decision kinds (host, spawn, read) as charter rules. The API: embassy's **decisions API** (for shadow mode, and for runtimes outside a sidecar), the same evaluator as `agentscd`. Approvals: §3.1 `approvals` |
| `engine/policy.rs`, `domain/policy.rs`, `domain/policy_document.rs`, `domain/capabilities.rs` | 109 KiB | Policy resolution: capabilities, versioned policy documents, their merge per agent | ~ | Charter `authz` and `ControlPlaneConfig` policy today. Policy documents become **versioned policies** in embassy's store, referenced by charters; a span records the policy version it was decided under (kept on import) |
| `engine/approvals.rs` | 24 KiB | Human approvals of tool calls: request, decide, expire | – | embassy **approvals** (store tables, API, SSE, console page); `agentscd` holds the call until decided or expired (a new authz outcome, `approval.pending`) |
| `engine/risk.rs`, `domain/risk.rs`, baselines | 43 KiB | Risk scoring of agents and sessions against baselines; quarantine | – | embassy **risk**: scores from audit records, baselines per agent; quarantine is a pushed charter overlay that denies the agent (no new enforcement path) |
| `engine/defend.rs`, `domain/dlp.rs`, `domain/injection.rs` | 49 KiB | DLP (classifiers, redaction) and prompt-injection screening | ~ | `agentscd` **guardrails**: today regexes and `pii_redact`; nexc's DLP classifiers and injection screens become guardrail kinds, applied where they are today (input, output, tool results), with the taint policy for what screened content may reach |
| `engine/evidence.rs`, `domain/evidence.rs`, `domain/bundle.rs`, `domain/seal.rs`, `domain/audit_chain.rs`, `security/signing.rs`, `bin/nexc_verify.rs` | 105 KiB | The evidence ledger: hash-chained spans and audit, signed run seals, exportable bundles, an offline verifier | ~ | embassy **ledger**: audit records reach embassy (today stdout and OTel only), are chained per stream, sealed with keys from Tutela's vault (`kid` published in a JWKS), exported as bundles; `agentsc verify` replaces `nexc-verify` and verifies imported nexc bundles too |
| `engine/trace.rs`, `engine/recording.rs` | 12 KiB | The trace spine and tool-call recording | = | attache's audit records and spans (CONTRACT.md §6); nexc spans are imported into the ledger |
| `otlp/` | 15 KiB | OTLP export of the agent trace | = | `agentsc-otel`; the exporter starts after the imported trace's end |
| `gateway/` (`mod`, `fetch`, `mcp`, `a2a`) | 60 KiB | The tools gateway: `fetch_url`, MCP over HTTP, A2A as a tool | ~ | `agentscd` **tool gateway**: `fetch_url` is an http tool under the charter's egress rules (today); MCP servers become charter tools of kind `mcp` (HTTP transport only: nexc already refuses stdio servers); A2A below |
| `a2a/` (`card`, `client`, `inbound`) | 56 KiB | Agent-to-agent: the card, outbound tasks, the inbound endpoint | ~ | `agentscd` **A2A edge**: attache agents already call each other over the mesh (`InvokeAgent`, SPIFFE identities); A2A cards and tasks are an adapter at the edge for counterparts outside the mesh, under the same authz |
| `alerting/` | 36 KiB | Routing security alerts to webhooks and Slack | – | embassy **alerting**: rules over audit and decision records, destinations re-sealed on import |
| `egress_proxy.rs` | 36 KiB | `nexc egress-proxy`: the runtime's only way out | = | `agentscd` already mediates every tool, peer and model call; the runtime has no network of its own. A CONNECT proxy is added only if a merged tool needs raw egress |
| `rpc.rs` (`nexc.runtime.v1`, `nexc.firewall.v1`) | — | The runtime and firewall protocols | ~ | `runtime.proto` (Execute, ToolHost) and the decisions API; nexc's protocols are mapped, not kept |
| `llm/` (`anthropic`, `openai_compat`, `router`, `breaker`, `pricing`, `catalog`) | 48 KiB | Providers, routing, the circuit breaker, prices, the model catalog | = | the model gateway (sidecar and standalone, one price table, budgets). The router's fallback is the charter's `harness.fallback_model`; a breaker per provider is a follow-up of the gateway |
| `engine/guardrails.rs`, `engine/usage.rs` | 2 KiB | Workspace guardrails (budgets) and the usage ledger | = | charter budgets enforced by the model gateway; usage reported from `model_call` records |
| `ontology/facts.rs` | — | Trace → facts ("ask the audit") | – | embassy feeds onto-intelli from the ledger (later) |

### 3.2 `agent-runtime/` (Python)

| Part | Size | What it does | Lands in attache |
| --- | ---: | --- | --- |
| `src/nexc_runtime` (agents, runner, `policy.py`, approvals, injection, evidence, tools `files`, `python_exec`, `docx`, `workspace`, the gateway tool, providers, gRPC and HTTP servers) | 286 KiB | nexc's agent runtime | attache's runtime (`runtime/`, `agentsc_runtime`): nexc's agents become charters, their tools charter tools served by the runtime's ToolHost; `python_exec` needs a sandbox decision first (§8). The runtime keeps no key and no policy of its own: both are `agentscd`'s |
| `parsing/` | — | Document parsing | **not attache**: onto-intelli (PRODUCT-MIGRATION.md §4) |
| `tests/` | 173 KiB | Its tests | ported with the code they test, as attache tests |

### 3.3 API, tables and console

| nexc | Lands in attache |
| --- | --- |
| Handlers `agents`, `agent_templates`, `policies`, `approvals`, `alerts`, `alert_destinations`, `secops`, `evidence`, `trace`, `payloads`, `exports` (SIEM pulls), `mcp_servers`, `a2a`, `a2a_counterparts` | embassy's REST API (`/api/v1/...`, OpenAPI in `docs/api/openapi.yaml`), with its roles and namespace scoping |
| Tables `agents`, `agent_evaluations`, `baselines`, `approvals`, `alerts`, `alert_destinations`, `alert_deliveries`, `a2a`, `mcp_servers`, `policies`, `secops`, `evidence`, `spans`, `span_payloads`, `external_runs`, `otlp_export`, `audit` (the chain), `usage` | embassy's PostgreSQL schema, one migration per step (§6) |
| Console `features/agents`, `secops`, `policies`, `alerting`, `a2a`, `gateway`, `audit`, the trace views | embassy's console (`ui/`), or components the product embeds |

## 4. Target architecture

```
           product (nexc-engine), texc-symphony, onto-intelli, users
                         │ REST / SSE (Tutela tokens)
                         ▼
   ┌──────────────────────────── embassy (control plane) ───────────────────────────┐
   │ registry · policies · decisions API · approvals · risk/quarantine · alerting    │
   │ evidence ledger (chain, seals, bundles) · usage · charters · memory · CA        │
   │                         PostgreSQL (many replicas)                              │
   └───────────────┬──────────────────────────────────────────────▲─────────────────┘
       charters, policies, quarantines (Connect streams)  audit records, decisions
                   ▼                                              │
   ┌──────────── agentscd (in every agent pod) ───────────────────┴──┐   agentsc-gateway
   │ authz order · guardrails (DLP, injection) · approvals hold      │   (model calls from
   │ tool gateway (http, MCP) · A2A edge · model gateway · mesh mTLS │    outside a pod)
   └───────────────┬────────────────────────────────────────────────┘
                   │ unix sockets
                agent runtime (untrusted: no keys, no egress, no policy)
```

- **Decisions stay local.** `agentscd` evaluates every call against what embassy pushed. The
  decisions API in embassy runs the same evaluator (one crate) for shadow mode and for callers
  outside a pod. It is never on the hot path of a sidecar.
- **Everything that happened flows back.** Today audit records go to stdout and OTel. For the
  ledger, sidecars also send them over their Connect stream (the outbox already sends batches,
  CONTRACT.md §6), and embassy chains and stores them.
- **Principals.** An agent becomes a principal of its own, `agent:agt_<uuidv7>` (Tutela),
  mapped to `(namespace, service, agent)` in the registry. nexc's `agent://<workspace>/<name>` is
  kept as an alias, so old traces resolve.

## 5. Data migration

PRODUCT-MIGRATION.md §7.2 lists what moves. In attache it lands as follows, each with a
PostgreSQL migration of its own:

| nexc tables | attache |
| --- | --- |
| `agents`, `agent_evaluations`, `agent_baselines`, `agent_session_baselines`, `agent_risk_history` | registry and risk tables; baselines copied, so scoring does not restart cold |
| `policies` (with versions) | policy tables, version numbers kept |
| `approvals` | open ones drained in nexc first; decided ones imported read-only |
| `alerts`, `alert_destinations`, `alert_deliveries` | alerting tables; destination URLs re-sealed |
| `agent_spans`, `span_payloads`, `audit_log`, `audit_chain_heads` | the ledger, byte for byte (hashes, seals, `kid`); nexc's public keys published as retired keys. Test: `nexc-verify` and `agentsc verify` agree on the same bundles |
| `mcp_servers`, `a2a_counterparts`, `a2a_tasks` | charter tools and A2A counterparts; auth headers re-sealed |
| `workspace_guardrails`, `llm_usage` | charter budgets; usage history imported for reporting |

Imports are idempotent and resumable, verified by row counts and content digests, and run
against a read-only source.

## 6. Order of the work

| Step | What | Needs | Done when |
| --- | --- | --- | --- |
| **1** | **embassy PostgreSQL store** (§7): today's `Store` on PostgreSQL, migrations on start, many replicas | — | `--store postgres` passes the same tests as SQLite, plus the replica tests; CI runs them against PostgreSQL |
| 2 | **Ledger**: audit records from sidecars into PostgreSQL, hash chain per stream, seals, bundles, `agentsc verify` | step 1; signing keys in Tutela's vault (or a key file until then) | a bundle verifies offline; a tampered record fails; nexc's bundles verify after import |
| 3 | **Registry and policies**: agents as principals, versioned policies, the decisions API | step 1; Tutela phase B for principals | shadow decisions against nexc's firewall match for 1–2 weeks |
| 4 | **Approvals, risk and quarantine, alerting** | steps 2–3 | nexc's approval and risk tests pass as ported attache tests; shadow risk scores agree |
| 5 | **Tool gateway and A2A**: MCP over HTTP, `fetch_url`, A2A edge | step 3 | nexc's gateway tests ported; no stdio MCP |
| 6 | **Runtime**: nexc's agents and tools on attache's runtime; nexc's runtime retired but `parsing/` | steps 3–5; a `python_exec` sandbox decision | new runs start on attache; nexc's in-flight runs finish |
| 7 | **Data import and cut-over** (§5), then nexc removes its copies | 2–6 | the import verifies; nexc's flip and remove stages done |

Each step ships its tests and docs, and every decision it takes over goes through shadow first.

## 7. Step 1: the embassy PostgreSQL store

`embassy serve --store postgres` keeps everything the SQLite store keeps, in PostgreSQL, for one
or many embassy replicas.

- **Connection.** The connection string (`postgres://user:password@host:5432/db?sslmode=require`)
  comes from `--postgres-url-file` (a mounted Secret) or env `AGENTSC_POSTGRES_URL`, never a flag
  value (it holds a password, and argv is visible to every process on the host).
  `sslmode=require` uses TLS verified against the system roots, or only against
  `--postgres-ca-file`'s certificates when given (a private CA, a cloud provider's bundle). `--postgres-pool-size` bounds the
  connections per replica.
- **Schema and migrations.** The same tables as SQLite (docs/adr/0003-sqlite-store-schema.md),
  in PostgreSQL types, with the same invariants as triggers: counters never go down, a stored
  version is exactly the next one and immutable, a decided proposal stays decided, the
  control-plane audit is append-only. Plus `pending_adoptions`, which the single-process stores
  keep in memory and many replicas must share. Migrations are numbered, applied on start in one
  transaction each, under a PostgreSQL advisory lock, so replicas starting together apply each
  once. A database migrated by a newer embassy is refused. The applied migrations are listed in
  `agentsc_schema_migrations`.
- **Many replicas.** Every write is one transaction that locks its service's row first
  (`SELECT ... FOR UPDATE`), then checks its precondition. So two replicas writing the same service
  serialize, and the loser gets the usual `409` conflict. Each replica tells the others what
  changed with `NOTIFY`. Each replica listens on a connection of its own and turns their
  notifications into the store events its Connect streams and SSE clients follow. A replica whose
  listen connection broke reconnects and then emits every service's charter and memory again, so
  nothing a notification carried while it was away is lost.
- **Dev and the other stores.** SQLite stays the store for one process and development; the file
  store stays for GitOps-style directories; the Kubernetes store keeps charters as CRs.

What step 1 does not do: store anything the other stores do not (the ledger, the registry and
the rest come in their own steps and migrations), or run embassy's components in separate
processes against one database. That works, but is not tested here beyond two replicas of the
whole set.

## 8. Open questions

- **Principals.** `agent:agt_<uuidv7>` from Tutela versus attache's SPIFFE IDs
  (`spiffe://<trust>/ns/<ns>/svc/<svc>`) plus the agent name: the registry maps both, but which
  one a decision record names first is to settle with Tutela.
- **Policies versus charters.** Merge nexc's policy documents into the charter schema, or keep
  them as separate versioned objects that charters reference (this document assumes the second,
  because nexc's spans record a policy version).
- **`python_exec`.** Run arbitrary code only in a sandbox attache controls (gVisor, Firecracker,
  or a separate pod with no credentials), or drop it.
- **Signing keys** for seals: Tutela's vault, or a KMS until it ships.
- **Tenancy.** embassy scopes by Kubernetes namespace; nexc by workspace. A workspace maps to a
  Tutela org; whether an org spans namespaces is open.
