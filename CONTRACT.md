# CONTRACT.md — the source of truth

Everything that has to fit together across the sidecar, the agent runtime, the
control plane, the CLI and the Kubernetes manifests is defined here. When code
and this file disagree, this file wins and the code is wrong. Keep it updated
in the same change.

## 0. Names (placeholders, one find/replace away)

| Thing                       | Name            | Where                                   |
| --------------------------- | --------------- | --------------------------------------- |
| Product                     | **attache**     | repo, docs                              |
| Sidecar daemon binary       | `attached`      | `services/attached`                     |
| CLI                         | `attache`       | `services/attache-cli`                  |
| Control plane / CA          | `embassy`       | `services/embassy`                      |
| Agent + policy spec file    | `charter.yaml`  | `examples/charters/*.charter.yaml`      |
| Kubernetes API group        | `attache.io/v1alpha1` | `apiVersion` in charters, labels  |
| Agent runtime (Python)      | `attache-runtime` | `runtime/`                            |
| Discipline                  | AgentSecOps     | README                                  |

## 1. What attache is

**The agent is a sidecar of the service, not a service of its own.**

```
                       pod: orders                                      pod: inventory
 ┌────────────────────────────────────────────────┐        ┌────────────────────────────────────────┐
 │  app container (Go, no SDK)                    │        │  app container (FastAPI, no SDK)       │
 │   POST localhost:3500/v1/agents/ops-assistant  │        │   GET /stock      POST /admin/reset    │
 │             │                                  │        │        ▲                 ▲ (denied)    │
 │  ───────────┼──────────────────────────────    │        │  ──────┼─────────────────┼──────────── │
 │  attached (sidecar)  ◀── charter.yaml (CM)     │  mTLS  │  attached (sidecar) ◀── charter.yaml   │
 │   HTTP 3500 · gRPC 50001 · mesh 50002 ─────────┼────────┼─▶ mesh 50002  authz(SAN + agent)       │
 │   guardrails · budgets · authz · audit JSONL   │        │   guardrails · budgets · authz · audit │
 │        │ unix socket                           │        │        │ unix socket                   │
 │   attache-runtime (python) ── Claude / mock    │        │   attache-runtime (python)             │
 │     ops-assistant (orchestrator)               │        │     stock-analyst (agent)              │
 └────────────────────────────────────────────────┘        └────────────────────────────────────────┘
                 ▲ certs: Secret attache-cert-orders           ▲ certs: Secret attache-cert-inventory
                 └──────────────── embassy (CA, Job) ──────────┘  spiffe://attache/ns/<ns>/svc/<svc>
```

Principles every component honours:

1. **Zero SDK.** The app talks plain HTTP (or gRPC) to `localhost`. Any language.
2. **Everything an agent does goes through the sidecar** and is audited:
   agent invocations, model calls, tool calls, service calls, HTTP calls,
   authz decisions, guardrail decisions, budget decisions. One JSONL line each.
3. **Policy is data.** Agents, tools, budgets, guardrails, authz and audit
   live in `charter.yaml`. The sidecar validates it on load and refuses unknown
   fields. A UI will generate it later; the schema is the API.
4. **Identity is the certificate.** Every pod has an mTLS identity
   `spiffe://attache/ns/<namespace>/svc/<service>`. The callee sidecar decides
   using the caller's certificate SAN plus the calling agent name, never a
   header alone.
5. **Default deny** for authz once a charter exists. Explicit `allow` rules
   are the only way an identity reaches an agent or an agent reaches a path.

## 2. Components and ports

| Component            | Listens on                               | Who calls it                      | Protocol        |
| -------------------- | ---------------------------------------- | --------------------------------- | --------------- |
| `attached` app HTTP  | `127.0.0.1:3500`                         | the app container                 | HTTP/1.1 JSON   |
| `attached` app gRPC  | `127.0.0.1:50001`                        | the app container                 | gRPC plaintext  |
| `attached` mesh      | `0.0.0.0:50002` (pod IP, via Service)    | other pods' sidecars              | gRPC **mTLS**   |
| `attached` tools     | `unix:/run/attache/sidecar.sock`         | the local agent runtime           | gRPC            |
| `attache-runtime`    | `unix:/run/attache/runtime.sock`         | the local sidecar                 | gRPC            |
| `embassy`            | none (Job) — see §7                      | —                                 | Kubernetes API  |

Peer discovery: the mesh address of service `S` in namespace `N` is
`S.N.svc.cluster.local:50002` unless `mesh.peers.S` in the charter overrides
it. Every demo Service therefore exposes port `50002` (`mesh`) next to the
app port.

Flags / environment of `attached` (flag wins over env):

| Flag              | Env                      | Default                           |
| ----------------- | ------------------------ | --------------------------------- |
| `--charter`       | `ATTACHE_CHARTER`        | `/etc/attache/charter/charter.yaml` |
| `--tls-dir`       | `ATTACHE_TLS_DIR`        | `/etc/attache/tls` (`ca.crt`, `tls.crt`, `tls.key`) |
| `--http-addr`     | `ATTACHE_HTTP_ADDR`      | `127.0.0.1:3500`                  |
| `--grpc-addr`     | `ATTACHE_GRPC_ADDR`      | `127.0.0.1:50001`                 |
| `--mesh-addr`     | `ATTACHE_MESH_ADDR`      | `0.0.0.0:50002`                   |
| `--socket-dir`    | `ATTACHE_SOCKET_DIR`     | `/run/attache`                    |
| `--runtime-cmd`   | `ATTACHE_RUNTIME_CMD`    | `attache-runtime` (shell words; `--listen` and `--sidecar` are appended) |
| `--no-runtime`    | `ATTACHE_NO_RUNTIME`     | off. `1/true/yes/on` = do not spawn the runtime; something else serves `runtime.sock`, and readiness still follows its `Health` |
| —                 | `ANTHROPIC_API_KEY`      | unset → the runtime uses the `mock` model for every agent |

## 3. `charter.yaml`

Top-level keys are exactly these; unknown keys anywhere are a validation
error (`attache charter validate` exits 1 and names the path). JSON Schema:
`schemas/charter.schema.json`, generated from the Rust types by
`attache charter schema`; a test keeps the file in sync.

```yaml
apiVersion: attache.io/v1alpha1
kind: Charter
service:
  name: orders                 # DNS-1123 label
  namespace: attache-demo      # DNS-1123 label
  app_port: 8080               # where the app container listens on localhost
mesh:                          # optional
  port: 50002
  peers: {}                    # service name → host:port override
agents:
  - name: ops-assistant        # unique, DNS-1123 label
    type: orchestrator         # agent | orchestrator (orchestrator = may use `agent` tools)
    model: claude-opus-5-5     # any Claude model id, or `mock`
    system: "..."              # system prompt
    tools: []                  # see below
    budgets:
      max_tokens_per_call: 2048      # max_tokens for each model call, 1..=128000 (thinking counts against it)
      max_calls_per_minute: 30       # inbound invocations of this agent, sliding window
      max_cost_usd_per_day: 5.0      # sum of model_call cost_usd per UTC day
      max_steps: 6                   # model-call iterations per invocation
guardrails:
  max_input_bytes: 16384
  pii_redact: true             # redact emails and phone numbers in agent output (response + audit)
  input_deny:                  # regex (Rust `regex` syntax) applied to the raw input; deny on match
    - { name: no-secrets, regex: "(?i)(api[_-]?key|password)\\s*[:=]" }
  output_deny: []              # same, applied to the final output
  allowed_tools:               # agent → tool names it may use (default: every tool it declares)
    ops-assistant: [lookup_order, stock_analyst]
  allowed_services:            # agent → services it may call at all (default: every service its tools name)
    ops-assistant: [orders, inventory]
authz:
  default: deny                # deny | allow — applies when no rule matches
  callers:                     # who may invoke which of MY agents
    - identity: local                                        # the app container (localhost)
      agents: ["*"]
    - identity: spiffe://attache/ns/attache-demo/svc/orders  # a peer pod
      agents: [stock-analyst]
      caller_agents: [ops-assistant]   # optional: only when the caller's sidecar says this agent is calling
  services:                    # path-level rules for service invocation
    - name: inbound-orders-to-stock
      identity: spiffe://attache/ns/attache-demo/svc/orders  # caller pod; omit = any (incl. local)
      agent: ops-assistant                                   # calling agent; omit = any
      service: inventory                                     # target service (self when evaluated inbound)
      allow: ["GET /stock", "GET /stock/*"]
      deny:  ["* /admin", "* /admin/*"]
audit:
  sink: stdout                 # stdout | file
  file: /var/log/attache/audit.jsonl   # only with sink: file; the image makes /var/log/attache writable
  redact: []                   # dotted paths inside `input`/`output` to replace with "[redacted]"
```

### 3.1 Tools

```yaml
- name: lookup_order           # tool name shown to the model, unique per agent
  description: "..."           # required
  type: service                # service | agent | http
  parameters:                  # JSON Schema object for the tool input (default: {type: object, properties: {}})
    type: object
    properties: { order_id: { type: string } }
    required: [order_id]
  # type: service — call another (or this) service's HTTP API through the sidecar
  service: orders              # target service name; this service's own name = local app
  method: GET
  path: /orders/{order_id}     # `{param}` is substituted from the tool input; leftovers become the JSON body (POST/PUT/PATCH) or query (GET/DELETE)
  # type: agent — invoke another agent (orchestrator pattern)
  agent: stock-analyst
  service: inventory           # omit for a local agent
  # type: http — a URL performed by the sidecar; `{param}` only in the path/query,
  # never in the scheme, host or port (the origin is fixed by the charter)
  method: GET
  url: https://example.com/items/{id}
```

`agent` tools take `{ "input": string }`; their `parameters` default to that.
Only `type: orchestrator` agents may declare `agent` tools. An `agent` tool
whose `service` is this charter's own service is a local agent tool.

`{param}` values are percent-encoded by the runtime (`/` becomes `%2F`), so a
value can never add path segments.

### 3.2 Validation rules (all enforced by `attache-charter`)

- `apiVersion` must be `attache.io/v1alpha1`, `kind` must be `Charter`.
- Names (`service.name`, `service.namespace`, agent names) are DNS-1123 labels.
- Agent names unique; tool names unique per agent.
- `agent` tools only on orchestrators; a local `agent` tool (no `service`, or this service) must name an agent in this charter; an agent may not call itself.
- `http` tool `url` is `http(s)://host[:port]/…` with no `{param}` and no userinfo before the path.
- `budgets.max_tokens_per_call` ≤ 128000.
- `service` tools need `service`, `method`, `path`; `http` tools need `method`, `url`; `agent` tools need `agent`.
- `guardrails.allowed_tools` / `allowed_services` keys must be agent names and the values must be declared tools / referenced services.
- `authz.services[].name` unique; `allow`/`deny` entries are `"<METHOD|*> <path-glob>"` where the glob supports a trailing `*` only.
- Regexes must compile.
- `budgets.*` positive; `audit.sink: file` requires `audit.file`.

## 4. Wire protocol

Protobuf package `attache.v1alpha1` under `proto/attache/v1alpha1/`
(`common.proto`, `app.proto`, `mesh.proto`, `runtime.proto`). Generated Rust in
`crates/attache-proto`; generated Python in `runtime/src/attache_runtime/pb/`
(committed; regenerate with `make proto`).

### 4.1 App → sidecar (HTTP, `127.0.0.1:3500`)

`POST /v1/agents/{name}/invoke`

```json
{ "input": "How many WIDGET-1 are in stock?", "context": { "any": "json" } }
```

Request headers honoured: `traceparent` (W3C; generated when absent),
`content-type: application/json`.

Response `200`:

```json
{
  "status": "ok",
  "request_id": "7f0c…",            "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "agent": "ops-assistant",
  "output": "WIDGET-1: 42 on hand …",
  "usage": { "input_tokens": 812, "output_tokens": 96, "cost_usd": 0.0052 },
  "steps": [
    { "kind": "model_call",   "name": "claude-opus-5-5",            "decision": "allow", "latency_ms": 1180, "summary": "stop=tool_use" },
    { "kind": "agent_call",   "name": "inventory/stock-analyst",    "decision": "allow", "latency_ms": 930 },
    { "kind": "service_call", "name": "inventory POST /admin/reset","decision": "deny",  "rule": "authz.services.deny-admin", "latency_ms": 4 }
  ]
}
```

Other statuses, same envelope with `status` and `rule`/`reason`:

| HTTP | `status`  | when                                                   |
| ---- | --------- | ------------------------------------------------------ |
| 400  | `error`   | bad JSON / missing `input`                             |
| 403  | `denied`  | authz or guardrail denied the **invocation itself**    |
| 404  | `error`   | unknown agent                                          |
| 429  | `denied`  | budget exceeded (`budget.max_calls_per_minute`, `budget.max_cost_usd_per_day`) |
| 502  | `error`   | runtime unavailable / model error                      |

A tool call that is denied inside the run does **not** fail the invocation; it
is returned to the model as an error tool result, appears in `steps[]` with
`decision: deny`, and is audited.

Response headers always include `traceparent` and `x-attache-request-id`.

Also: `GET /v1/agents` → `{"agents":[{"name","type","model","tools":[...]}]}`,
`GET /v1/charter` → the loaded charter as JSON, `GET /healthz` → `200 ok`
(process up), `GET /readyz` → `200` once the charter is loaded, TLS is
loaded and the runtime answered `Health`; `503` otherwise. Body:
`{"ready", "runtime", "model_provider", "mesh"}`.

An unknown agent is reported only after `authz.callers` passed: the app gets
`404 agent.unknown`, a peer not allowed for that name gets
`403 authz.callers.*` (no probing of agent names over the mesh).

gRPC equivalent on `127.0.0.1:50001`: `AppApi.InvokeAgent(InvokeAgentRequest)`
and `AppApi.ListAgents`. Denials map to `PERMISSION_DENIED` /
`RESOURCE_EXHAUSTED`, unknown agent to `NOT_FOUND`, runtime errors to
`UNAVAILABLE`; the JSON envelope above is the gRPC message `InvokeAgentResponse`.

### 4.2 Sidecar ↔ sidecar (mesh, gRPC over mTLS, port 50002)

Metadata on every call: `traceparent`, `x-attache-request-id`,
`x-attache-agent` (calling agent). Caller identity is **only** taken from the
client certificate's URI SAN. `x-attache-agent` is a claim made by the
caller's sidecar (it is set by `attached`, never by the app or the model); the
callee cannot see the caller's charter, so it trusts the pair (SAN, agent)
exactly as far as its own `authz` rules say.

- `Mesh.InvokeAgent(InvokeAgentRequest) → InvokeAgentResponse` — the callee
  runs `authz.callers` (identity SAN → agent) then the agent, same as a local
  invocation.
- `Mesh.InvokeService(ServiceRequest) → ServiceResponse` — the callee runs
  `authz.services` with `service = self`, `identity = SAN`, `agent =
  x-attache-agent`, then forwards `method path headers body` to
  `127.0.0.1:<service.app_port>` and returns status/headers/body. Denials
  return `PERMISSION_DENIED` with the rule name in the message and the
  metadata `x-attache-rule`.

### 4.3 Sidecar ↔ runtime (gRPC over Unix sockets)

`Runtime` (served by the runtime):

- `Execute(ExecuteRequest) → ExecuteResponse`. `agent_spec_json` is the agent's
  charter entry **after** the sidecar applied `guardrails.allowed_tools` (the
  model never sees a tool it may not call). `depth` is the agent-call nesting
  depth; the sidecar refuses depth > 4 (`budget.max_depth`).
- `Health(Empty) → HealthResponse{ok, model_provider: "anthropic"|"mock"}`.

`SidecarTools` (served by the sidecar on `sidecar.sock`, called by the runtime
for every tool call so the sidecar can authorize and audit it):

The sidecar does not trust the runtime (it is driven by a model). Every call
must name a tool the agent declared and may use (`guardrail.allowed_tools`)
and must match that tool's declaration — same service and method, same agent
target, same http origin — else `guardrail.tool_spec`.

- `InvokeService(ToolServiceRequest) → ServiceResponse` — tool check,
  `guardrail.allowed_services`, path canonicalisation (§5.1,
  `guardrail.path`), `authz.services` with `identity = local`,
  `service = target`; then the local app (`service == self`) or the mesh.
- `InvokeAgent(ToolAgentRequest) → InvokeAgentResponse` — tool check; a local
  agent re-enters the invocation pipeline with `caller = local`,
  `caller_agent` set; a remote one goes over the mesh.
- `InvokeHttp(ToolHttpRequest) → ServiceResponse` — tool check (origin must
  equal the declared URL's), then plain HTTP egress, audited as `http_call`.
- `ReportEvent(AuditEvent{json}) → Empty` — the runtime's `model_call` records;
  the sidecar stamps `service`, `namespace`, redacts, and writes them.

The sidecar adds `traceparent` (a child span) and `x-attache-request-id` to
every request it sends — local app, mesh, http tool — and, toward an app,
`x-attache-caller` and `x-attache-agent`. Values for `traceparent`,
`tracestate`, `host`, `content-length` and any `x-attache-*` header supplied by
the runtime or a peer are dropped, never forwarded.

Outcomes, for all three tool RPCs (message = reason, metadata `x-attache-rule`):

| outcome | gRPC status | runtime sees | audit `decision` |
| ------- | ----------- | ------------ | ---------------- |
| allowed and done | `OK` | the result | `allow` |
| denied by policy (here or at the callee) | `PERMISSION_DENIED` (`RESOURCE_EXHAUSTED` for `budget.*`) | `is_error` tool result `denied by <rule>: <reason>` | `deny` + rule |
| allowed but failed (peer down, app down, model error, unknown agent) | `UNAVAILABLE` (`NOT_FOUND` for `agent.unknown`) | `is_error` tool result `tool failed: …` | `allow` + `error` |

A `RESOURCE_EXHAUSTED` without a `budget.*` rule (gRPC's own message-size
limit) is a failure, not a denial.

Clients of the unix sockets must send a plain `:authority` (the runtime sets
`grpc.default_authority=localhost`): grpc-python's default for `unix:` targets
is the percent-encoded socket path, which the sidecar's HTTP/2 stack rejects
with `PROTOCOL_ERROR`.

## 5. Identity, mTLS, authz

- Trust domain `attache`. SPIFFE ID `spiffe://attache/ns/<namespace>/svc/<service>`.
- `embassy` holds one CA per cluster: Secret `attache-ca` (`ca.crt`, `ca.key`)
  in the demo namespace. Leaf certs: Secret `attache-cert-<service>` with
  `ca.crt`, `tls.crt`, `tls.key`. Leaf SANs: URI = the SPIFFE ID; DNS =
  `<service>`, `<service>.<ns>`, `<service>.<ns>.svc`,
  `<service>.<ns>.svc.cluster.local`. CA TTL 10 years, leaf TTL 365 days
  (MVP: no rotation; re-running the Job keeps the CA and re-issues leaves).
- Mesh server: rustls, requires a client certificate chained to `ca.crt`.
  Caller identity = the first URI SAN of the client leaf; a certificate
  without a `spiffe://attache/` URI SAN is rejected (`authz.identity.invalid`).
- Mesh client: verifies the server against `ca.crt` with server name
  `<service>.<ns>.svc.cluster.local` and presents its own leaf.
- MVP simplification (documented, not hidden): the certificate is **per
  service** (every replica of a Deployment shares the Secret), issued by a
  bootstrap Job. Per-pod issuance through an init container CSR to a running
  `embassy` is the next step, as is the mutating webhook (§7).

### 5.1 Authz evaluation order (callee side, inbound)

1. `authz.callers`: find rules whose `identity` equals the caller (`local` or
   the SAN); the agent is allowed if any such rule lists it or `"*"` **and**
   the rule's `caller_agents` is empty or contains the calling agent (the
   caller sidecar's `x-attache-agent` claim; for local agent calls, the local
   calling agent). Otherwise `deny` with rule `authz.callers.default` (no rule
   for that identity) or `authz.callers.<service>` (a rule exists but excludes
   the agent or the calling agent). This runs before the agent name is looked
   up.
2. Budgets: `budget.max_calls_per_minute`, `budget.max_cost_usd_per_day`.
3. Guardrails on input — the `input` **and** the `context` JSON, everything
   the model sees first: `guardrail.max_input_bytes` (their sum),
   `guardrail.input_deny.<name>` (either matches).
4. Run. Tool calls: egress rules on the caller side (`guardrail.allowed_tools`,
   `guardrail.tool_spec`, `guardrail.allowed_services`, `guardrail.path`,
   `authz.services` for the target with identity `local`), inbound rules on
   the callee side (`guardrail.path`, `authz.services` for self with the
   caller's SAN).
5. Guardrails on output: `guardrail.output_deny.<name>` → deny;
   `guardrail.pii_redact` → rewrite, decision stays `allow`.

`authz.services` matching: a rule applies when its `identity` (if set) equals
the caller identity, its `agent` (if set) equals the calling agent and its
`service` equals the target. Among applying rules, any `deny` match wins
(`authz.services.<rule-name>`); else any `allow` match allows
(`authz.services.<rule-name>`); else `authz.default`. When no rule applies,
`authz.default` (`authz.default.deny` / `authz.default.allow`). A pattern is
`"<METHOD> <path>"` with `*` as the method wildcard and an optional trailing
`*` on the path (`/stock/*` matches `/stock/x` and `/stock/x/y`, not `/stock`).

Path canonicalisation (`guardrail.path`): before any `authz.services` match,
on both sides, the path is resolved with the same WHATWG URL parser the
sidecar uses to send the request, so `.`/`..` and percent-encoded dot segments
(`%2e%2e`) are removed first — `/stock/../admin/reset` is matched, audited and
sent as `/admin/reset`. A path that does not start with `/`, or contains
whitespace, a control character, `\`, `#`, or an encoded `/`, `\` or NUL
(`%2f`, `%5c`, `%00`), is denied with `guardrail.path`.

`identity: local` in `authz.services` matches calls made by this pod's own
agents (egress and self calls); a SPIFFE identity matches inbound calls from
that peer.

## 6. Audit record

One JSON object per line, written by `attached` only (sink `stdout`, readable
with `kubectl logs -c attached`, or `file`). Field order is fixed as below so
`grep` and humans see the same thing.

```json
{
  "ts": "2026-10-20T19:02:11.482Z",
  "kind": "agent_invocation | model_call | tool_call | agent_call | service_call | http_call | authz | guardrail | budget",
  "request_id": "0c4a3f8e-…",             // one per top-level invocation, propagated unchanged across hops
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",   // W3C, propagated via traceparent
  "span_id": "00f067aa0ba902b7",           // this hop
  "parent_span_id": "b7ad6b7169203331",    // or null
  "service": "orders", "namespace": "attache-demo",
  "agent": "ops-assistant",                // the agent this record belongs to (null for pure authz failures before resolution)
  "caller": "local | spiffe://attache/ns/attache-demo/svc/orders",
  "caller_agent": "ops-assistant",         // when another agent made the call, else null
  "callee": "ops-assistant | anthropic:claude-opus-5-5 | mock | inventory/stock-analyst | inventory GET /stock | https://…",
  "direction": "inbound | outbound | internal",
  "input":  <json or string, redacted>,    // what went in (prompt/messages for model_call, args for tools, body for service calls)
  "output": <json or string, redacted>,    // what came out (null when denied)
  "input_sha256": "hex of the full, unredacted input serialisation",
  "output_sha256": "hex or null",
  "tokens": { "input": 812, "output": 96 } | null,
  "cost_usd": 0.0052 | null,
  "latency_ms": 1180,
  "decision": "allow | deny",
  "rule": "authz.services.deny-admin | guardrail.input_deny.no-secrets | budget.max_calls_per_minute | null",
  "reason": "human readable or null",
  "error": "string or null"
}
```

Redaction, in this order, over the full payloads:

1. `input_sha256` / `output_sha256` are computed over the full original bytes,
   so a consumer can prove a payload later without the sidecar storing it.
2. `audit.redact` dotted paths are replaced with `"[redacted]"` inside
   `input`/`output` (arrays are walked). Values found at those paths (strings
   and numbers of 4+ characters) are also remembered per `request_id` for 15
   minutes and scrubbed from every later record of the same request in that
   sidecar — they reappear as text inside model prompts and tool results.
3. `guardrails.pii_redact` rewrites emails to `[redacted:email]` and phone
   numbers to `[redacted:phone]` in the agent's output returned to the caller
   **and** in every string of every audit `input`/`output` that sidecar writes.
4. Payloads larger than 8 KiB are truncated to 8 KiB plus
   `…(truncated, N bytes)` — after redaction, so a cut never exposes part of a
   redacted value.

A mesh call refused for its certificate (`authz.identity.invalid`) is audited
as kind `authz` with `caller: "unknown"`.

Which records a single demo call produces (orders pod unless noted):

```
[orders]     model_call        outbound  ops-assistant → anthropic:<model> | mock          allow   (reported by the runtime)
[inventory]  model_call        outbound  stock-analyst → anthropic:<model> | mock          allow
[inventory]  tool_call         internal  stock-analyst → get_stock                         allow
[inventory]  service_call      internal  stock-analyst → inventory GET /stock/WIDGET-1     allow   (self → 127.0.0.1:app_port)
[inventory]  model_call        outbound  stock-analyst → …                                 allow
[inventory]  guardrail         internal  stock-analyst                                     allow   rule guardrail.pii_redact
[inventory]  agent_invocation  inbound   spiffe://…/svc/orders (ops-assistant) → stock-analyst   allow
[orders]     tool_call         internal  ops-assistant → stock_analyst                     allow
[orders]     agent_call        outbound  ops-assistant → inventory/stock-analyst           allow
[orders]     model_call        outbound  ops-assistant → …                                 allow
[orders]     agent_invocation  inbound   local → ops-assistant                             allow
```

Records are written when each step finishes, so an invocation's own record
comes after its children's.

And the denied call: on the inventory pod `service_call inbound
spiffe://…/svc/orders (ops-assistant) → inventory POST /admin/reset deny
rule=authz.services.deny-admin`; on the orders pod the matching `tool_call`
with `decision: deny` and the same `request_id` and `trace_id`.

## 7. Kubernetes packaging

`deploy/` is a kustomize tree, applied with `kubectl apply -k deploy/`:

- `namespace.yaml` — `attache-demo`.
- `embassy/` — ServiceAccount, Role (`secrets: get, create, update`),
  RoleBinding, Job `embassy-bootstrap` running
  `embassy bootstrap --namespace attache-demo --services orders,inventory`.
- `orders/`, `inventory/` — Deployment with two containers (`app`,
  `attached`) and a Service exposing the app port and `mesh` 50002. The
  charter ConfigMap `<svc>-charter` (key `charter.yaml`) is created by
  `make charters` from `examples/charters/<svc>.charter.yaml`, the single
  committed copy, and mounted at `/etc/attache/charter/`. The TLS Secret is
  mounted at `/etc/attache/tls/` (sibling, never nested in the read-only
  ConfigMap mount).
- Labels: `app: <svc>`, `attache.io/service: <svc>`. `attache logs` selects
  on `attache.io/service`.
- Images (built inside minikube's docker): `attache/attached:dev`
  (sidecar binary + Python runtime in one image), `attache/embassy:dev`,
  `attache/orders:dev`, `attache/inventory:dev`. `imagePullPolicy: IfNotPresent`.
- The inventory app listens on `127.0.0.1` inside its pod and its Service
  exposes only `mesh`: every other pod reaches it through the sidecar. (The
  orders app keeps its HTTP port because it is the demo's entry point.)
- Optional Secret `attache-anthropic` (`ANTHROPIC_API_KEY`), referenced with
  `optional: true`; without it every agent runs on the mock model.
- Sidecar injection is **explicit** in the MVP: the `attached` container, the
  charter ConfigMap mount and the TLS Secret mount are written in each
  Deployment. The mutating admission webhook keyed on
  `attache.io/inject: "true"` is not implemented yet.

## 8. CLI

```
attache charter validate <file>        # exit 0 "valid", exit 1 with one error per line
attache charter schema                 # JSON Schema to stdout (== schemas/charter.schema.json)
attache logs <svc>[,<svc>…] [-n NS] [--context C] [--agent A] [--trace T] [--request R] [--kind K] [--denied] [-f] [--raw] [--file F|-] [--tail N]
attache version
```

`attache logs` runs `kubectl logs -n NS -l 'attache.io/service in (<svcs>)' -c
attached --tail N [-f]`, keeps only lines that parse as §6 records (sidecar
diagnostics share the container log on stderr and are skipped), applies the
filters (`--trace`/`--request` match by prefix; `--agent` matches `agent` or
`caller_agent`), sorts by `ts` unless following, and prints one line per
record:

```
19:02:11.482 orders    ops-assistant   agent_invocation inbound  local → ops-assistant            allow            1412ms
19:02:12.904 inventory stock-analyst   service_call     inbound  …/svc/orders → inventory POST /admin/reset   DENY authz.services.deny-admin 4ms
```

`--file F` (or `-` for stdin) reads records from a file instead of kubectl.

## 9. Agent runtime semantics

- One `Execute` = one agentic loop: `system` + user `input` (+ `context` as a
  JSON block in the first user message when present). Loop until the model
  stops with `end_turn`, `max_steps` is reached (`budget.max_steps`, status
  `error`), or the model refuses (`stop_reason: refusal`, status `denied`,
  rule `model.refusal`).
- Every tool call goes to the sidecar (§4.3). Multiple `tool_use` blocks in one
  turn are executed sequentially and returned in one user message.
- `model_call` events are reported through `ReportEvent` with
  `input = {system, messages, tools}` and `output = content blocks`; tokens
  from the API `usage`; `cost_usd` from the pricing table in
  `runtime/src/attache_runtime/pricing.py` (per 1M tokens; `mock` = 0).
- Provider selection: `ANTHROPIC_API_KEY` set and `model != mock` → Anthropic
  SDK, else the deterministic mock. Requests are streamed and collected
  (`messages.stream(...).get_final_message()`), so large `max_tokens` never
  trip the SDK's non-streaming limit; `output_config.effort: low` is sent to
  every model that accepts it (not `claude-haiku-4-5`, `claude-sonnet-4-5` or
  older). Thinking blocks are replayed unchanged on the next turn.
- `stop_reason: max_tokens`: with text and no tool call → `ok` with the
  truncated text (step summary says so); with a tool call or no text → `error`,
  rule `budget.max_tokens_per_call` (a cut-off tool call never runs).
- Mock model: on a turn without tool results it picks the single tool whose
  name+description shares the most words with the input (ties → declaration
  order) and fills string parameters heuristically (`input`/`question`/`query`
  → the whole input; `sku`/`id`/`order_id` → the first `UPPER-1` token, else
  the first run of 3+ digits); on a turn with tool results it answers
  `Based on <tool>: <result>` (results truncated to 600 chars). No tools → it
  echoes `Mock answer for: <input>`.

## 10. Testing gates

- `cargo test --workspace` — charter validation (including unknown-field
  rejection and schema sync), authz matcher, guardrails, redaction, trace
  parsing, PKI issue/parse round trip, and an in-process mTLS mesh test (two
  sidecar cores on localhost: allowed call succeeds, `/admin` denied with the
  rule name, wrong identity rejected).
- `cd runtime && uv run pytest` — mock model routing, agent loop with a fake
  sidecar, pricing, event shape.
- `services/attache-cli/tests/cli.rs` — `charter validate` accepts the demo
  charters and rejects `examples/charters/invalid-unknown-field.charter.yaml`;
  `logs --file` filters and sorts.
- `make local-demo` — the full demo on one machine: both apps, two sidecars
  with embassy certificates over mTLS, the real runtime (mock model).
- `make demo` on minikube is the end-to-end gate.

## 11. Known gaps (MVP)

- Per-pod certificates and rotation; webhook injection; `embassy` as a
  long-running CA server.
- Budgets are in-memory per sidecar replica (not shared across replicas).
- Model egress (the HTTPS call to Anthropic) is made by the runtime, not
  proxied by the sidecar; it is audited via `ReportEvent`, not intercepted.
- Server-side refusal fallbacks (`fallbacks: "default"`) are not enabled; a
  refusal is surfaced as `model.refusal`.
