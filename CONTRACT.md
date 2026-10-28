# CONTRACT.md — the source of truth

Everything that has to fit together across the sidecar, the agent runtime, the
control plane, the CLI and the Kubernetes manifests is defined here. When code
and this file disagree, this file wins and the code is wrong. Keep it updated
in the same change.

## 0. Names

| Thing                       | Name            | Where                                   |
| --------------------------- | --------------- | --------------------------------------- |
| Product                     | **agent-sidecar** (short: **agentsc**) | repo, docs                |
| Sidecar daemon binary       | `agentscd`      | `services/agentscd`                     |
| CLI                         | `agentsc`       | `services/agentsc-cli`                  |
| Control plane / CA          | `embassy`       | `services/embassy`                      |
| Agent + policy spec file    | `charter.yaml`  | `examples/charters/*.charter.yaml`      |
| Kubernetes API group        | `agentsc.io/v1alpha1` | `apiVersion` in charters, labels  |
| Agent runtime (Python)      | `agentsc-runtime` | `runtime/`                            |
| Discipline                  | AgentSecOps     | README                                  |

## 1. What agentsc is

**The agent is a sidecar of the service, not a service of its own.**

```
                       pod: orders                                      pod: inventory
 ┌────────────────────────────────────────────────┐        ┌────────────────────────────────────────┐
 │  app container (Go, no SDK)                    │        │  app container (FastAPI, no SDK)       │
 │   POST localhost:3500/v1/agents/ops-assistant  │        │   GET /stock      POST /admin/reset    │
 │             │                                  │        │        ▲                 ▲ (denied)    │
 │  ───────────┼──────────────────────────────    │        │  ──────┼─────────────────┼──────────── │
 │  agentscd (sidecar)  ◀── charter.yaml (CM)     │  mTLS  │  agentscd (sidecar) ◀── charter.yaml   │
 │   HTTP 3500 · gRPC 50001 · mesh 50002 ─────────┼────────┼─▶ mesh 50002  authz(SAN + agent)       │
 │   guardrails · budgets · authz · audit JSONL   │        │   guardrails · budgets · authz · audit │
 │        │ unix socket                           │        │        │ unix socket                   │
 │   agentsc-runtime (python) ── Claude / mock    │        │   agentsc-runtime (python)             │
 │     ops-assistant (orchestrator)               │        │     stock-analyst (agent)              │
 └────────────────────────────────────────────────┘        └────────────────────────────────────────┘
                 ▲ certs: Secret agentsc-cert-orders           ▲ certs: Secret agentsc-cert-inventory
                 └──────────────── embassy (CA, Job) ──────────┘  spiffe://agentsc/ns/<ns>/svc/<svc>
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
   `spiffe://<trust domain>/ns/<namespace>/svc/<service>` (trust domain `agentsc`
   unless configured, §5). The callee sidecar decides
   using the caller's certificate SAN plus the calling agent name, never a
   header alone.
5. **Default deny** for authz once a charter exists. Explicit `allow` rules
   are the only way an identity reaches an agent or an agent reaches a path.

## 2. Components and ports

| Component            | Listens on                               | Who calls it                      | Protocol        |
| -------------------- | ---------------------------------------- | --------------------------------- | --------------- |
| `agentscd` app HTTP  | `127.0.0.1:3500`                         | the app container                 | HTTP/1.1 JSON   |
| `agentscd` app gRPC  | `127.0.0.1:50001`                        | the app container                 | gRPC plaintext  |
| `agentscd` mesh      | `0.0.0.0:50002` (pod IP, via Service)    | other pods' sidecars              | gRPC **mTLS**   |
| `agentscd` tools     | `unix:/run/agentsc/sidecar.sock`         | the local agent runtime           | gRPC            |
| `agentscd` model gateway | `unix:/run/agentsc/model.sock`       | the local agent runtime (every model call, §4.4) | HTTP/1.1 (Anthropic Messages API) |
| `agentsc-runtime`    | `unix:/run/agentsc/runtime.sock`         | the local sidecar                 | gRPC            |
| `embassy`            | none (Job) — see §7                      | —                                 | Kubernetes API  |

Peer discovery: a charter names a peer `S` (a service of its own namespace) or
`S.N` (service `S` in namespace `N`, charter schema level 5) in `tools[].service`
and `mesh.peers`. The mesh address of service `S` in namespace `N` is
`S.N.svc.<cluster domain>:50002` (`--peer-address-template`, cluster domain
`cluster.local` unless `--cluster-domain` says otherwise) unless `mesh.peers`
in the charter overrides it under the name the tools use. Whatever the address,
the caller accepts only the peer's identity `spiffe://<trust domain>/ns/N/svc/S`
(§5). Every demo Service therefore exposes port `50002` (`mesh`) next to the
app port.

Flags / environment of `agentscd` (flag wins over env):

| Flag              | Env                      | Default                           |
| ----------------- | ------------------------ | --------------------------------- |
| `--charter`       | `AGENTSC_CHARTER`        | `/etc/agentsc/charter/charter.yaml` |
| `--tls-dir`       | `AGENTSC_TLS_DIR`        | `/etc/agentsc/tls` (`ca.crt`, `tls.crt`, `tls.key`) |
| `--http-addr`     | `AGENTSC_HTTP_ADDR`      | `127.0.0.1:3500`                  |
| `--grpc-addr`     | `AGENTSC_GRPC_ADDR`      | `127.0.0.1:50001`                 |
| `--mesh-addr`     | `AGENTSC_MESH_ADDR`      | `0.0.0.0:50002`                   |
| `--socket-dir`    | `AGENTSC_SOCKET_DIR`     | `/run/agentsc`                    |
| `--runtime-cmd`   | `AGENTSC_RUNTIME_CMD`    | `agentsc-runtime` (shell words; `--listen` and `--sidecar` are appended) |
| `--no-runtime`    | `AGENTSC_NO_RUNTIME`     | off. `1/true/yes/on` = do not spawn the runtime; something else serves `runtime.sock`, and readiness still follows its `Health` |
| `--mesh-cache-bytes` | `AGENTSC_MESH_CACHE_BYTES` | `16777216`. Bytes of service-call responses the response cache keeps (`GET`/`HEAD` the app marked with `Cache-Control: max-age`; docs/adr/0002-response-caching.md); `0` disables it |
| `--mesh-cache-max-age` | `AGENTSC_MESH_CACHE_MAX_AGE` | `300`. The longest, in seconds, a cached service-call response is served, whatever the app's `max-age` says |
| `--max-response-bytes` | `AGENTSC_MAX_RESPONSE_BYTES` | `3145728` (3 MiB). The largest response body a tool or mesh call reads from the app, a peer or an http tool's origin, read as it streams; a longer one fails the call (`http.response_too_large`) |
| `--audit-fail-closed` | `AGENTSC_AUDIT_FAIL_CLOSED` | off. `1/true/yes/on` = while the audit sink fails, refuse new work with rule `audit.unavailable` and report not ready, until a write succeeds again (§6 "Sink failures") |
| `--trust-domain`  | `AGENTSC_TRUST_DOMAIN`   | `agentsc`. The SPIFFE trust domain of this pod's identity, of the peers it accepts and calls, and of the control plane (§5); must be embassy's |
| `--cluster-domain` | `AGENTSC_CLUSTER_DOMAIN` | `cluster.local`. `{cluster_domain}` of `--peer-address-template` (default `{service}.{namespace}.svc.{cluster_domain}:{port}`) |
| `--anthropic-api-key-file` | `AGENTSC_ANTHROPIC_API_KEY_FILE` | unset. The Anthropic API key, read by the sidecar's model gateway only (§4.4) |
| —                 | `ANTHROPIC_API_KEY`      | the same key as text (env only, never a flag). Neither set → the gateway has no provider, and an agent whose `model` is not `mock` is refused (`FAILED_PRECONDITION`), unless `AGENTSC_MOCK_FALLBACK=1`. The runtime the sidecar starts never gets either, nor `ANTHROPIC_AUTH_TOKEN`, `OPENAI_API_KEY` or `AGENTSC_APP_TOKEN` |
| `--anthropic-base-url` | `AGENTSC_ANTHROPIC_BASE_URL` | `https://api.anthropic.com` |
| —                 | `AGENTSC_MOCK_FALLBACK`  | unset. `1` = when the sidecar holds no key, every agent runs on the `mock` model (demos, CI); the runtime the sidecar starts inherits it (an injected pod's `agentsc-runtime` container gets it from the injector's template, Helm `injection.mockFallback`) |
| —                 | `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_API_KEY_FILE`, `LLM_API_KEY`, `LLM_MODEL`, `LLM_MODEL_SMALL`, `LLM_TIMEOUT_SECS`, `LLM_MAX_RETRIES`, `LLM_GATEWAY_URL`, `LLM_GATEWAY_TOKEN_FILE` | unset. The LLM connection contract v1 (docs/LLM-CONNECTION.md), used when no Anthropic key is set the sidecar's own way: `LLM_PROVIDER=anthropic` with a key, or gateway mode (the model gateway's `/v1/messages` with the token: the pod holds no provider key). `LLM_TIMEOUT_SECS` caps every model call; `LLM_MAX_RETRIES` retries a connection that could not be made. An invalid value stops the sidecar naming the variable; the runtime never gets the key or token variables |

## 3. `charter.yaml`

Top-level keys are exactly these; unknown keys anywhere are a validation
error (`agentsc charter validate` exits 1 and names the path). JSON Schema:
`schemas/charter.schema.json`, generated from the Rust types by
`agentsc charter schema`; a test keeps the file in sync. Fields marked
*v0.2*, *level 3*, *level 4* or *level 6* are optional additions (§3.3, §3.5); a
charter without them is a v0.1 charter and serializes exactly as one. It
does not behave exactly as one: the practices (level 6, §3.3) are on by
default, so a sidecar of this build gives every agent a working method and
an output style, and offers it `ask_caller` (§9), with no change to its
charter. This build also rejects a tool named `ask_caller` at every level
(§3.2 rule 12), so a charter with such a tool must rename it before the
upgrade.

```yaml
apiVersion: agentsc.io/v1alpha1
kind: Charter
service:
  name: orders                 # DNS-1123 label
  namespace: agentsc-demo      # DNS-1123 label
  app_port: 8080               # where the app container listens on localhost
  service_accounts: [orders]   # v0.2: Kubernetes service accounts allowed to obtain this identity (default: [<service.name>])
mesh:                          # optional
  port: 50002
  peers: {}                    # peer (`inventory`, or `inventory.warehouse` for another namespace) → host:port override
skills:                        # v0.2, at most 64
  - name: refund-policy        # DNS-1123 label, unique
    description: How to decide whether a refund is allowed.   # 1..=1024 characters
    instructions: |            # 1..=32768 bytes
      Look up the order with lookup_order first. ...
    tools: [lookup_order]      # optional; each must be allowed for every agent that uses the skill
telemetry:                     # v0.2, optional; absent = these defaults
  otlp_endpoint: http://otel-collector:4318   # optional; http(s)://host[:port], no path, query or fragment
  traces: true
  metrics: true
  export_payloads: false       # spans carry inputs/outputs only if true
  control_plane_payloads: true # audit records sent to the control plane keep their redacted, truncated input/output
agents:
  - name: ops-assistant        # unique, DNS-1123 label
    type: orchestrator         # agent | orchestrator (orchestrator = may use `agent` tools)
    model: claude-opus-5-5     # any Claude model id, or `mock`
    system: "..."              # system prompt, at most 32768 bytes
    tools: []                  # see below
    budgets:
      max_tokens_per_call: 2048      # max_tokens for each model call, 1..=128000 (thinking counts against it)
      max_calls_per_minute: 30       # inbound invocations of this agent, sliding window
      max_cost_usd_per_day: 5.0      # model spend per UTC day, as the sidecar measures it (§4.4)
      max_steps: 6                   # model-call iterations per invocation (held by the sidecar, §4.4)
    skills: [refund-policy]          # v0.2: names from the top-level `skills`, each once
    harness:                         # v0.2, optional; absent = these defaults
      max_retries: 2                 # 0..=10
      request_timeout_seconds: 120   # 1..=600, per attempt
      fallback_model: claude-haiku-5-5   # optional; a model id other than `model`
      tool_result_max_chars: 20000   # 100..=200000
    learning:                        # v0.2, optional; absent = these defaults (off)
      enabled: false
      mode: review                   # review | auto (auto requires enabled: true)
      max_notes: 20                  # 1..=200
      max_note_chars: 500            # 50..=4000
      note_ttl_days: 7               # 1..=365; auto notes only
      from_peers: false              # also reflect on invocations whose caller is a peer service
      max_proposals_per_hour: 10     # 1..=100
      require_evidence: true         # level 6, optional; a lesson must cite steps of the run (§9)
      contrast_runs: 5               # level 6, optional; 0..=20 earlier runs shown as digests; 0 = none
      scopes: [invariant, domain]    # level 6, optional; the lesson scopes that are kept; non-empty, each once
    taint:                           # level 3, optional; absent = no taint rules (§5.2)
      mode: enforce                  # enforce | audit
      input: trusted                 # label of the invocation's own input: trusted | untrusted | sensitive
    practices:                       # level 6, optional; absent = these defaults (on) (§3.3, §9)
      plan: true                     # a short plan before the first tool call; each result checked against its step
      clarify: blocking              # never | blocking | always: when to ask the caller with ask_caller
      max_questions: 5               # 1..=10, questions per round
      brevity: lite                  # normal | lite | full | ultra, when the service's own app is the caller
      agent_brevity: full            # normal | lite | full | ultra, when an agent is the caller (every mesh call)
      auto_clarity: true             # plain prose for warnings, destructive and ordered steps
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
    - identity: spiffe://agentsc/ns/agentsc-demo/svc/orders  # a peer pod
      agents: [stock-analyst]
      caller_agents: [ops-assistant]   # optional: only when the caller's sidecar says this agent is calling
  services:                    # path-level rules for service invocation
    - name: inbound-orders-to-stock
      identity: spiffe://agentsc/ns/agentsc-demo/svc/orders  # caller pod; omit = any (incl. local)
      agent: ops-assistant                                   # calling agent; omit = any
      service: inventory                                     # target service (self when evaluated inbound)
      allow: ["GET /stock", "GET /stock/*"]
      deny:  ["* /admin", "* /admin/*"]
  taint:                       # schema level 4, optional; absent = off (§5.2)
    mode: enforce              # enforce | audit: a peer's write whose run read untrusted data
audit:
  sink: stdout                 # stdout | file
  file: /var/log/agentsc/audit.jsonl   # only with sink: file; the image makes /var/log/agentsc writable
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
  service: orders              # target service name; this service's own name = local app;
                               # `<service>.<namespace>` = a service in another namespace (level 5)
  method: GET
  path: /orders/{order_id}     # `{param}` is substituted from the tool input; leftovers become the JSON body (POST/PUT/PATCH) or query (GET/DELETE)
                               # `{param?}` as the whole last segment is optional: /stock/{sku?} → /stock
  # type: agent — invoke another agent (orchestrator pattern)
  agent: stock-analyst
  service: inventory           # omit for a local agent
  # type: http — a URL performed by the sidecar; `{param}` only in the path/query,
  # never in the scheme, host or port (the origin is fixed by the charter)
  method: GET
  url: https://example.com/items/{id}
  # level 3, any type, used by `agents[].taint` (§5.2)
  label: untrusted             # trusted | untrusted | sensitive — what the tool returns (default: untrusted for http, else trusted)
  effect: read                 # read | write (default: read for agent tools and GET/HEAD/OPTIONS, else write)
```

`agent` tools take `{ "input": string, "context"?: object }`: the question,
and a JSON object the callee gets as its `context` (§4.1), which is how a
calling agent answers the callee's questions (§9). Their `parameters`
default to that schema, which the sidecar fills in `agent_spec_json` (§4.3).
With its own `parameters`, an `agent` tool sends a string `input` argument as
the input and a `context` object argument as the context; without a string
`input`, all its arguments as one JSON string and no context. A `context` that
is not a JSON object is refused before anything is sent (`is_error` tool
result `denied by guardrail.tool_spec: …`).
Only `type: orchestrator` agents may declare `agent` tools. An `agent` tool
whose `service` is this charter's own service is a local agent tool.

`{param}` values are percent-encoded by the runtime (`/` becomes `%2F`, `;`
becomes `%3B`), so a path value is exactly one segment: it can never add segments, and since a
missing or empty value, or one made only of dots (`.`, `..`), is refused
before anything is sent (`is_error` tool result `denied by
guardrail.tool_spec: …`), it can never drop or climb one either
(`DELETE /orders/{id}` never becomes `DELETE /orders`). Only `{param?}`, as the
whole last segment, may be left out (or empty): the segment goes with its `/`.
A `{param}` may also be part of a segment (`/files/{name}.json`) or sit in the
query (`/search?q={term}`, where it may be empty). Leftover arguments are
appended to the query with `&` when the template already has one.

The sidecar holds every `service` and `http` call to its template: the
canonical path (§5.1; for `http`, the URL's path) must have the template's
literal segments, and one segment of one or more characters for each
`{param}` — else `guardrail.tool_spec`. The query is not checked.

### 3.2 Validation rules (all enforced by `agentsc-charter`)

- `apiVersion` must be `agentsc.io/v1alpha1`, `kind` must be `Charter`.
- Names (`service.name`, `service.namespace`, agent names) are DNS-1123 labels.
- A peer named with a namespace (`tools[].service` of `service` and `agent`
  tools, `mesh.peers` keys) is `<service>.<namespace>`, two DNS-1123 labels, and
  never the charter's own namespace (that peer is written `<service>`, so every
  rule names it one way). The rest of the charter names it the same way:
  `guardrails.allowed_services` and the caller's `authz.services[].service`.
- Agent names unique; tool names unique per agent.
- `agent` tools only on orchestrators; a local `agent` tool (no `service`, or this service) must name an agent in this charter; an agent may not call itself.
- `http` tool `url` is `http(s)://host[:port]/…` with no `{param}` and no userinfo before the path.
- A `service` tool `path` and the path of an `http` tool `url` are templates: they start with `/`; have no empty (`//`), `.` or `..` segments; their literal text is RFC 3986 path characters except `;` (`A–Z a–z 0–9 -._~!$&'()*+,=:@`, plus `%XX` escapes other than `%2F`, `%5C`, `%00`; a `;` is written `%3B`); `{name}` has `name` matching `^[a-zA-Z0-9_]+$`; `{name?}` is only the whole last segment.
- `budgets.max_tokens_per_call` ≤ 128000.
- `service` tools need `service`, `method`, `path`; `http` tools need `method`, `url`; `agent` tools need `agent`.
- `guardrails.allowed_tools` / `allowed_services` keys must be agent names and the values must be declared tools / referenced services.
- `authz.services[].name` unique; `allow`/`deny` entries are `"<METHOD|*> <path-glob>"` where the glob supports a trailing `*` only, and the path is one a canonical path (§5.1) can be: the template characters above, no `?`, no empty, `.` or `..` segments.
- Regexes must compile.
- `budgets.*` positive; `audit.sink: file` requires `audit.file`.

v0.2 rules (each has a passing and a failing test in `crates/agentsc-charter/tests/v02_rules.rs`;
the JSON Schema mirrors what it can express: patterns, ranges, lengths, `maxItems`, `uniqueItems`,
`learning.mode: auto` ⇒ `enabled: true`, a tool `name` that matches `^[a-zA-Z0-9_-]{1,64}$` and is
`not` one of `load_skill` and `ask_caller` (rule 12), and a `model` / `fallback_model` that matches `^[^\s\x00-\x1f\x7f-\x9f]+$`
with `maxLength` 128; the validator is the authority, e.g. it counts the 128 in bytes):

1. Skill names are DNS-1123 labels and unique; `agents[].skills` entries name a top-level skill
   and are not repeated.
2. For each agent using a skill, every `skill.tools` entry is in `Charter::allowed_tools(agent)`
   (the declared tools, narrowed by `guardrails.allowed_tools`).
3. No tool may be named `load_skill` (the runtime offers it for skills, §3.3).
4. `harness.fallback_model` follows the `model` rules — not empty, no whitespace or control
   characters, at most 128 bytes (`model` itself follows them too) — and differs from `model`.
   `harness` ranges: `max_retries` 0..=10, `request_timeout_seconds` 1..=600,
   `tool_result_max_chars` 100..=200000.
5. `telemetry.otlp_endpoint` is an `http://` or `https://` URL with a host and no userinfo, path
   (other than `/`), query or fragment. Whitespace and control characters anywhere (a trailing
   space, a tab) are refused before the URL is parsed, since the parser would quietly drop them;
   the schema `pattern` refuses the same.
6. `learning.mode: auto` requires `learning.enabled: true`. `learning` ranges: `max_notes`
   1..=200, `max_note_chars` 50..=4000, `note_ttl_days` 1..=365, `max_proposals_per_hour`
   1..=100.
7. Size limits: the charter is at most 256 KiB, measured the same way whatever form it arrives
   in: its JSON serialization and its plain YAML as `Charter::to_yaml` writes it (the text
   `CharterUpdate.charter_yaml` and the file store carry) are each at most 262144 bytes, so a
   charter accepted in one form (a custom resource at the webhook, JSON, YAML) is accepted in
   every form it is converted to. YAML indents every line of a block scalar, so the YAML can be
   the bigger of the two. A plain charter's YAML text, comments included, is also at most
   256 KiB and is refused before it is parsed when bigger. In the custom resource form, §3.4,
   the limit applies to the charter `spec` describes, never to `status` or `metadata`. At most
   64 skills; `agents[].system` at most 32 KiB; a skill's `instructions` 1 to 32768 bytes and
   its `description` 1 to 1024 characters; and a service's memory is at most 262144
   **characters**: the sum of `max_notes × max_note_chars` over the agents with learning
   enabled is at most 262144 (`MAX_MEMORY_CHARS`). Memory exists only for
   agents with learning enabled: agents with learning off or absent hold no notes, do not count,
   and get no memory from `runtime_spec` (§4.3).
8. `service.service_accounts` entries are DNS-1123 labels.

Level 6 rules (design: [docs/design/agent-practices.md](docs/design/agent-practices.md); each has
a passing and a failing test in `crates/agentsc-charter/tests/practices_rules.rs`; the JSON
Schema mirrors the ranges, the enums, `minItems`, `uniqueItems` and the reserved tool name, and
the validator is the authority):

9. `practices.max_questions` is 1..=10: `agents[i] (a): practices.max_questions must be 1..=10`.
10. `learning.contrast_runs` is 0..=20: `agents[i] (a): learning.contrast_runs must be 0..=20`.
11. `learning.scopes` is non-empty and lists each value once: `agents[i] (a): learning.scopes
    must list invariant, domain or both, each once`.
12. No tool may be named `ask_caller` (the runtime offers it for questions to the caller, §9),
    as no tool may be named `load_skill` (rule 3): `… the tool name ask_caller is reserved for
    questions to the caller`.

### 3.3 Skills, harness, learning, telemetry (v0.2), practices (level 6)

- **Skills** are named instructions in the top-level `skills`; an agent lists the ones it uses.
  The runtime receives them resolved (§4.3): a skill whose `instructions` are shorter than 2048
  bytes is *inline* (appended to the system prompt); the others are offered through the
  runtime's `load_skill` tool.
- **Harness**: model-call retries, the per-attempt timeout, a fallback model tried once after the
  last retryable failure, and the cut-off for tool results. Absent = the defaults above.
- **Learning**: agents may propose lessons (`SidecarTools.ProposeLesson`, §4.3); in `review`
  mode an editor decides, in `auto` mode a lesson becomes a note at once and expires after
  `note_ttl_days`. Absent = off. The level-6 fields shape the reflection (§9) and matter only
  when `enabled` is true: with `require_evidence` a lesson must cite at least one step of the
  run, `contrast_runs` is how many digests of earlier runs the reflection sees, and `scopes`
  are the lesson scopes that are kept (`invariant`: how to work; `domain`: the agent's subject).
- **Practices** (level 6): a fixed working method and output style that the runtime puts in
  front of the model (§9). Their texts are fixed in the runtime; the charter holds only
  switches and levels, never text, so these settings can't carry instructions. `plan` asks for
  a short plan before the first tool call and a check of each result. `clarify` offers the
  `ask_caller` tool: `blocking` asks only when a decision only the caller can make blocks the
  task and no safe default exists, `always` asks before acting on any open decision, and
  `never` offers no `ask_caller`. `max_questions` caps the questions of one round. `brevity` is
  the answer's style when the service's own app (or another local caller without a calling
  agent) is the caller, `agent_brevity` when an agent is (`normal`, `lite`, `full`, `ultra`;
  `normal` is no output style). Every call over the mesh comes from an agent tool, so it
  carries a calling agent and gets `agent_brevity`. `auto_clarity` keeps plain prose for
  warnings, destructive and ordered steps. Absent = on, with the defaults above; a partial
  block fills the missing fields with them, so `practices: {brevity: normal}` keeps
  `plan`, `clarify` and `auto_clarity` on. No value is `off`: YAML 1.1 readers (`kubectl`, Helm,
  PyYAML) read a bare `off` as the boolean `false`.
- **Telemetry**: OpenTelemetry export and what audit leaves the pod. `otlp_endpoint` is honoured
  only when the sidecar allows it (`--otlp-endpoint-allow`).
- `service.service_accounts`: the pods allowed to obtain this service's certificate run as the
  service account `<service.name>` or one of these.

Defaults are filled by `agentsc-charter` (`AgentSpec::harness_or_default`,
`learning_or_default`, `practices_or_default`, `LearningSpec::require_evidence_or_default`,
`contrast_runs_or_default`, `scopes_or_default`, `Charter::telemetry_or_default`); empty v0.2
lists, absent v0.2 blocks, an absent `practices` block and absent level-6 `learning` fields are
left out when a charter is serialized, so a v0.1 charter serializes exactly as before and a
level-2 `learning` block serializes as it did at level 2.

### 3.4 Custom resource form

A charter is also accepted as a Kubernetes custom resource; `Charter::from_yaml`,
`Charter::from_value` (and so `agentsc charter validate`) read both forms. A document with a
top-level `spec` or `metadata` is the resource form:

```yaml
apiVersion: agentsc.io/v1alpha1
kind: Charter
metadata:
  name: orders                 # must equal spec.service.name
  namespace: agentsc-demo      # spec.service.namespace defaults to it; if both are given they must be equal
spec:                          # the plain charter without apiVersion and kind
  service: { name: orders, app_port: 8080 }
  agents: [...]
```

Other `metadata` fields (labels, annotations, uid, …) are kept as they are and ignored; `status`
is written by embassy only and ignored when the charter is read; unknown fields anywhere else are
errors, as in the plain form. A namespace in neither place is an error. The 256 KiB limit
(§3.2 rule 7) applies to the charter `spec` describes (measured as in rule 7, so the same charter
passes or fails in both forms), not to `status` (which holds the service's memory and proposals)
or `metadata`; a resource document is not parsed beyond 3 MiB (`MAX_RESOURCE_BYTES`, the API
server's own request limit). A text over 256 KiB is parsed only when it may be the resource
form, that is when `spec` or `metadata` followed by `:` appears in it; any other is refused as
an oversized plain charter before it is parsed.

- `agentsc charter to-cr <file>` prints the resource form of a charter (`metadata` from `service`,
  `spec.service` without `namespace`); `Charter::to_resource` does the same in code.
- `agentsc charter schema --crd` prints the CustomResourceDefinition `charters.agentsc.io`
  (namespaced, `v1alpha1` served and stored, `status` subresource, printer columns Service,
  Version, Valid, Synced, Age). Its `spec` schema is the charter's JSON Schema made structural
  (references inlined, `Option` fields `nullable`, free-form values such as a tool's `parameters`
  `x-kubernetes-preserve-unknown-fields`); `status` has `observedGeneration`, `appliedVersion`,
  `conditions` (`Valid`, `Synced`), and free-form `memory` and `proposals`. **No pruning:** every
  object node (the root, `spec` and everything in it, `status`, the condition items) carries
  `x-kubernetes-preserve-unknown-fields: true`, so the API server never drops a field it does not
  know and the validating webhook, which rejects unknown fields, sees the resource exactly as
  written. The root `metadata` is the one exception: Kubernetes allows nothing there but rules
  for `name` and `generateName`. The output is committed as
  `deploy/crds/charters.agentsc.io.yaml`; a test keeps it in sync. The schema checks structure
  and ranges only: the charter validator (the validating webhook) is the authority.

### 3.5 Schema level and restart-only fields

- `Charter::schema_level()` is 1 for a charter that uses only v0.1 fields, 2 when it uses any
  v0.2 field (`skills`, `telemetry`, `service.service_accounts`, `agents[].skills`, `harness`,
  `learning`; empty lists count as unused), 3 when it uses a taint field (`agents[].taint`,
  `tools[].label`, `tools[].effect`), 4 when it uses `authz.taint`, 5 when it names a peer
  in another namespace (`<service>.<namespace>` as a tool's `service` or a `mesh.peers` key: no
  new field, but an older sidecar would take it for a service of its own namespace), and 6 when
  it uses a practices or level-6 learning field (`agents[].practices`,
  `agents[].learning.require_evidence`, `agents[].learning.contrast_runs`,
  `agents[].learning.scopes`).
  `Charter::level_fields()` lists each such field with its level (a tool once, at the highest).
  `CHARTER_SCHEMA_LEVEL` = 6 is the level this build understands (sent as `Hello.charter_schema_level`); the control
  plane refuses to push a field to a connected instance below its level, naming the field and
  the instances.
- The practices need no charter field to be on (§3.3), so a level-6 sidecar gives every agent
  the practices while an older sidecar (level 5 or below) running the same charter does not: in
  a mixed fleet the same agent behaves differently pod to pod until every sidecar is upgraded.
  The opt-out is a `practices` block. The control plane refuses it (400 `version_skew`) while an
  older sidecar of the service is connected, and an older sidecar rejects it in a ConfigMap
  charter as an unknown field, so it can be written only after the last old pod is gone; until
  then the upgraded pods run the defaults. The sidecar and the runtime ship in one image, so
  they always agree on `agent_spec_json` (§4.3).
- **Restart-only fields**: a hot reload may not change `service.name`, `service.namespace`,
  `service.app_port`, `mesh.port`, `audit.sink`, `audit.file` or `telemetry.otlp_endpoint`
  (`agentsc_charter::diff::restart_required` lists the ones that differ). A sidecar refuses such
  an update with `config.invalid`; the control plane refuses such a write with 400
  `config.restart_required` while instances are connected.
- `agentsc_charter::diff::weakened` lists the changes that reduce protection (§6, `config`
  records) and `agentsc_charter::diff::required_role` the role a change needs (viewer < editor <
  admin, with one `"<field> requires admin"` reason per field that needs admin; any change to
  `agents[].taint`, and setting or changing a tool's `label` or `effect`, needs admin; the
  level-6 fields need editor, and two of their changes are weakened, §6.1). A service with
  no stored charter has nothing to diff: `agentsc_charter::diff::first_charter_role` says that
  adopting a pending charter needs editor and a first `PUT` needs admin.

## 4. Wire protocol

Protobuf package `agentsc.v1alpha1` under `proto/agentsc/v1alpha1/`
(`common.proto`, `app.proto`, `mesh.proto`, `runtime.proto`). Generated Rust in
`crates/agentsc-proto`; generated Python in `runtime/src/agentsc_runtime/pb/`
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
| 503  | `denied`  | `audit.unavailable`: `--audit-fail-closed` and the audit sink is failing (§6) |

A tool call that is denied inside the run does **not** fail the invocation; it
is returned to the model as an error tool result, appears in `steps[]` with
`decision: deny`, and is audited.

**Questions** (level 6, `practices.clarify`, §3.3). A run that stopped to ask
the caller (`ask_caller`, §9) still ends with status `ok`; the response adds
`questions`, present only when there are any:

```json
{
  "status": "ok",
  "output": "I need these decisions from you before I go on:\n\n1. Refund to the card or as store credit?\n   Recommended: Store credit, because the card on the order has expired.",
  "questions": [
    { "question": "Refund to the card or as store credit?",
      "recommended": "Store credit, because the card on the order has expired." }
  ],
  …
}
```

`output` holds the same questions as text, so an app or a peer that knows
nothing about `questions` still shows them. The sidecar treats questions as
model output, in this order:

1. With `practices.clarify: never` it drops any questions the runtime sends.
2. It keeps at most `practices.max_questions` of them.
3. It runs `guardrails.output_deny` over each raw `question` and
   `recommended`, as the runtime sent it, and over the raw strings rendered
   in the format of §9. A match denies the whole invocation (403, output and
   questions withheld).
4. It redacts PII in each string when `pii_redact` is on, then cuts it to
   1000 characters. Redacting first means a cut can't leave half an e-mail
   address that the redaction no longer recognises.
5. It renders `output` from these delivered strings, in the format of §9, in
   place of the runtime's `output`, and runs `output_deny` again over each
   delivered string and over that `output`. A match denies as in step 3.
   The `agent_invocation` record (§6) holds `output`, so the audit log shows
   exactly the questions the caller got.

Steps 3 and 5 check the strings on both sides of the redaction and the
cut, so no match is lost to them, and the caller gets only text that was
checked. The runtime's own `output` is neither checked nor redacted: the
caller never gets it, and step 3 checks the sidecar's rendering of the raw
strings instead.

A non-`ok` status never carries questions.

The runtime keeps no state between invocations. The caller answers with a
new invocation that carries the original `input` and puts the questions and
its answers in `context`, for example
`{"answers": [{"question": "…", "answer": "…"}]}`, or writes them into the
`input`; the agent treats those decisions as settled and does not ask them
again. An app sets the request's `context`; a calling agent sets the
`context` argument of its agent tool (§3.1), which the sidecar passes on as
the callee's `context`, locally or over the mesh (§4.3). `context` passes the
input guardrails like any other (§5.1 step 3), whoever sent it.
Answers in `context` or `input` are vouched for by the caller. From an app,
the answering run is a new run and starts with only `taint.input` (§5.2),
whatever the run that asked had read. From an agent, local or over the mesh,
it is part of the calling run (the same `request_id`, §5.2), so it also starts
with every label the calling run has read; when that run got the questions,
those include what the asking run read, since a callee's labels come back
with its response. Answers an agent forwards from a tainted run never arrive
as trusted. For an agent with a `taint` block, an unattended app must not
send the recommended answers back on its own, since they may come from
untrusted data; it uses `clarify: never` for that agent, or has a person
answer.

Response headers always include `traceparent` and `x-agentsc-request-id`.

Also: `GET /v1/agents` → `{"agents":[{"name","type","model","tools":[...]}]}`,
`GET /v1/charter` → the loaded charter as JSON, `GET /healthz` → `200 ok`
(process up), `GET /readyz` → `200` once the charter is loaded, TLS is
loaded and the runtime answered `Health` (and, with `--audit-fail-closed`,
the audit sink takes writes); `503` otherwise. Body:
`{"ready", "runtime", "model_provider", "mesh", "charter", "cert_expires_in_s",
"audit": {"healthy", "fail_closed", "write_errors", "dropped", "pending_bytes",
"last_error"}}` (§6 "Sink failures").

An unknown agent is reported only after `authz.callers` passed: the app gets
`404 agent.unknown`, a peer not allowed for that name gets
`403 authz.callers.*` (no probing of agent names over the mesh).

gRPC equivalent on `127.0.0.1:50001`: `AppApi.InvokeAgent(InvokeAgentRequest)`
and `AppApi.ListAgents`. Denials map to `PERMISSION_DENIED` /
`RESOURCE_EXHAUSTED`, unknown agent to `NOT_FOUND`, runtime errors and
`audit.unavailable` to `UNAVAILABLE`; the JSON envelope above is the gRPC
message `InvokeAgentResponse`.
Questions are `repeated Question questions = 10` in it, with
`message Question { string question = 1; string recommended = 2; }` in
`common.proto`; the sidecar fills them for app and mesh callers, so a run
that asked returns them to a peer's sidecar too.

### 4.2 Sidecar ↔ sidecar (mesh, gRPC over mTLS, port 50002)

Metadata on every call: `traceparent`, `x-agentsc-request-id`,
`x-agentsc-agent` (calling agent). Caller identity is **only** taken from the
client certificate's URI SAN. `x-agentsc-agent` is a claim made by the
caller's sidecar (it is set by `agentscd`, never by the app or the model); the
callee cannot see the caller's charter, so it trusts the pair (SAN, agent)
exactly as far as its own `authz` rules say.

`x-agentsc-taint` (§5.2) carries the run's taint labels, `untrusted,sensitive`
(sorted, comma-separated, absent when the run is clean). The caller's sidecar
sends it on every mesh request; the callee of `InvokeAgent` adds the labels to
its record of that `x-agentsc-request-id` and returns the run's labels on a
successful response, which the caller adds in turn (`InvokeService` callees
ignore it). Only sidecars set it; unknown words are ignored. Labels only add
restrictions, so a peer gains nothing by lying.

- `Mesh.InvokeAgent(InvokeAgentRequest) → InvokeAgentResponse` — the callee
  runs `authz.callers` (identity SAN → agent) then the agent, same as a local
  invocation.
- `Mesh.InvokeService(ServiceRequest) → ServiceResponse` — the callee runs
  `authz.services` with `service = self`, `identity = SAN`, `agent =
  x-agentsc-agent`, then forwards `method path headers body` to
  `127.0.0.1:<service.app_port>` and returns status/headers/body. Denials
  return `PERMISSION_DENIED` with the rule name in the message and the
  metadata `x-agentsc-rule`.

### 4.3 Sidecar ↔ runtime (gRPC over Unix sockets)

`Runtime` (served by the runtime):

- `Execute(ExecuteRequest) → ExecuteResponse`. `agent_spec_json` is the agent's
  charter entry **after** the sidecar applied `guardrails.allowed_tools` (the
  model never sees a tool it may not call). `depth` is the agent-call nesting
  depth; the sidecar refuses depth > 4 (`budget.max_depth`).
  Since v0.2 it is `Charter::runtime_spec(agent, memory)`: that entry plus
  `skills: [{name, description, instructions, inline}]` (the agent's skills
  resolved, in its order; `inline` = instructions shorter than 2048 bytes),
  `harness` and `learning` with the defaults filled (§3), and
  `memory: [{id, text}]` (the agent's active notes, oldest first). Memory
  exists only for agents with `learning.enabled`: for any other agent
  `memory` is `[]`, whatever notes the sidecar holds, and `spec.py` drops
  notes that arrive for an agent without learning. Since level 6 it also
  carries `practices`, always and with every field filled (an agent without
  a `practices` block gets the defaults, §3.3), and `learning` carries the
  three level-6 fields, filled:

  ```json
  "practices": { "plan": true, "clarify": "blocking", "max_questions": 5,
                 "brevity": "lite", "agent_brevity": "full", "auto_clarity": true },
  "learning": { …, "require_evidence": true, "contrast_runs": 5, "scopes": ["invariant", "domain"] }
  ```

  An `agent` tool without `parameters` gets the default of §3.1 filled in, so
  the model is offered the `context` the sidecar forwards; `spec.py` falls
  back to the same schema.
  The runtime's `spec.py` parses exactly this (unknown fields are errors;
  `Practices` and the three `Learning` fields have the same defaults);
  `schemas/runtime-agent-spec.example.json` is a generated example that the
  Rust and Python tests both check.
  `ExecuteResponse.questions` (`repeated Question questions = 7`) holds the
  questions of a run that ended with `ask_caller` (§9), with status `ok`; the
  sidecar handles them as in §4.1 before any caller sees them.
- `Health(Empty) → HealthResponse{ok, model_provider: "anthropic"|"mock"}`.

`SidecarTools` (served by the sidecar on `sidecar.sock`, called by the runtime
for every tool call so the sidecar can authorize and audit it):

The sidecar does not trust the runtime (it is driven by a model). Every call
must belong to an Execute of `ctx.agent` for `ctx.request_id` that is in flight
(else `PERMISSION_DENIED`, rule `tool.unbound`: a made-up request id, another
agent's run, or a run that returned); the run's trace id and agent-call depth
replace the ones the runtime sent. Every call
must name a tool the agent declared and may use (`guardrail.allowed_tools`)
and must match that tool's declaration — same service and method (compared
uppercased), same agent target, same http origin, and a path that fits the
declared path or URL template (§3.1) — else `guardrail.tool_spec`.

- `InvokeService(ToolServiceRequest) → ServiceResponse` — tool check,
  `guardrail.allowed_services`, method and path canonicalisation (§5.1,
  `guardrail.path`), the template check (`guardrail.tool_spec`),
  `authz.services` with `identity = local`, `service = target`; then the
  local app (`service == self`) or the mesh.
- `InvokeAgent(ToolAgentRequest) → InvokeAgentResponse` — tool check; a local
  agent re-enters the invocation pipeline with `caller = local`,
  `caller_agent` set; a remote one goes over the mesh.
  `ToolAgentRequest {ToolContext ctx = 1; string target_service = 2; string target_agent = 3; string input = 4; string context_json = 5;}`:
  `context_json` is `""` or a JSON object, else `guardrail.tool_spec`. The
  sidecar passes it on as the callee's `context` (`InvokeAgentRequest.context_json`,
  locally or over the mesh), where it meets the callee's input guardrails and
  taint as an app's `context` does (§5.1, §5.2). The calling agent's
  `tool_call` and `agent_call` records then have `input = {input, context}`,
  like the callee's `agent_invocation` record. The mesh has always carried
  `context_json`, so a peer of an older build gets the context too.
- `InvokeHttp(ToolHttpRequest) → ServiceResponse` — tool check (origin must
  equal the declared URL's), canonicalisation of the URL's path and query
  (§5.1, `guardrail.path`), the template check against the declared URL's
  path (`guardrail.tool_spec`), then plain HTTP egress of the canonical URL,
  audited as `http_call`.
- `ReportEvent(AuditEvent{json}) → Empty` — the runtime's `model_call` records
  of the `mock` model (a provider's calls go through the model gateway, §4.4,
  which writes their records itself; a `model_call` record with any other
  callee is refused) and its `load_skill:<skill>` `tool_call` records. The
  sidecar stamps `service`, `namespace`, sets `cost_usd` from its price table
  (`mock` = 0, whatever the record said), redacts, and writes them.
- `ProposeLesson(LessonRequest) → LessonResponse` (v0.2) — a lesson the runtime
  drew from a finished run, for the agent's memory:
  `LessonRequest {ToolContext ctx = 1; string note = 2; string rationale = 3; string run_request_id = 4;}`,
  `LessonResponse {string decision = 1; string rule = 2; string reason = 3;}`.
  The sidecar checks that learning is enabled for `ctx.agent`, that the run's
  caller was `local` unless `learning.from_peers`, the rate limit
  `max_proposals_per_hour`, and that `note` is at most `max_note_chars`. It
  scrubs the note and the rationale (every value remembered for
  `run_request_id` by `audit.redact`, every withheld guardrail-denied input,
  then PII redaction), runs `guardrails.input_deny` on both (a match →
  `learning.denied`), and writes a `learning` record (§6). Managed, it sends a
  `LearningProposal` to the control plane, the only writer of memory;
  unmanaged with `mode: auto` it adds the note to its local memory; unmanaged
  with `mode: review` the proposal is only audited. Rules: `learning.proposed`,
  `learning.applied`, `learning.denied`, `learning.rate_limited`. Only the
  note becomes memory. The `rationale` (level 6) carries what else the
  reflection found (§9), with no payloads, only step ids, kinds and tool
  names, and a reviewer sees it next to the note. It is one line:

  ```text
  Reflection on a run that ended ok and used get_order. Scope: domain. Target: tool:get_order. Evidence: s2 call get_order; s3 result get_order (error). Compared with 2 earlier runs.
  ```

  A run that called no tool (it ended `denied` or `error`) reads `… and used
  no tools.`, a tool the charter doesn't declare shows as `undeclared`, and
  `Evidence: none.` stands for no cited step. The last sentence is left out
  when the reflection saw no earlier runs, and reads `Compared with 1 earlier
  run.` for one.

The sidecar adds `traceparent` (a child span) and `x-agentsc-request-id` to
every request it sends — local app, mesh, http tool — and, toward an app,
`x-agentsc-caller` and `x-agentsc-agent`. Values for `traceparent`,
`tracestate`, `host`, `content-length` and any `x-agentsc-*` header supplied by
the runtime or a peer are dropped, never forwarded.

The sidecar never follows a redirect. A 3xx from the local app (tool or mesh
forward) or from an http tool's origin goes back to the caller unchanged
(status, headers including `Location`, body): authz, the path canonicalisation
and the http origin check only ever saw the first URL. Requests toward the app
on loopback never use an HTTP(S) proxy; http tools use the environment's
proxy, if any.

Deadlines: a gRPC caller's `grpc-timeout` is honoured, and every call made on
its behalf carries what is left of it, less 500 ms, as its own `grpc-timeout`,
so the inner call gives up first and the outer one still answers and audits.
App gRPC or mesh `InvokeAgent` → runtime `Execute` (at most 300 s; the HTTP
API sets no deadline, so 300 s); `Execute` → the runtime's tool RPCs (at most
120 s for service and http tools, 300 s for agent tools) and its model
requests (at most 600 s; §9); a tool RPC → the peer over the mesh, or the local
app and http tools (at most 30 s).

Outcomes, for all three tool RPCs (message = reason, metadata `x-agentsc-rule`):

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

### 4.4 Runtime → model gateway (HTTP over `unix:/run/agentsc/model.sock`)

Every model call of the runtime goes out through the sidecar. The runtime is
driven by a model and is not trusted with spend: it holds no provider key and
reports no cost. The runtime's Anthropic SDK is pointed at the socket
(`AGENTSC_MODEL_GATEWAY`, which the sidecar sets for the runtime it starts;
default `model.sock` next to `--sidecar`) with a placeholder key.

- `GET /v1/agentsc/providers` → `{"providers": ["anthropic"]}`: the providers
  the sidecar can call (a key, or the platform's model gateway in the LLM
  connection contract's gateway mode, docs/LLM-CONNECTION.md). Empty → the
  runtime runs every agent on `mock`.
- `POST /v1/messages` — the Anthropic Messages API. The call names its run with
  `x-agentsc-request-id` and `x-agentsc-agent`; `x-agentsc-attempt` (`1`, `2`,
  …, `fallback`) and `x-agentsc-purpose: reflection` only label its record. The
  sidecar refuses, before anything leaves the pod:
  - a call of no run: no Execute of that agent for that request in flight, and
    not the one reflection after it returned (in the run window, when the agent
    learns from the run's caller) — `model.unbound`;
  - a `model` other than the agent's `model` or `harness.fallback_model` —
    `model.not_allowed`;
  - `max_tokens` above `budgets.max_tokens_per_call` — `budget.max_tokens_per_call`;
  - more than `max_steps × (1 + max_retries + 1 if a fallback)` calls in the run,
    or a request that already has `max_steps` assistant turns — `budget.max_steps`;
  - a request field outside `model, max_tokens, messages, system, tools,
    tool_choice, stream, stop_sequences, metadata, thinking, output_config,
    temperature, top_p, top_k` (the sampling fields do not change the price;
    `fallbacks` is refused, since it may answer with, and bill, another model:
    onto-intelli sets `llm.fallbacks = false` in gateway mode), or a server tool
    (a `tools[]` entry with a `type` other than `custom`, billed outside the
    token price) — `model.request_invalid` (HTTP 400);
  - with less than 500 ms left of the Execute's deadline — `deadline.exceeded`;
  - a content block whose `source` is a URL (the provider would fetch it,
    outside the tool policy, at a size nobody knows yet) — `model.request_invalid`;
  - when the agent's spend today, plus what its calls in flight hold, plus the
    most this call can cost (its request bytes + 4096 input tokens, or the
    model's whole context window when the request carries an image or a
    document, priced as 1-hour cache writes, and `max_tokens` output tokens)
    would exceed `max_cost_usd_per_day` — `budget.max_cost_usd_per_day`.

  A refusal is HTTP 403 (400 for a request it cannot take) with the provider's
  error body (`permission_error` / `invalid_request_error`, message
  `<rule>: <reason>`) and `x-agentsc-rule`, and an `authz` record (`budget` for
  a `budget.*` rule). Otherwise the sidecar sends the body unchanged to
  `--anthropic-base-url` with its own `x-api-key` (the runtime's `x-api-key`,
  `authorization` and `anthropic-beta` are dropped), at most until the
  Execute's deadline less 500 ms (600 s at most), and streams the answer back as
  it arrives: status, headers (`retry-after` included) and body, so the
  runtime's SDK and harness see exactly what the provider sent. A successful
  answer carries `x-agentsc-rule: budget.max_cost_usd_per_day` once the day's
  budget is spent.
- The sidecar reads the answer for its usage (`message_start`, `message_delta`;
  input, output, cache read and cache write tokens) and content, prices it
  from the one table in `crates/agentsc-common/src/pricing.rs` (per 1M tokens;
  cache reads and writes at their own rates; unknown model ids at the top tier),
  replaces the call's hold with that cost, and writes its `model_call` record.
  Only a whole answer (a stream that reached `message_stop` without an `error`
  event, or a non-streamed body with its `usage`) is counted at its usage; an
  error status or a connection never made counts nothing; an answer cut before
  it completed (the deadline, a timeout, a broken connection, a mid-stream
  error) is counted at its hold, since the provider may bill more than it had
  reported. The record
  (§9 shape; `callee: anthropic:<model>`, `parent_span_id` = the invocation's
  span). A call whose runtime went away is read to the end and counted (the
  provider bills it), with `error: "cancelled: …"`. A failed call counts what
  the provider had reported.
- The invocation's answer and its `agent_invocation` record carry the usage and
  cost the gateway measured, never the runtime's. When the gateway refused one
  of the run's calls for a budget and the run did not end `ok`, that budget is
  the outcome: `budget.max_cost_usd_per_day` → `denied` (429),
  `budget.max_steps` / `budget.max_tokens_per_call` → `error` (502).

Provider adapters implement one interface (`services/agentscd/src/gateway`:
request check, upstream request, usage meter). Anthropic is the one shipped;
an OpenAI-compatible adapter (`POST /v1/chat/completions`) is the next.

## 5. Identity, mTLS, authz

- Trust domain: `--trust-domain` / `AGENTSC_TRUST_DOMAIN` on `agentscd` and on
  every `embassy` command that issues or checks identities (Helm value
  `trustDomain`, which also reaches injected sidecars), default `agentsc`; a
  SPIFFE trust domain name (`a-z 0-9 . - _`, 1..=255). SPIFFE ID
  `spiffe://<trust domain>/ns/<namespace>/svc/<service>`; the control plane is
  `spiffe://<trust domain>/control-plane`. Sidecars and embassy of one install
  must agree on it: an identity in another trust domain is no identity (a
  sidecar refuses such a `--tls-dir` certificate, a peer's client certificate
  and a control plane; `Connect` refuses such a sidecar). Charters name peers
  in the install's trust domain (`authz.callers[].identity`,
  `authz.services[].identity`: `local` or any `spiffe://` URI validates).
- `embassy` holds one CA per cluster: Secret `agentsc-ca` (`ca.crt`, `ca.key`)
  in the demo namespace. Leaf certs: Secret `agentsc-cert-<service>` with
  `ca.crt`, `tls.crt`, `tls.key`. Leaf SANs: URI = the SPIFFE ID; DNS =
  `<service>`, `<service>.<ns>`, `<service>.<ns>.svc`,
  `<service>.<ns>.svc.<cluster domain>` (`--cluster-domain`, default
  `cluster.local`). CA TTL 10 years, leaf TTL 365 days
  (MVP: no rotation; re-running the Job keeps the CA and re-issues leaves).
- Mesh server: rustls, requires a client certificate chained to `ca.crt`.
  Caller identity = the first URI SAN of the client leaf that is a workload ID
  in the trust domain; a certificate without one is rejected
  (`authz.identity.invalid`, reason `client certificate has no
  spiffe://<trust domain>/ns/<ns>/svc/<svc> URI SAN`).
- Mesh client: verifies the server against the mesh CA roots and by identity:
  the server's only URI SAN must be the SPIFFE ID of the service the charter
  names, `spiffe://<trust domain>/ns/<namespace>/svc/<service>`. The name sent
  for SNI decides nothing. It presents its own leaf.
- In the kustomize manifests (§7) the certificate is **per service** (every
  replica of a Deployment shares the Secret), issued by the bootstrap Job. A
  managed sidecar (every pod the Helm chart's webhook injects, §7) makes its
  own ECDSA P-256 key instead and gets a per-pod leaf from a running
  `embassy` (`CertificateAuthority.IssueCertificate`, with its Kubernetes or
  join token), valid for `issuance.workload_cert_ttl` (24 hours by default)
  and renewed from two thirds of its lifetime without a restart.

### 5.1 Authz evaluation order (callee side, inbound)

1. `authz.callers`: find rules whose `identity` equals the caller (`local` or
   the SAN); the agent is allowed if any such rule lists it or `"*"` **and**
   the rule's `caller_agents` is empty or contains the calling agent (the
   caller sidecar's `x-agentsc-agent` claim; for local agent calls, the local
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
5. Guardrails on output, over `output` or, for a run that asked (§4.1), over
   each raw string of `questions`, their rendering, each delivered (redacted,
   cut) string and the `output` rendered from them:
   `guardrail.output_deny.<name>` → deny on any match;
   `guardrail.pii_redact` → rewrite, decision stays `allow`.

`authz.services` matching: a rule applies when its `identity` (if set) equals
the caller identity, its `agent` (if set) equals the calling agent and its
`service` equals the target. Among applying rules, any `deny` match wins
(`authz.services.<rule-name>`); else any `allow` match allows
(`authz.services.<rule-name>`); else `authz.default`. When no rule applies,
`authz.default` (`authz.default.deny` / `authz.default.allow`). A pattern is
`"<METHOD> <path>"` with `*` as the method wildcard and an optional trailing
`*` on the path (`/stock/*` matches `/stock/x` and `/stock/x/y`, not `/stock`).
Patterns meet the canonical method and path (below), and:

- one trailing `/` on the path is ignored: `/x/` is `/x`, so `* /admin`
  denies `POST /admin/`, and `/stock/*` matches neither `/stock` nor `/stock/`;
- a `GET` pattern also matches `HEAD` (routers answer HEAD with the GET
  handler); a `HEAD` pattern matches only `HEAD`;
- `deny` patterns ignore ASCII case in the path (`* /admin` denies `/ADMIN`,
  as many routers ignore case); `allow` patterns do not, so a case variant of
  an allowed path is never allowed by accident;
- the query is never matched.

A deny list is a backstop for the spellings above, not a sandbox: `default:
deny` with narrow `allow` patterns is the posture to rely on.

Canonicalisation (`guardrail.path`): before any `authz.services` match, on
both sides, the method is uppercased and must be one of `GET`, `POST`, `PUT`,
`PATCH`, `DELETE`, `HEAD`, `OPTIONS`, and the path is made canonical:
percent-escapes of unreserved characters (`A–Z a–z 0–9 - . _ ~`) are decoded
(`/%61dmin` is `/admin`) and every other escape gets uppercase hex; then the
path is resolved with the same WHATWG URL parser the sidecar uses to send the
request, so `.`/`..` and percent-encoded dot segments (`%2e%2e`) are removed —
`/stock/../admin/reset` is matched, audited and sent as `/admin/reset`.
Denied with `guardrail.path`: a path that does not start with `/`; whitespace,
a control character, `\` or `#` anywhere; in the path component (not the
query, where they are only data) an encoded `/`, `\` or NUL (`%2f`, `%5c`,
`%00`), a `%` that does not start an escape, and a literal `;`; and an empty
segment (`//`). The `;` rule is for path parameters (RFC 3986 §3.3): Tomcat,
Spring and Jetty cut `;…` off each segment before routing, so `/admin;x/reset`
would reach their `/admin/reset` and `/stock/..;/admin` their `/admin`, while
Go and Starlette route the segment as written. Rather than guess which router
the app runs, the sidecar refuses the spelling. Those routers split on the raw
`;` before decoding, so an escaped `%3B` is data to all of them and is kept
(the runtime sends a `;` in a value that way); a `;` in the query is data too.
The canonical method and path are what is authorized, audited and sent.

`identity: local` in `authz.services` matches calls made by this pod's own
agents (egress and self calls); a SPIFFE identity matches inbound calls from
that peer.

### 5.2 Taint rules (caller side, every tool call)

Design: [docs/design/taint-policy.md](docs/design/taint-policy.md).

The sidecar keeps, per `request_id`, the set of labels the run has read and
the tools they came from. A label is added:

- when an invocation of an agent with `taint` starts: `taint.input` (source `input`);
- when a `service`, `http` or `agent` tool call succeeds: the tool's `label`
  (source: the tool name);
- from `x-agentsc-taint` on an inbound `InvokeAgent` (source `caller <identity>`)
  and on an `InvokeAgent` response (source `agent <name>`).

`trusted` adds nothing. Labels are never removed; a run's set is forgotten 15
minutes after its last change. The state is in memory, per sidecar.

For an agent with a `taint` block, each `InvokeService`, `InvokeAgent` and
`InvokeHttp` tool RPC is checked right after the tool is resolved
(`guardrail.allowed_tools`), before any other rule:

| rule | the run has read | the tool |
| ---- | ---------------- | -------- |
| `taint.untrusted_write` | `untrusted` | has `effect: write` |
| `taint.sensitive_egress` | `sensitive` | has `type: http` |

The effect is the charter's (`effect`, or the default from the declared
method), never the request's. With `mode: enforce` the call is denied
(`PERMISSION_DENIED`, a `deny` record with the rule, reason `this run read
untrusted data (from read_ticket) and tool issue_refund writes`). With `mode:
audit` it goes on, after a `guardrail` record with decision `allow` and rule
`taint.would_deny.untrusted_write` / `taint.would_deny.sensitive_egress`.

Learning: a lesson (`ProposeLesson`) from a run that has read `untrusted` data
never becomes a note on its own. With an enforcing `taint` block it is refused
(`learning` record, decision `deny`, rule `taint.untrusted_learning`); with
`mode: audit` a `guardrail` record names `taint.would_deny.untrusted_learning`;
in every case `learning.mode: auto` falls back to review for that lesson
(`learning.proposed`, the reason names the sources).

Inbound (callee side, schema level 4): with `authz.taint` in the callee's
charter, a peer's `Mesh.InvokeService` that carries `x-agentsc-taint` with
`untrusted` and a method other than GET, HEAD or OPTIONS is checked after
`authz.services`: `enforce` refuses it (`PERMISSION_DENIED`, a `service_call`
deny record, rule `taint.untrusted_write`); `audit` lets it through after a
`guardrail` record with rule `taint.would_deny.untrusted_write`. The caller's
sidecar sends the run's labels on every mesh call.

### 5.3 Agent principals and the registry

An agent is a principal of its own, named as Tutela names principals:
`agent:agt_<uuidv7>` (`agt_` and a UUIDv7 in its 36-character lowercase form, version digit
`7`, variant digit `8`, `9`, `a` or `b`; `agentsc_common::principal`). A workload principal is
`workload:spiffe://<trust domain>/ns/<namespace>/svc/<service>`, the identity of §5: the path
names a service, not a service account (Tutela's own examples use `/sa/<sa>`; f8fvwgzc/tutela#29).
Design: [docs/design/agent-registry.md](docs/design/agent-registry.md).

- **The registry is embassy's** (it is the system of record of agents). It keeps one row per
  `(namespace, service, agent name)`: the id, `status` (`active` | `retired`), `created_at`,
  `updated_at` and aliases. The SQLite and PostgreSQL stores keep it (migration 2); `--store
  file:<dir>` keeps it in `<dir>/.secops.sqlite3`; `--store kubernetes` keeps it where
  `--secops-store sqlite:<path> | postgres` says, and has none without it.
- **Ids are minted by the charter.** When a stored charter (any write path: API, adoption,
  rollback, a file-store edit, a Charter CR change, another replica) first declares an agent,
  embassy mints its id. An agent the charter no longer declares (or whose service is deleted) is
  `retired`; declared again, it is `active` again **with the same id**. An agent is never
  deleted and an id never changes or names another agent (store triggers refuse it). A charter
  that cannot be read retires nothing. Each change is a control-plane audit record
  (`agent_registered`, `agent_reactivated`, `agent_retired`; `reason` = the principal), by the
  charter write's actor (`embassy:registry` for the sync at start-up).
- **Aliases.** An agent may have up to 16 aliases, `<scheme>://<name>` (a lowercase scheme, no
  whitespace, at most 256 bytes; nexc-engine's `agent://<workspace>/<name>`), each naming one
  agent. Adding or removing one needs admin and is audited (`agent_alias_put`,
  `agent_alias_delete`).
- **Sidecars get the ids.** After the charter and memory of a `Connect` stream, and whenever
  the registry changes for its service, embassy sends `ControlMessage.agent_ids` (`AgentIds`:
  agent name → id of the active agents; a full replacement, not acknowledged). The sidecar
  writes the id as `agent_id` on every audit record of that agent (§6); embassy fills it on
  records that arrive without it.
- **API** (`/api/v1`, docs/api/openapi.yaml): `GET /agents?namespace=&service=&status=`,
  `GET /agents/{id}`, `GET /principals?principal=` (an agent principal, an alias, or a workload
  principal with its active agents), `POST /agents/{id}/aliases` `{"alias"}` and `DELETE
  /agents/{id}/aliases?alias=` (admin). An agent outside the caller's namespaces is `404`;
  without a registry the answer is `503 secops_unavailable`.
- **Not yet:** creating and disabling the principal in Tutela (`tutela.admin.v1`, Tutela
  phase B, #24) and delegated agent tokens (RFC 8693 token exchange at `tutelad`, #25); both
  wait for `tutelad`.

## 6. Audit record

One JSON object per line, written by `agentscd` only (sink `stdout`, readable
with `kubectl logs -c agentscd`, or `file`). Field order is fixed as below so
`grep` and humans see the same thing.

**Sink failures.** A write or flush error is never ignored. The line the sink
did not take is kept and written first by the next attempt, resuming at the
first byte not taken (so no line is written twice or cut); up to 4 MiB is
kept, a record beyond that is not (counted as `dropped`). The sink is
unhealthy from the first failure until that backlog is written and flushed.
Attempts: every later write, every `GET /readyz`, and a retry once a second.
Failures are logged on stderr (the first at once, then at most one summary
every 10 s, and the recovery) and reported in the `/readyz` body (`audit`).
Subscribers (§6.2) get every record, also one the sink did not take.

With `--audit-fail-closed` (off by default) an unhealthy sink stops new work:
an invocation from the app (`503`, `status: denied`, rule
`audit.unavailable`; gRPC `UNAVAILABLE`), a peer's `InvokeAgent` /
`InvokeService` and the runtime's `InvokeService` / `InvokeAgent` /
`InvokeHttp` / `ProposeLesson` are refused (`UNAVAILABLE`, `x-agentsc-rule:
audit.unavailable`), and `/readyz` answers `503`. Each refusal writes its own
record (`agent_invocation`, `service_call` inbound or `tool_call`, `decision:
deny`, rule `audit.unavailable`; a refused `ProposeLesson` writes none), which
is itself an attempt: the first attempt that writes the backlog ends the
refusals. Work that already started finishes and its records are written or
kept; `ReportEvent` is never refused (the model call it reports already ran
and was billed).

```json
{
  "ts": "2026-10-20T19:02:11.482Z",               // the step's END time (RFC 3339, ms); start = ts − latency_ms
  "kind": "agent_invocation | model_call | tool_call | agent_call | service_call | http_call | authz | guardrail | budget | config | learning",
  "request_id": "0c4a3f8e-…",             // one per top-level invocation, propagated unchanged across hops
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",   // W3C, propagated via traceparent
  "span_id": "00f067aa0ba902b7",           // this hop
  "parent_span_id": "b7ad6b7169203331",    // or null
  "service": "orders", "namespace": "agentsc-demo",
  "agent": "ops-assistant",                // the agent this record belongs to (null for pure authz failures before resolution)
  "agent_id": "agt_0193a1b2-c3d4-7b33-9c44-5d6e7f809102", // its registry id (§5.3); left out when the sidecar has none
  "caller": "local | spiffe://agentsc/ns/agentsc-demo/svc/orders",
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
  "rule": "authz.services.deny-admin | guardrail.input_deny.no-secrets | budget.max_calls_per_minute | taint.untrusted_write | clarify.asked | null",
  "reason": "human readable or null",
  "error": "string or null"
}
```

Redaction, in this order, over the full payloads:

1. `input_sha256` / `output_sha256` are computed over the full original bytes,
   so a consumer can prove a payload later without the sidecar storing it.
   A payload a content guardrail denied is then withheld whole: it is written
   as `"[redacted:<rule>]"`, only its hash remains. That is the invocation's
   input (with its `context`) in the `guardrail` and `agent_invocation` records
   of a `guardrail.input_deny.*` denial, the final output in the `guardrail`
   record of a `guardrail.output_deny.*` denial (for a run that asked, the
   question string or rendering that matched, §4.1), and the input of the
   calling agent's `tool_call` / `agent_call` records (with its `context`) when
   the callee's input rule denied it. The denied input is also scrubbed
   (`[redacted]`) from every later record of the same request in that sidecar,
   like the values in step 2; a denied agent tool `context` also value by
   value, since the calling agent's next prompt quotes it as JSON.
2. `audit.redact` dotted paths are replaced with `"[redacted]"` inside
   `input`/`output` (arrays are walked). Values found at those paths (strings
   and numbers of 4+ characters) are also remembered per `request_id` for 15
   minutes and scrubbed from every later record of the same request in that
   sidecar — they reappear as text inside model prompts and tool results —
   in `input`/`output` and in the text fields `callee`, `reason` and `error`
   (a callee such as `GET https://api.example.com/x?ssn=…`, an error that
   echoes the input).
3. `guardrails.pii_redact` rewrites emails to `[redacted:email]` and phone
   numbers to `[redacted:phone]` in the agent's output returned to the caller
   **and** in every string of every audit `input`/`output`, `callee`, `reason`
   and `error` that sidecar writes. The record's shape and field order do not
   change: only string values are rewritten, `null` stays `null`.
4. Payloads larger than 8 KiB are truncated to 8 KiB plus
   `…(truncated, N bytes)` — after redaction, so a cut never exposes part of a
   redacted value.

A mesh call refused for its certificate (`authz.identity.invalid`) is audited
as kind `authz` with `caller: "unknown"`.

The `agent_invocation` record of a run that asked the caller (`ask_caller`,
§9) has decision `allow`, rule `clarify.asked` and the questions, as text, in
its `output`. The sidecar renders that `output` from the questions it keeps,
after the guardrails and redaction of §4.1, so it is exactly what the caller
got. `ask_caller` writes
no `tool_call` record of its own; it shows in `steps[]` and in the
`model_call` record of the turn that called it.

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
comes after its children's, and `ts` is that end time (a record's start is
`ts − latency_ms`). A step whose handler is dropped before it finishes
(the client disconnected, its deadline passed, the peer reset the stream)
still writes the records it owes — `agent_invocation`; `tool_call` plus its
`service_call` / `agent_call` / `http_call`; an inbound `service_call` — with
the decision it was authorized with and `error: "cancelled: the caller went
away or its deadline passed before this finished"`. The target may already
have acted on it. That cancel guard stamps `ts` when it writes.

And the denied call: on the inventory pod `service_call inbound
spiffe://…/svc/orders (ops-assistant) → inventory POST /admin/reset deny
rule=authz.services.deny-admin`; on the orders pod the matching `tool_call`
with `decision: deny` and the same `request_id` and `trace_id`.

### 6.1 `config` and `learning` records (v0.2)

| kind | agent | caller | callee | direction | input | output | rules |
| ---- | ----- | ------ | ------ | --------- | ----- | ------ | ----- |
| `config` | null | `control-plane` or `file` | `charter` / `memory` / `certificate` | internal | `{source, epoch, version, sha256, weakened: [paths]}` | null | `config.applied`, `config.invalid`, `config.restart_required`, `cert.issued`, `cert.renew_failed` |
| `learning` | the agent | `local` | `learning` | internal | `{request_id_of_run}` | `{note, rationale}` (after scrubbing) | `learning.proposed`, `learning.applied` (auto), `learning.denied`, `learning.rate_limited` |

`weakened` lists the changes that reduce protection, as paths
(`agentsc_charter::diff::weakened`): a removed `audit.redact` path
(`audit.redact[<path>]`), `guardrails.pii_redact` true → false,
`telemetry.export_payloads` false → true, `authz.default` deny → allow, and a
removed `input_deny` / `output_deny` rule (`guardrails.input_deny[<name>]`; a
rule whose regex changed counts as removed). Taint (§5.2): a removed
`agents.<a>.taint`, `agents.<a>.taint.mode` enforce → audit,
`agents.<a>.taint.input` and `agents.<a>.tools.<t>.label` changed away from
untrusted or sensitive (each guards a different rule), `agents.<a>.tools.<t>.effect`
write → read. Level 6 (§3.3): `agents.<a>.practices.auto_clarity` true →
false and `agents.<a>.learning.require_evidence` true → false; both compare
effective values, so an absent block or field counts as true.

**Unknown kinds.** A consumer that sees a `kind` it does not know keeps the
record and shows the kind as written: `agentsc logs` and embassy never reject a
record for its kind (`agentsc logs --kind <any>` filters on it as a string,
`--raw` prints the line as it was read).

**Reading records of other versions.** Consumers that read records another
sidecar version may have written (the CLI, embassy, the OpenTelemetry
exporter) use the lenient `agentsc_common::audit::AuditRecordView`: `kind`,
`direction` and `decision` are strings; `tokens` (`TokensView`) accepts
counts it does not know and keeps them; unknown top-level fields are kept in
`extra` (`#[serde(flatten)]`) and serialized again unchanged, after the known
fields in the order above. The fields that identify a record (`ts`, `kind`,
`request_id`, `trace_id`, `service`, `caller`, `callee`, `direction`,
`decision`) are required, so a JSON line that is not a record does not parse;
the others default when absent. `AuditRecordView::from(&AuditRecord)` gives
the same JSON as the record; `known_kind()` maps `kind` to the kinds this
build knows.

### 6.2 Subscribing to the audit stream

`AuditWriter::subscribe() → tokio::sync::broadcast::Receiver<Arc<AuditRecord>>`
delivers every record written after the call — for every sink (`stdout`,
`file`) — after redaction and truncation, exactly as written and in the sink's
order. The channel holds 4096 records: a receiver that falls further behind
loses the oldest (`RecvError::Lagged(n)`), and the writer never waits for a
receiver. The OpenTelemetry exporter and the control-plane client use it; what
leaves the pod has therefore always been redacted and truncated first.

`AuditWriter::set_redaction(paths, pii_redact)` replaces the `audit.redact`
paths and the `guardrails.pii_redact` switch in place, for a charter hot
reload: every record written after the call uses the new settings (each
record is redacted with one consistent snapshot), and the writer, its sink,
the values it remembered for open requests and its subscribers are unaffected.
`AuditWriter::redaction()` returns the settings in force.

### 6.3 The evidence ledger

Audit records become evidence when embassy chains and seals them (design:
[docs/design/evidence-ledger.md](docs/design/evidence-ledger.md); the format is the crate
`agentsc-ledger`, so embassy and `agentsc verify` share one definition).

- **Chains.** A chain is one run: the records of one `request_id`, across every service and hop,
  in the order embassy took them in. Records without a `request_id` (`config`) chain per service
  as `service:<namespace>/<service>`. Entry `seq` (from 0) holds `ingested_at` (when embassy took
  it in), the `record`, `prev_hash` and `hash`:

  ```
  hash = hex(SHA-256("agentsc-ledger-entry-v1" 0x00 ‖ prev_hash (32 bytes) ‖ canonical({chain, ingested_at, record, seq})))
  ```

  The first entry's `prev_hash` is 64 zeros. `canonical(v)` is compact JSON with every object's
  keys sorted bytewise (strings and numbers as `serde_json` writes them), so a re-indented or
  reordered copy hashes the same.
- **Seals.** A seal signs `{chain, entries, head, kid, sealed_at, type: "agentsc.ledger_seal.v1"}`
  (the canonical text, kept exactly as signed) with Ed25519: it says entries `0..entries` of the
  chain end in `head`. `kid` is the RFC 7638 thumbprint of the public key
  (`base64url(SHA-256({"crv":"Ed25519","kty":"OKP","x":"<base64url key>"}))`). Public keys are a
  JWKS: `{kty: "OKP", crv: "Ed25519", x, kid, alg: "EdDSA", use: "sig", status: "current" |
  "retired"}`; a retired key's seals still verify.
- **Bundles.** One chain's evidence: `{format: "agentsc-evidence-bundle/v1", exported_at,
  chain, entries: [{seq, ingested_at, record, prev_hash, hash}], seals: [{statement, signature
  (hex), kid}]}`.
- **`agentsc verify <bundle> (--keys <jwks.json> | --key <public key>) [--json]`** runs every
  check whatever the others find: `format`; `chain` (entries `0..n` in order, each following the
  one before and hashing to its hash, at least one); `seals` (each seal parses, names its key,
  the key is published under its thumbprint, the signature holds over the exact statement, it is
  about this chain, its head is the hash of its last entry; and one seal covers every entry). It
  prints `chain <id>`, one `ok`/`FAIL` line per check and the verdict, or with `--json`
  `{ok, chain, checks: [{name, ok, detail}]}`; exit 0 when the bundle verifies, 1 when a check
  fails, 2 when the bundle or the keys cannot be read. An edited record fails `chain`; a record
  taken off the end or added after the last seal fails `seals`; a removed or reordered one fails
  both; an edited statement or a wrong key fails `seals`.

## 7. Kubernetes packaging

`deploy/` is a kustomize tree, applied with `kubectl apply -k deploy/`:

- `namespace.yaml` — `agentsc-demo`.
- `embassy/` — ServiceAccount, Role (`secrets: get, create, update`),
  RoleBinding, Job `embassy-bootstrap` running
  `embassy bootstrap --namespace agentsc-demo --services orders,inventory`.
- `orders/`, `inventory/` — Deployment with two containers (`app`,
  `agentscd`) and a Service exposing the app port and `mesh` 50002. The
  charter ConfigMap `<svc>-charter` (key `charter.yaml`) is created by
  `make charters` from `examples/charters/<svc>.charter.yaml`, the single
  committed copy, and mounted at `/etc/agentsc/charter/`. The TLS Secret is
  mounted at `/etc/agentsc/tls/` (sibling, never nested in the read-only
  ConfigMap mount).
- Labels: `app: <svc>`, `agentsc.io/service: <svc>`. `agentsc logs` selects
  on `agentsc.io/service`.
- Images (built inside minikube's docker): `agentsc/agentscd:dev`
  (sidecar binary + Python runtime in one image), `agentsc/embassy:dev`,
  `agentsc/orders:dev`, `agentsc/inventory:dev`. `imagePullPolicy: IfNotPresent`.
- The inventory app listens on `127.0.0.1` inside its pod and its Service
  exposes only `mesh`: every other pod reaches it through the sidecar. (The
  orders app keeps its HTTP port because it is the demo's entry point.)
- Optional Secret `agentsc-anthropic` (`ANTHROPIC_API_KEY`), referenced with
  `optional: true`; without it every agent runs on the mock model.
- Sidecar injection is **explicit** in the MVP: the `agentscd` container, the
  charter ConfigMap mount and the TLS Secret mount are written in each
  Deployment. The v0.2 Helm chart (`deploy/helm/agent-sidecar`, design §13)
  injects instead, on the pod label `agentsc.io/inject: "true"`:
  - two native sidecars, `agentsc-runtime` first (command `agentsc-runtime
    --listen unix:/run/agentsc/runtime.sock --sidecar
    unix:/run/agentsc/sidecar.sock`, only the `agentsc-run` emptyDir, no
    env), then `agentscd` with `AGENTSC_NO_RUNTIME=true`, its state in its
    own emptyDir `agentsc-state` (`AGENTSC_STATE_DIR`) and the only
    `ANTHROPIC_API_KEY`. The runtime cannot read the sidecar's key or
    environment;
  - a pod that brings its own `agentscd` or `agentsc-runtime`, mounts the
    sidecar's volumes elsewhere, projects another `agentsc`-audience token or
    sets `shareProcessNamespace`/`hostPID` is refused at admission;
  - with the sidecar image allow-list on (ControlPlaneConfig
    `sidecar_images.allowed_digests`; Helm `images.agentscd.digest`,
    `injection.allowedImageDigests`; empty = off, for development builds,
    and embassy warns at start-up), only images pinned to an allowed digest
    are injected, IssueCertificate and every renewal refuse pods whose
    running sidecar `imageID` is not allowed, and the ValidatingAdmissionPolicy
    `agentsc-sidecar-integrity` (Kubernetes 1.30+) refuses such pods, sidecar
    image changes and ephemeral containers;
  - with the allow-list on, IssueCertificate also refuses a pod whose sidecars
    differ from the injected shape (`agentscd` env, `AGENTSC_CA_PEM` with other
    certificates than the CA's roots, `envFrom`, lifecycle hooks, probes, mounts,
    volume types, a missing `agentsc-runtime`, `hostAliases`, `dnsPolicy: None`,
    `dnsConfig` nameservers or searches), and the policy
    refuses sidecar containers in pods without the label
    `agentsc.io/inject: "true"`, so the injector checks every pod that has them.

## 8. CLI

```
agentsc charter validate <file>        # plain or resource form (§3.4); exit 0 "valid", exit 1 with one error per line
agentsc charter schema                 # JSON Schema to stdout (== schemas/charter.schema.json)
agentsc charter schema --crd           # the CustomResourceDefinition charters.agentsc.io, YAML (== deploy/crds/charters.agentsc.io.yaml)
agentsc charter to-cr <file>           # the charter as a `Charter` custom resource, YAML; exit 1 if the charter is invalid
agentsc logs <svc>[,<svc>…] [-n NS] [--context C] [--agent A] [--trace T] [--request R] [--kind <any kind>] [--rule PREFIX] [--denied] [-f] [--raw] [--file F|-] [--tail N]
agentsc verify <bundle|-> (--keys <jwks.json> | --key <public key>) [--json]   # an evidence bundle, offline (§6.3); exit 0 verifies, 1 a check fails, 2 unreadable
agentsc version
```

`agentsc charter to-cr` validates the file (either form) and prints the
resource form: `metadata: {name, namespace}` from `service`, everything else
under `spec` (`spec.service` without `namespace`); `to-cr` of its own output
prints the same document. `agentsc charter schema --crd` prints the CRD of
§3.4, generated from the Rust types.

`agentsc logs` runs `kubectl logs -n NS -l 'agentsc.io/service in (<svcs>)' -c
agentscd --tail N [-f]`, keeps only lines that parse as §6 records (sidecar
diagnostics share the container log on stderr and are skipped), applies the
filters (`--trace`/`--request`/`--rule` match by prefix; `--agent` matches `agent` or
`caller_agent`), sorts by `ts` unless following, and prints one line per
record. Records of any sidecar version are read (`AuditRecordView`, §6.1): a
kind, direction or decision this CLI does not know is shown as written, and
`--kind` takes any kind as a string — the v0.2 ones (`config`, `learning`)
and kinds of newer sidecars alike. A table line:

```
19:02:11.482 orders    ops-assistant   agent_invocation inbound  local → ops-assistant            allow            1412ms
19:02:12.904 inventory stock-analyst   service_call     inbound  …/svc/orders → inventory POST /admin/reset   DENY authz.services.deny-admin 4ms
```

`--raw` prints each matching record's JSON exactly as it was read (unknown
fields included) instead of the table line. `--file F` (or `-` for stdin)
reads records from a file instead of kubectl.

## 9. Agent runtime semantics

- One `Execute` = one agentic loop: `system` + user `input` (+ `context` as a
  JSON block in the first user message when present). Loop until the model
  stops with `end_turn`, `max_steps` is reached (`budget.max_steps`, status
  `error`), or the model refuses (`stop_reason: refusal`, status `denied`,
  rule `model.refusal`).
- Every tool call goes to the sidecar (§4.3). Multiple `tool_use` blocks in one
  turn are executed sequentially and returned in one user message.
- Every model call leaves a `model_call` record with
  `input = {system, messages, tools}` and `output = content blocks`: the model
  gateway writes it for a provider's calls (§4.4), with tokens from the
  provider's `usage` and `cost_usd` from the sidecar's price table; the runtime
  reports it through `ReportEvent` for the `mock` model (`cost_usd` 0). Every
  model call that ran is recorded, because the provider bills it: a failed call
  carries the usage the API had reported before it failed (its input tokens
  once `message_start` arrived) and `error`; a call still running when its
  `Execute` is cancelled finishes in the background and is recorded with
  `error: "cancelled: …"`, so its cost still counts toward
  `max_cost_usd_per_day`. The runtime prices nothing.
- Deadline: each model request gets what is left of the `Execute` deadline,
  less 500 ms, as its SDK timeout (which bounds the connect and each wait for
  the next streamed chunk, not the whole stream). With 500 ms or less left, no
  new step starts: status `error`, rule `deadline.exceeded`.
- Provider selection: `model: mock` → the deterministic mock. Otherwise, when
  the gateway lists `anthropic` (the sidecar holds a key) → the Anthropic SDK,
  pointed at the gateway (§4.4); when it lists none → the mock only with
  `AGENTSC_MOCK_FALLBACK=1`, else Execute fails with `FAILED_PRECONDITION`
  (fail closed: a missing key never silently becomes a mock). `Health`
  reports `model_provider` `anthropic`, `mock` (the fallback) or `none`. Requests are streamed and collected
  (`messages.stream(...).get_final_message()`), so large `max_tokens` never
  trip the SDK's non-streaming limit; `output_config.effort: low` is sent to
  every model that accepts it (not `claude-haiku-4-5`, `claude-sonnet-4-5` or
  older). Thinking blocks are replayed unchanged on the next turn.
- `stop_reason: max_tokens`: with text and no tool call → `ok` with the
  truncated text (step summary says so); with a tool call or no text → `error`,
  rule `budget.max_tokens_per_call` (a cut-off tool call never runs).
- System prompt (level 6, §3.3; the texts are fixed in the runtime and given
  word for word in [docs/design/agent-practices.md](docs/design/agent-practices.md)):
  the charter's `system`, then `# Skills` (inline skills), then
  `# Working method`, then `# Output style`. A section with nothing in it is
  left out, so an agent with `plan: false`, `clarify: never` and both brevity
  levels at `normal` gets exactly the prompt it got at level 5.
  `# Working method` holds the plan text when `plan` is true and the agent has
  at least one charter tool (in `agent_spec_json`, so after
  `guardrails.allowed_tools`), and the clarify text of its level (`blocking`
  or `always`, naming `max_questions`) when `clarify` is not `never`,
  separated by a blank line. `# Output style` is present when the level is not
  `normal`; the level is `agent_brevity` when the Execute has a `caller_agent`
  (another agent called, locally or over the mesh), else `brevity`. Its text
  is the level's sentence, then the common rules (keep every technical fact;
  never drop a negation, a number or a unit; keep names, identifiers, code,
  commands, JSON, error messages and quoted text exactly; the style is for the
  answer only, never for tool inputs), then, with `auto_clarity`, the clarity
  rule (plain, complete sentences for a security warning, a destructive or
  irreversible action, and steps whose order matters). The reflection call
  never gets these sections: its prompt is the reflection prompt alone, and a
  lesson stays plain prose.
- `ask_caller` (level 6): offered when `clarify` is not `never`, after the
  charter tools and after `load_skill` when that is offered, with input
  `{"questions": [{"question", "recommended"}]}` (`minItems` 1, `maxItems`
  `max_questions`, both strings required). A valid call ends the run at once
  with status `ok`: the other `tool_use` blocks of that turn are not run;
  `questions` (§4.3) is the list, whitespace trimmed; `output` is the
  questions as text, `I need these decisions from you before I go on:`, then
  per question `<k>. <question>` and `   Recommended: <recommended>`, each
  block after a blank line; `steps[]` gets a `tool_call` step `ask_caller`,
  decision `allow`, summary `1 question` or `<k> questions`. A call with no
  questions, more than `max_questions`, or an empty `question` or
  `recommended` gets the error tool result `ask_caller needs 1 to <n>
  questions, each with a non-empty question and recommended answer.`, a
  `tool_call` step with summary `error: invalid questions`, and the loop goes
  on. Like `load_skill`, `ask_caller` is not in `tools_used`, so a run that
  only asked is not reflected on; no `tool_call` record is reported for it
  (§6). The runtime keeps no state between Executes: answers come back in
  `context` or the `input` (§4.1); a calling agent sends them in its agent
  tool's `context` argument (§3.1), which the runtime sends as
  `ToolAgentRequest.context_json` (§4.3).
- Reflection (learning on, after the Execute returned; design §12). The
  transcript numbers every entry after `input`, `s1` to `sN`, the outcome
  included (`s4 outcome: ok`); each entry is one line, its whitespace
  collapsed. A call that never got a result (cut off by `max_tokens`, or
  another call in the turn that asked) reads `sN call <tool> (not run):
  <args>`, and a tool name the charter doesn't declare (other than
  `load_skill` and `ask_caller`) shows as `undeclared`. With `contrast_runs`
  above 0 the runtime keeps, per agent and per process, a digest of each
  finished run of an agent with learning on: its status, rule, number of
  steps (its transcript entries, `s1` to `sN`, the outcome included), and the
  declared tools it called, in order (only calls that got a result;
  `load_skill` and `ask_caller` are left out, and a tool the charter doesn't
  declare shows as `undeclared`). Digests hold no input, output, argument or
  result, so nothing of one caller's run reaches the reflection on another's.
  A reflection gets the newest `contrast_runs` digests from before its run,
  newest first, in an `<earlier_runs>` block (`r1 ok; 4 steps; tools:
  get_order` for a call, its result, the answer and the outcome), left out
  when there are none; digests live in memory and reset when the runtime
  restarts. With `require_evidence` the prompt says a lesson must rest on
  steps named by id; without it, that the model cites them when it can.
  The answer is `NONE` or exactly four lines, `SCOPE: invariant | domain`,
  `TARGET: notes | system | skill:<name> | tool:<name>`, `EVIDENCE: s2, s3`
  and `NOTE: <one line>`, and code checks it: a line that starts with three
  backticks is ignored; `NONE`, an empty answer, one without a `NOTE:` line
  or with a `NOTE` of `NONE` or `N/A`, or one that gives a field twice, gives
  no lesson; the note is one line once whitespace is collapsed, and a note
  over `max_note_chars` gives no lesson;
  `SCOPE` must be one of `learning.scopes`; every `EVIDENCE` id must be an id
  of this transcript (one unknown id gives no lesson), and with
  `require_evidence` at least one is needed; a `TARGET` other than `notes`,
  `system`, `skill:<a skill of the agent>` or `tool:<a tool of the agent>`
  becomes `notes`. Only the note is proposed as memory; scope, target,
  evidence and contrast go in the `rationale` (§4.3). `TARGET` is advice for
  the reviewer: nothing edits `system` or a skill on its own.
- Mock model: on a turn without tool results it picks the single tool whose
  name+description shares the most words with the input (ties → declaration
  order) and fills string parameters heuristically (`input`/`question`/`query`
  → the whole input; `sku`/`id`/`order_id` → the first `UPPER-1` token, else
  the first run of 3+ digits); on a turn with tool results it answers
  `Based on <tool>: <result>` (results truncated to 600 chars). No tools → it
  echoes `Mock answer for: <input>`. It never calls `ask_caller` (it is left
  out of its tool choice, like `load_skill`); tests that need it script the
  model. On the reflection prompt it answers in the four-line format by fixed
  rules: a refused tool call, else the first tool used, gives `SCOPE: domain`,
  `TARGET: tool:<name>` and that step as evidence; else a run that ended
  `denied` or `error` gives `SCOPE: invariant`, `TARGET: notes` and the
  outcome step as evidence; else `NONE`. When the prompt says only one scope
  is kept, it uses that one.

## 10. Testing gates

- `cargo test --workspace` — charter validation (including unknown-field
  rejection and schema sync), authz matcher, guardrails, redaction, trace
  parsing, PKI issue/parse round trip, and an in-process mTLS mesh test (two
  sidecar cores on localhost: allowed call succeeds, `/admin` denied with the
  rule name — also as `/%61dmin`, `/admin/` and `/ADMIN` — tool paths held to
  their templates, wrong identity rejected), and a sidecar with a fake runtime and
  app (redirects returned unfollowed, guardrail-denied payloads withheld from
  the audit log, dropped and timed-out calls still audited, deadlines
  propagated), and the model gateway against a fake provider (a runtime that
  reports no cost still cannot spend past the budget, concurrent calls cannot
  overshoot it, `max_tokens_per_call` and `max_steps` held, calls bound to runs,
  the key never the runtime's, answers streamed through unchanged and recorded).
  The level-6 rules of §3.2 are in
  `crates/agentsc-charter/tests/practices_rules.rs`; questions held to the
  output guardrails, PII redaction and `max_questions`, and rule
  `clarify.asked`, in `services/agentscd/tests/clarify.rs`.
- `cd runtime && uv run pytest` — mock model routing, agent loop with a fake
  sidecar, the gateway client on a unix socket, event shape, model calls
  reported after a cancel or a failure, deadlines; the practices sections of
  the system prompt (`tests/test_practices.py`); `ask_caller` and its questions
  (`tests/test_clarify.py`); the numbered transcript, the digests of earlier
  runs and the checks on the four-line answer.
- `make test-live` (CI: `.github/workflows/real-model.yml`, nightly and by hand,
  when the secret `ANTHROPIC_API_KEY` exists) — the real model path: agentscd,
  the runtime and the Anthropic API through the gateway; streaming, `tool_use`,
  429 / 529 / a mid-stream overload retried, a refusal, a stalled stream ended
  at the deadline, no key in the runtime process.
- `services/agentsc-cli/tests/cli.rs` — `charter validate` accepts the demo
  charters and rejects `examples/charters/invalid-unknown-field.charter.yaml`;
  `logs --file` filters and sorts.
- `make local-demo` — the full demo on one machine: both apps, two sidecars
  with embassy certificates over mTLS, the real runtime (mock model).
- `make demo` on minikube is the end-to-end gate.

## 11. Known gaps (MVP)

- The kustomize manifests of §7 write the sidecar into each Deployment and
  use per-service certificates from the bootstrap Job, with no rotation and
  one CA per namespace. Webhook injection and per-pod certificates that
  `embassy` renews (§5, §7) come with the Helm chart.
- Budgets are in-memory per sidecar replica (not shared across replicas).
- The `mock` model runs in the runtime: its calls cost nothing, and its step
  limit is the runtime's own (`max_steps`); provider calls are held by the
  gateway (§4.4).
- The gateway has one provider adapter (Anthropic Messages); an
  OpenAI-compatible one is not shipped yet.
- Server-side refusal fallbacks (`fallbacks: "default"`) are not enabled; a
  refusal is surfaced as `model.refusal`.
- An `output_deny` match cannot retract the `model_call` record already
  written for the turn that produced the output.
- The practices (§3.3) are instructions to the model, not enforcement. The
  sidecar enforces tools, budgets, guardrails and taint; a model can still
  ignore the plan or the brevity rules. `ask_caller` adds no permission: it
  only ends the run.
- Digests of earlier runs (§9) are per runtime process, so per replica, and
  reset on restart.
