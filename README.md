# attache

**The agent is a sidecar of the service, not a service of its own.**

attache runs governed AI agents next to any service on Kubernetes, the way
Dapr runs building blocks next to it. The app talks plain HTTP or gRPC to
`localhost`, in any language, with no SDK. Everything an agent does goes
through the sidecar. That covers its input and output, every model call and
tool call, and every request to another service. All of it is authorized
against a YAML charter and written as one JSONL audit line you can read with
`kubectl logs`. The discipline is **AgentSecOps**: identity, policy, budgets
and audit for agents, owned by the platform rather than by each app.

> `attache` is a working name. The binaries are `attached` (sidecar), `attache` (CLI)
> and `embassy` (control plane / CA). The spec file is `charter.yaml`, and the API group
> is `attache.io/v1alpha1`. A rename is one find/replace.

[CONTRACT.md](CONTRACT.md) is the source of truth for the wire protocol, the
charter schema and the audit record. When code and CONTRACT.md disagree, the
code is wrong.

## How it fits together

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

- **`attached`** (Rust, tokio, axum, tonic, rustls) loads and validates
  `charter.yaml`. It serves the app on localhost, spawns and supervises the
  agent runtime, and runs every tool call through allowed-tools,
  allowed-services and authz checks. It forwards service and agent calls to
  peer sidecars over mTLS and writes the audit log to stdout.
- **`attache-runtime`** (Python 3.12, grpcio, `anthropic`) runs the agentic
  loop for each charter agent. It calls Claude when `ANTHROPIC_API_KEY` is set
  and a deterministic mock model otherwise, so the demo runs offline. It has
  no network access of its own for tools: every tool call is a gRPC call to
  its sidecar.
- **`embassy`** (Rust) holds the cluster CA. It issues one certificate per
  service with URI SAN `spiffe://attache/ns/<namespace>/svc/<service>`. The
  callee sidecar authorizes the caller by that SAN plus the calling agent
  name.
- **`attache`** (Rust CLI) validates charters, prints the JSON Schema, and
  tails and pretty-prints the audit log.

An orchestrator is just an agent whose tools are other agents, local or in
another pod. Many agents can live in one service.

## Try it

### On this machine, no Kubernetes (about a minute)

Needs `cargo`, `protoc`, `uv`, `go`, `python3` and `curl` (see
[Prerequisites](#prerequisites)). This starts both demo apps
and two sidecars with real mTLS certificates and the real Python runtime. It
then makes the calls below and prints the audit trail. It fails if the allowed
call does not cross the mesh, the admin call is not denied, or the guardrail
lets a secret through.

```bash
make local-demo
```

### On minikube

```bash
make minikube-up build deploy demo
```

| Target             | What it does |
| ------------------ | ------------ |
| `make minikube-up` | Starts minikube with the docker driver, 4 CPUs and 6 GB, if it is not running. |
| `make build`       | Builds `attache/attached`, `attache/embassy`, `attache/orders` and `attache/inventory` inside minikube's docker. No registry is needed. |
| `make deploy`      | Creates the namespace and charter ConfigMaps, runs the `embassy-bootstrap` Job to create the CA and per-service certificate Secrets, then rolls out both Deployments. |
| `make demo`        | Port-forwards `orders` and runs the two calls below. It fails loudly if the allowed call does not cross the mesh or the admin call is not denied. |
| `make logs`        | Prints the audit lines of both pods sorted by time. Add `TRACE=<id>` or `AGENT=<name>` to filter. |
| `make logs-denied` | Prints only the denials. |
| `make secret-anthropic` | Uses real Claude: puts `$ANTHROPIC_API_KEY` into a Secret and restarts the pods. |

Raw records are plain container logs:

```bash
kubectl --context minikube -n attache-demo logs -l attache.io/service=inventory -c attached
```

## What the demo shows

1. **An allowed cross-pod call.** `orders` (Go) gets `POST /ask` and calls
   its sidecar with one HTTP request. The sidecar runs `ops-assistant`, an
   orchestrator, which picks its `stock_analyst` tool. The `orders` sidecar
   calls the `inventory` sidecar over mTLS. That sidecar checks that
   `spiffe://attache/ns/attache-demo/svc/orders` may invoke `stock-analyst`,
   and the agent calls `GET /stock/WIDGET-1` on its own app. The stock record
   carries a warehouse contact email. The `inventory` charter has
   `pii_redact: true`, so the email never leaves the pod. It is redacted in
   the answer and in every audit payload.
2. **A denied call.** Asked to reset admin counters, `ops-assistant` tries
   `POST /admin/reset` on `inventory`. The `inventory` sidecar denies it with
   rule `authz.services.deny-admin`. The agent receives the denial as a tool
   error and says so. Both pods log the denial with the same `request_id` and
   `trace_id`. The inventory app listens only on its pod's loopback and its
   Service exposes only the mesh port, so there is no way around the sidecar.
3. **An input guardrail.** A question containing `api_key = …` is refused
   with HTTP 403 before any model call, under rule
   `guardrail.input_deny.no-secrets`.

The audit trail of call 1, from `attache logs`, spans both pods under one trace:

```
11:42:12.231 orders     ops-assistant  model_call       outbound local                      → mock                          allow                     3ms tokens=107/39
11:42:12.239 inventory  stock-analyst  model_call       outbound svc/orders (ops-assistant) → mock                          allow                     2ms tokens=79/12
11:42:12.242 inventory  stock-analyst  tool_call        internal local (stock-analyst)      → get_stock                     allow                     1ms
11:42:12.242 inventory  stock-analyst  service_call     internal local (stock-analyst)      → inventory GET /stock/WIDGET-1 allow                     1ms
11:42:12.243 inventory  stock-analyst  model_call       outbound svc/orders (ops-assistant) → mock                          allow                     0ms tokens=152/33
11:42:12.243 inventory  stock-analyst  guardrail        internal svc/orders (ops-assistant) → stock-analyst                 allow guardrail.pii_redact 0ms
11:42:12.243 inventory  stock-analyst  agent_invocation inbound  svc/orders (ops-assistant) → stock-analyst                 allow                     7ms tokens=231/45
11:42:12.244 orders     ops-assistant  tool_call        internal local (ops-assistant)      → stock_analyst                 allow                     9ms
11:42:12.244 orders     ops-assistant  agent_call       outbound local (ops-assistant)      → inventory/stock-analyst       allow                     9ms tokens=231/45
11:42:12.244 orders     ops-assistant  model_call       outbound local                      → mock                          allow                     0ms tokens=212/38
11:42:12.245 orders     ops-assistant  agent_invocation inbound  local                      → ops-assistant                 allow                    18ms tokens=319/77
```

One raw record, the denial as the `inventory` sidecar wrote it:

```json
{"ts":"2026-10-20T11:42:12.357Z","kind":"service_call","request_id":"505e145b-d157-43a6-a024-940f8749c48b",
 "trace_id":"0c0e1cd43cc0690f33f7641ca8e657ae","span_id":"b2e829e29ba007c4","parent_span_id":"c1184c48e196a83b",
 "service":"inventory","namespace":"attache-demo","agent":"ops-assistant",
 "caller":"spiffe://attache/ns/attache-demo/svc/orders","caller_agent":"ops-assistant",
 "callee":"inventory POST /admin/reset","direction":"inbound",
 "input":{"method":"POST","path":"/admin/reset","body":{}},"output":null,
 "input_sha256":"004b59a790029158af09d1ac3ccd89684b533043e26499e4e20ecdc1f18826e8","output_sha256":null,
 "tokens":null,"cost_usd":null,"latency_ms":0,"decision":"deny","rule":"authz.services.deny-admin",
 "reason":"POST /admin/reset on inventory matches deny pattern \"* /admin/*\"","error":null}
```

## The charter

Agents, tools, budgets, guardrails, authz and audit all live in one file per
service. Unknown fields anywhere are an error. The schema is
[`schemas/charter.schema.json`](schemas/charter.schema.json), generated from
the Rust types, and a test keeps it in sync.

```yaml
apiVersion: attache.io/v1alpha1
kind: Charter
service: { name: inventory, namespace: attache-demo, app_port: 8000 }
agents:
  - name: stock-analyst
    type: agent                      # or orchestrator: may use `agent` tools
    model: claude-opus-5-5           # or mock
    system: You are the stock analyst …
    tools:
      - name: get_stock
        description: Get current stock levels for one SKU.
        type: service                # service | agent | http
        service: inventory
        method: GET
        path: /stock/{sku}
    budgets: { max_tokens_per_call: 512, max_calls_per_minute: 60, max_cost_usd_per_day: 2.0, max_steps: 4 }
guardrails:
  pii_redact: true
  input_deny: [{ name: no-secrets, regex: "(?i)(api[_-]?key|password|secret)\\s*[:=]" }]
authz:
  default: deny
  callers:
    - { identity: local, agents: ["*"] }
    - { identity: spiffe://attache/ns/attache-demo/svc/orders, agents: [stock-analyst], caller_agents: [ops-assistant] }
  services:
    - name: deny-admin
      identity: spiffe://attache/ns/attache-demo/svc/orders
      agent: ops-assistant
      service: inventory
      deny: ["* /admin", "* /admin/*"]
audit: { sink: stdout }
```

```bash
cargo run -p attache-cli -- charter validate examples/charters/inventory.charter.yaml
cargo run -p attache-cli -- charter validate examples/charters/invalid-unknown-field.charter.yaml   # exit 1: unknown field `pii_redaction`
cargo run -p attache-cli -- charter schema
```

## Calling an agent from your app

```bash
curl -s localhost:3500/v1/agents/ops-assistant/invoke \
  -H 'content-type: application/json' -H 'traceparent: 00-<trace>-<span>-01' \
  -d '{"input": "How many WIDGET-1 are in stock?", "context": {"customer": "c-1"}}'
```

The response carries `status`, `output`, `usage`, `steps[]`, `request_id` and
`trace_id`. Denials return 403, and an exhausted budget returns 429. The gRPC
equivalent is `attache.v1alpha1.AppApi/InvokeAgent` on `localhost:50001`.

## Repository

```
CONTRACT.md                 source of truth: ports, wire protocol, charter, authz order, audit record
proto/attache/v1alpha1/     common, app (app→sidecar), mesh (sidecar↔sidecar), runtime (sidecar↔runtime)
crates/attache-charter      charter types, validation, JSON Schema
crates/attache-common       audit records, W3C trace context, SPIFFE ids, authz, guardrails, budgets
crates/attache-pki          CA and leaf issuance (rcgen), SAN parsing (x509-parser)
crates/attache-proto        generated tonic code
services/attached           the sidecar
services/embassy            the CA: ca-init, cert-issue, in-cluster bootstrap into Secrets
services/attache-cli        the CLI
runtime/                    the Python agent runtime (uv)
examples/orders             Go service, zero SDK
examples/inventory          FastAPI service, zero SDK
examples/charters           the two demo charters and one deliberately invalid one
deploy/                     kustomize: namespace, embassy Job + RBAC, both Deployments with the sidecar
docker/Dockerfile           attached (sidecar + runtime) and embassy images
scripts/demo.sh             the minikube demo; scripts/local-demo.sh runs the same thing without Kubernetes
```

## Prerequisites

- **Rust** stable (edition 2024, so 1.85 or newer) with `rustfmt` and `clippy`.
- **`protoc`**, the protobuf compiler. `attache-proto` compiles `proto/` at
  build time, so every `cargo` build needs it: `brew install protobuf` or
  `apt-get install protobuf-compiler`. Set `PROTOC` to use a binary off `PATH`.
- **`uv`** for the Python runtime. It fetches Python 3.12 itself.
- `go`, `python3` and `curl` for `make local-demo`; `docker`, `minikube` and
  `kubectl` for the minikube demo.

## Tests

```bash
make test        # cargo test --workspace and the runtime's pytest suite
make lint        # clippy -D warnings, ruff
make schema      # regenerate schemas/charter.schema.json from the Rust types
make proto       # regenerate the committed Python gRPC stubs from proto/
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs all of these on
Linux for every push and pull request, plus `cargo fmt --check`,
`ruff format --check` and `make local-demo`. It fails when `make schema` or
`make proto` changes a committed file.

The Rust suite includes an in-process mesh test. It starts two sidecars with
embassy-issued certificates on localhost and proves that:

- an allowed call crosses mTLS;
- `/admin` is denied with the rule name in both audit logs under one trace;
- a pod with another service's certificate, or no certificate, is refused;
- `caller_agents` limits which of a peer's agents may call;
- `..` and `%2e%2e` traversals meet the deny rule they aim past, and encoded
  slashes are refused;
- a peer cannot smuggle `x-attache-caller` or `traceparent` headers to the app.

## Not built yet

CONTRACT.md §11 is the full list. In short:

- **Sidecar injection is explicit.** The `attached` container is written in
  each Deployment. The mutating webhook for `attache.io/inject: "true"` is not
  built.
- **Certificates are per service.** They are issued by a bootstrap Job, with
  no rotation. Per-pod certificates through a running `embassy` come next.
- **Budgets are in memory** per sidecar replica.
- **The runtime calls the model API directly.** Model calls are audited, not
  proxied.
- **No UI.** The charter schema is the API a UI will generate against.
