# LLM connection contract v1 and the model gateway

Every core of the platform (texc-symphony, onto-intelli, attache) reads the same `LLM_*`
environment variables, so one Kubernetes Secret and one ConfigMap configure model access
everywhere. attache reads them in two places:

- **the sidecar** (`agentscd`): the provider its model gateway calls for the agent runtime
  (CONTRACT.md §4.4);
- **the standalone model gateway** (`agentsc-gateway`): the sidecar's gateway on its own, without
  a sidecar, a charter or Kubernetes. The other cores, Codex, Claude Code and sidecars send their
  model calls to it with a token, and it holds the provider keys.

## The contract

| Variable | Required | Meaning |
|---|---|---|
| `LLM_PROVIDER` | yes, unless gateway mode | `anthropic`, `openai` or `openai-compatible` (Ollama, vLLM, LM Studio, OpenRouter, Groq, Together, Gemini's OpenAI endpoint, Azure OpenAI: anything that speaks OpenAI Chat Completions at `LLM_BASE_URL`). In gateway mode it picks the wire format (default `anthropic`). |
| `LLM_BASE_URL` | for `openai-compatible` | The provider's API base URL (`http://` allowed). Defaults: `https://api.anthropic.com`, `https://api.openai.com/v1`. |
| `LLM_API_KEY_FILE` | | File holding the key (preferred: a mounted Secret). Read again for every request, so a rotated Secret applies to the next one. Wins over `LLM_API_KEY`. |
| `LLM_API_KEY` | | The key as text. |
| `LLM_MODEL` | yes | The model. |
| `LLM_MODEL_SMALL` | | A small, fast model. |
| `LLM_TIMEOUT_SECS` | | Timeout of one model request (`> 0`). |
| `LLM_MAX_RETRIES` | | Retries of one request (`0..=10`). |
| `LLM_GATEWAY_URL` | | **Gateway mode**: every model call goes to the platform's model gateway (`agentsc-gateway`), which speaks Anthropic Messages (`/v1/messages`), OpenAI Chat Completions (`/v1/chat/completions`) and Responses (`/v1/responses`). The root URL; a trailing `/v1` is ignored. No provider key is used. |
| `LLM_GATEWAY_TOKEN_FILE` | with the gateway | File holding the gateway token, sent as a bearer token. Read again for every request. |

The semantics are those of texc-symphony (`docs/configuration.md`, "LLM connection contract")
and onto-intelli (`llm::contract`); attache's parser is `agentsc_common::llm_contract`:

- The contract applies once `LLM_PROVIDER` or `LLM_GATEWAY_URL` is set. An empty value counts as
  unset.
- Other `LLM_*` without one of them are ignored, each with a warning (`Ignoring LLM_MODEL without
  LLM_PROVIDER or LLM_GATEWAY_URL`).
- An invalid value of an active contract stops the process with an error that names the
  variable, never the key: `LLM_PROVIDER is invalid`, `LLM_MODEL can't be blank`,
  `LLM_BASE_URL can't be blank` (for `openai-compatible`), `LLM_TIMEOUT_SECS is invalid`,
  `LLM_MAX_RETRIES is invalid`, `LLM_GATEWAY_TOKEN_FILE can't be blank`.
- In gateway mode `LLM_API_KEY`, `LLM_API_KEY_FILE` and `LLM_BASE_URL` are ignored, with a warning.
- At start-up the process logs one line saying what the contract configures (provider and
  endpoint, or the gateway; where the key comes from; the model), never a secret.

In Kubernetes the cores share ConfigMap `llm-config` (the non-secret `LLM_*` keys, as `envFrom`)
and Secret `llm-credentials` mounted at `/var/run/secrets/llm` (`api-key` → `LLM_API_KEY_FILE`,
`gateway-token` → `LLM_GATEWAY_TOKEN_FILE`). In gateway mode only the gateway token is mounted,
so the pod holds no provider key.

## The sidecar

`agentscd` reads the contract when no Anthropic key is configured the sidecar's own way
(`ANTHROPIC_API_KEY` or `--anthropic-api-key-file`; nothing changes for a deployment that sets
no `LLM_*`). With both a key and the contract set, the key wins with a warning, except in gateway
mode: then the sidecar refuses to start, because gateway mode exists to keep provider keys out
of the pod. The start-up log names the connection actually used (`model gateway upstream: ...`).
The agent runtime speaks Anthropic Messages, so:

| Contract | The sidecar's gateway calls |
|---|---|
| `LLM_PROVIDER=anthropic` + key | Anthropic at `LLM_BASE_URL` with the key (`LLM_API_KEY_FILE` read for every call) |
| `LLM_GATEWAY_URL` + `LLM_GATEWAY_TOKEN_FILE` | the standalone gateway's `/v1/messages`, with the token. The sidecar holds no provider key. Its `model_call` records name the callee `gateway:<model>`, and the run's `x-agentsc-request-id` travels on, so the gateway's record of the same call carries it too. |
| `LLM_PROVIDER=openai` / `openai-compatible` (no gateway) | refused at start-up: use `anthropic`, or the gateway |

Everything else of §4.4 holds either way: the run binding, the charter's model, `max_tokens` and
`max_steps`, the daily cost budget, the `model_call` record. `LLM_TIMEOUT_SECS` caps every model
call (below the run's deadline). `LLM_MAX_RETRIES` retries a connection that could not be made
(nothing was sent); answers are retried by the runtime's harness, as before. The runtime's
environment never has `LLM_API_KEY`, `LLM_API_KEY_FILE` or `LLM_GATEWAY_TOKEN_FILE`.

## The standalone model gateway

```bash
agentsc-gateway --listen 0.0.0.0:8090 --tenants-file /etc/agentsc/tenants.yaml
```

The binary ships in the `agentscd` image (`docker run --entrypoint agentsc-gateway ...`) and in
the release archives. Its upstream is the contract of its own environment (`LLM_PROVIDER`,
`LLM_BASE_URL`, `LLM_API_KEY_FILE`, ...; or `LLM_GATEWAY_URL` to chain to another gateway); its
callers are the tenants of the tenants file. Logs go to stderr; stdout carries only audit records.

| Flag | Env | Default | |
|---|---|---|---|
| `--listen` | `AGENTSC_GATEWAY_LISTEN` | `127.0.0.1:8090` | plain HTTP: bind to loopback, or put TLS (an ingress, a mesh) in front of it |
| `--tenants-file` | `AGENTSC_GATEWAY_TENANTS_FILE` | required | who may call (below) |
| `--prices-file` | `AGENTSC_PRICES_FILE` | none | prices of models the built-in table lacks (below) |
| `--audit-payloads` | `AGENTSC_GATEWAY_AUDIT_PAYLOADS` | off | record prompts and answers (off: tokens, cost and errors only) |
| `--namespace` | `AGENTSC_NAMESPACE` | empty | the `namespace` of the audit records |

### Wire formats

| Endpoint | Format | Answered by |
|---|---|---|
| `POST /v1/messages` | Anthropic Messages | an `anthropic` provider, or a chained gateway |
| `POST /v1/chat/completions` | OpenAI Chat Completions | an `openai` or `openai-compatible` provider, or a chained gateway |
| `POST /v1/responses` | OpenAI Responses | an `openai` provider, or a chained gateway |
| `GET /v1/models` | OpenAI model list | the contract's `LLM_MODEL` and `LLM_MODEL_SMALL` (with a token) |
| `GET /healthz`, `GET /readyz` | | `/readyz` is `503` while the audit sink fails |

A call goes to a provider that speaks its format, streamed through as it arrives. There is no
translation between formats in v1: a call whose model's providers do not speak its format is
refused with `400` and rule `model.wire_unsupported`, and the message names the endpoint that
would work. Pick the client's format accordingly (for Claude models `LLM_PROVIDER=anthropic` in
gateway mode; Codex speaks only Responses, so it needs an `openai` provider).

Clients in gateway mode:

| Client | Settings |
|---|---|
| texc-symphony, onto-intelli | `LLM_GATEWAY_URL=http://agentsc-gateway:8090`, `LLM_GATEWAY_TOKEN_FILE=/var/run/secrets/llm/gateway-token`, `LLM_PROVIDER` for the wire format, `LLM_MODEL`; onto-intelli also `llm.fallbacks = false` (below) |
| an attache sidecar | the same (`LLM_PROVIDER` is ignored: the runtime speaks Messages) |
| Claude Code | `ANTHROPIC_BASE_URL=http://agentsc-gateway:8090`, `ANTHROPIC_AUTH_TOKEN=<token>` |
| Codex | a model provider with `base_url = "http://agentsc-gateway:8090/v1"`, `wire_api = "responses"`, the token as its key |
| the Anthropic or OpenAI SDKs | base URL the gateway (`.../v1` for OpenAI's), the token as the API key |

### Tenants

```yaml
tenants:
  - name: texc-symphony              # lowercase letters, digits, -: records say tenant:<name>
    token_sha256: 9f86d0818...       # printf %s "$TOKEN" | sha256sum
    max_cost_usd_per_day: 50         # optional: no limit
    models: ["claude-*", "gpt-5*"]   # optional: any model
  - name: onto-intelli
    token_sha256: 60303ae22...
    providers:                       # bring your own keys, in order of preference
      - kind: openai
        api_key_file: /var/run/secrets/tenants/onto/openai
        models: ["gpt-*"]
      - kind: openai-compatible
        base_url: http://vllm.ml.svc:8000/v1
        models: ["llama-*"]
    use_platform: false              # default: true only for a tenant without providers
```

- **Tokens.** A caller sends its token as `Authorization: Bearer <token>` or `x-api-key: <token>`.
  The file holds only its SHA-256; every tenant's hash is compared in constant time. No token or
  an unknown one is `401` (`www-authenticate: Bearer`, rule `auth.unauthenticated`), and nothing
  goes upstream. Two tenants may not share a token.
- **Providers.** A call goes to the first of the tenant's own providers that speaks its format and
  lists its model, then, with `use_platform`, to the platform's (the contract). A provider's key is
  a file, never text in the tenants file, and is read again for every call. `anthropic` and
  `openai` providers need `api_key_file`; `openai-compatible` needs `base_url` and may have no
  key.
- **Models.** `models` patterns are a model id, a prefix ending in `*`, or `*`. A tenant's list
  limits what it may call (`403 model.not_allowed`); a provider's what it serves.
- The tenants file is read at start-up; restart to change it. Keys and tokens rotate without one.

### Checks and spend

The same as the sidecar's (CONTRACT.md §4.4), per tenant:

- Only allowed request fields reach the provider, so a new field that bills differently never
  gets through unseen. Hosted tools (`web_search`, `file_search`, `code_interpreter`, server tools
  of Messages) bill outside the token price and act outside the platform's tool policy:
  refused. So are `service_tier`, `audio`, `prediction`, `background`, more than one choice
  (`n`), and media the provider would fetch from a URL (inline data is fine). Refusals are `400`
  `model.request_invalid`.
- Sampling fields (`temperature`, `top_p`, `top_k`) pass: they do not change the price.
  Messages' `fallbacks` is refused: it may answer with another model than the request names, at
  that model's price. onto-intelli sends it by default; set `llm.fallbacks = false` in gateway
  mode.
- A streamed Chat Completions request gets `stream_options.include_usage: true`, so its last
  chunk carries the usage.
- Responses stores answers under the key that made them. On the platform's key, which every
  tenant using it shares, a call is sent with `store: false`, and `previous_response_id` or an
  `item_reference` input (stored state, another tenant's as likely as the caller's) is refused
  (`400 model.request_invalid`): send the items themselves. An item reference's `type` is
  optional, so an input item with an `id` and no `type` (or `"type": null`) counts as one; give
  replayed items their `type`. On a tenant's own key, storing is the
  tenant's choice, and a call that refers to stored state reserves the model's whole context
  window, since its size is not in the request.
- The most the call can cost is reserved against the tenant's `max_cost_usd_per_day` before it
  goes out (`403 budget.max_cost_usd_per_day` when it would not fit). The bound is the request's
  bytes plus 4096 tokens, or the model's context window for a request with media or stored state
  (`previous_response_id`, `item_reference`), and its output limit (`max_tokens`, `max_completion_tokens`,
  `max_output_tokens`; 128000 when it names none). The reservation is settled with the usage
  the provider reported. A call cut before it completed (a timeout, a broken stream, no usage
  reported) is counted at its reservation, so a server that reports no usage cannot run a budget
  open. Budgets are kept per process and day (UTC): with several replicas each holds its own.
- **Prices** come from the one table (`agentsc_common::pricing`: Anthropic list prices). A model
  it lacks is priced at the top tier, so a budget never under-counts. Add the others, at the
  prices your contract with the provider says, with `--prices-file` (USD per 1M tokens; cache
  reads as a fraction of the input rate):

  ```yaml
  gpt-5: {input: 1.25, output: 10.0, cache_read: 0.1}
  llama-3.3-70b: {input: 0, output: 0}
  ```

  OpenAI usage is counted as prompt and output tokens, cached prompt tokens at the input rate
  (the conservative reading).

### Records

Every call writes a `model_call` audit record (CONTRACT.md §6) on stdout: `caller`
`tenant:<name>`, `callee` `<provider>:<model>` (`anthropic`, `openai`, `openai-compatible`,
`gateway`), `request_id` (the caller's `x-agentsc-request-id` or `x-request-id`, else a new one),
`tokens`, `cost_usd`, `latency_ms`, and `error` when the provider failed or the answer broke off.
`input` holds the wire format, model and `stream`; prompts and answers only with
`--audit-payloads`. A refusal writes an `authz` (or `budget`) record with its rule. A call
without a valid token writes no record (only a debug log line), so a flood of them costs nothing.

### Errors

Refusals are in the shape of the call's format (Anthropic's `{"type": "error", "error": ...}`,
OpenAI's `{"error": {"type", "code", "message"}}`) with header `x-agentsc-rule`:

| Status | Rule | |
|---|---|---|
| 401 | `auth.unauthenticated` | no token, or an unknown one |
| 400 | `model.request_invalid` | a field, tool or media part the gateway does not forward, or a body that is not JSON |
| 400 | `model.wire_unsupported` | no provider of the model speaks the call's format |
| 403 | `model.not_allowed` | the tenant may not call the model |
| 403 | `model.provider_unavailable` | no provider serves the model, or its key file cannot be read |
| 403 | `budget.max_cost_usd_per_day` | the call would not fit the tenant's budget |
| 502 | `model.upstream_unavailable` | the provider could not be reached |

The provider's own answers (including its errors, `429` and `retry-after`) pass through
unchanged, so clients retry as against the provider.

## Upgrading

- **Responses on the platform's key (agentsc-gateway, PR #18 onwards).** A call on the platform's
  key is sent with `store: false`, and one that uses `previous_response_id`, or an item reference
  (`{"type": "item_reference", "id": ...}`, or an untyped `{"id": ...}`), now gets
  `400 model.request_invalid` instead of reaching OpenAI. Clients that continue conversations on
  the platform's key must send the earlier items themselves (stateless use), or move the tenant to
  its own OpenAI key (`providers` in the tenants file), where stored state is the tenant's own and
  reserves the model's whole context window against its budget.
- **Messages fields.** `temperature`, `top_p` and `top_k` pass; `fallbacks` stays refused, since it
  may answer with, and bill, another model: set onto-intelli's `llm.fallbacks = false` in gateway
  mode.

## Not in v1

- Translation between wire formats (a Responses call to an Anthropic model).
- TLS in `agentsc-gateway` itself: terminate it in front, or keep it on loopback.
- A Helm chart for the gateway, and sidecar injection of the gateway settings: deploy it as a
  Deployment with the `agentscd` image (`command: [agentsc-gateway]`), the tenants file in a
  ConfigMap and the keys in Secrets.
- Budgets shared between replicas, and request-rate limits per tenant.
