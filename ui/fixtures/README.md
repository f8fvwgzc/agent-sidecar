# Golden API data

Example responses of the control-plane API (`docs/api/openapi.yaml`, design
`docs/design/agent-platform.md` §10). The UI runs against them with `?fixtures=1`. Two checks
keep them honest:

- `services/embassy/tests/fixtures.rs` (`cargo test -p embassy`, and in CI through
  `cargo test --workspace`): each file deserializes into its Rust type in
  `services/embassy/src/api/types.rs` and serializes back to the same JSON; the orders and
  inventory charters are the example files; the files agree with each other; every charter
  passes `attache charter validate` (the workspace CLI, which `cargo test --workspace` builds).
- `docs/api/check_fixtures.py`: each file and each SSE event validates against the OpenAPI schema
  of the operation that names it (`x-fixture`), ids have their formats, the graph follows from
  the charters, the SSE audit events follow the record → edge mapping (design §10.1), the records
  pass the drop rule (design §7), `events-recent.json` is in the documented order, every
  `learning.proposed` record has its reflection `model_call`, every charter passes
  `attache charter validate`, and every UI path of design §11 has data. Run it with
  `uv run --no-project --with pyyaml --with jsonschema python3 -I docs/api/check_fixtures.py`
  (add `--self-test` to also check that known-bad edits are caught). It builds
  `target/debug/attache` with cargo when it is missing; `--skip-cli` skips the CLI and exits 3.

| File | Answers |
| --- | --- |
| `whoami.json` | `GET /api/v1/whoami` (alice, admin, all namespaces, payloads visible) |
| `whoami-viewer.json` | `GET /api/v1/whoami` for carol: viewer of `attache-demo`, payloads hidden |
| `graph.json` | `GET /api/v1/graph` at `2026-10-21T10:00:00.000Z`, version `412` |
| `services.json` | `GET /api/v1/services` |
| `charter-orders.json` | `GET /api/v1/services/attache-demo/orders/charter` (version `3`) |
| `charter-inventory.json` | `GET /api/v1/services/attache-demo/inventory/charter` (version `1`) |
| `charter-support.json` | `GET /api/v1/services/attache-demo/support/charter` (version `4`) |
| `charter-reports.json` | `GET /api/v1/services/attache-demo/reports/charter` (version `2`) |
| `charter-validate.json` | `POST /api/v1/services/attache-demo/support/charter/validate` for a candidate that drops the `no-card-numbers` input rule |
| `agent-view.json` | `GET /api/v1/services/attache-demo/orders/agents/ops-assistant` |
| `agent-view-support.json` | `GET /api/v1/services/attache-demo/support/agents/support-agent` |
| `links-result.json` | `POST /api/v1/links` from `support-agent` to `inventory/stock-analyst` with a stale `if_match` for support |
| `history.json` | `GET /api/v1/services/attache-demo/orders/charter/history` |
| `memory.json` | `GET /api/v1/services/attache-demo/support/memory` (version `2`) |
| `proposals.json` | `GET /api/v1/proposals` (all statuses, newest first) |
| `events-recent.json` | `GET /api/v1/events/recent?limit=30` (just before the snapshot) |
| `events.sse` | `GET /api/v1/events`, the first seconds after the snapshot |

## The world they describe

Namespace `attache-demo`, managed by the control plane. `ANTHROPIC_API_KEY` is set, so every
agent whose model is not `mock` calls `model:anthropic`.

| Service | Status | What it shows |
| --- | --- | --- |
| `orders` (2 pods) | connected | the README demo: `ops-assistant` (orchestrator) and `order-triage`; charter history; an undeclared edge |
| `inventory` (1 pod) | connected | `stock-analyst`; the `deny-admin` rule; an inbound record from a peer agent |
| `support` (2 pods) | degraded | skills (`tone` inline, `refund-policy` loaded with `load_skill`), a harness with a fallback model, learning in review mode with 2 notes and 1 pending proposal, a tool the guardrails do not allow (`issue_refund`, dimmed), the idle `mock` agent `faq`, `ask_billing` to an unknown peer, and a pod whose charter ack failed (`ack_error`) |
| `reports` | disconnected | a stored charter and no instance; the idle `digest` agent, edges last used yesterday |
| `shipping` (1 pod) | no_charter | a pending adoption of the sidecar's start-up charter |
| `billing` | placeholder | no charter and no instance: `support-agent`'s `ask_billing` names `billing/refund-approver`, so the graph has placeholder nodes for it |

Traffic in the 15-minute stats window (09:45–10:00):

- **orders/inventory**: three stock questions across the mesh (`ops-assistant` →
  `inventory/stock-analyst` → `GET /stock/WIDGET-1`), one `lookup_order`, one local
  `order_triage` call, the admin reset denied by inventory's `deny-admin` rule, and the input
  guardrail (`api_key = …`) refusing an invocation (so `ops-assistant` shows status `denied`).
- **support**: four `support-agent` invocations. One ended in an error (the model was overloaded
  on every retry and on the fallback model), one had `ask_billing` fail (billing does not
  exist), so the agent shows status `errors`. The last one (09:59:30–09:59:35, in
  `events-recent.json`) loads `refund-policy`, reads ticket T-2291 and answers; its reflection
  proposes the lesson that is pending in `proposals.json` (the `learning` record at 09:59:37).
- alice stored support's charter version 4 at 09:58:10. Pod `h4k8r` applied it; pod `r9t2z`
  could not: its state volume is full, and a sidecar does not apply a charter it cannot persist,
  so it stays on version 3, writes a `config` record with `decision: deny`, rule
  `config.invalid` and the error, and acks version 4 with `applied: false`. Its `ack_error` makes
  support `degraded` (in `services.json` and on the graph's service node).
- The run at 09:59:30 is reflected on after it returned (design §12): the reflection is a
  `model_call` under the invocation span (09:59:35.079–09:59:37.382, counted in the agent's
  tokens and cost and on its model edge), and its note becomes the `learning.proposed` record.

The orders charter has a history: version 1 was adopted from the sidecar, version 2 (alice)
added an `http` tool `partner_eta` to `https://api.partner.example`, version 3 rolled back to
version 1. That explains the `external:https://api.partner.example` node and the one
**undeclared** edge to it (`declared: false`, `partner_eta` is no longer a declared tool): its
only call, made under version 2, was denied with `guardrail.path`. Orders never had learning
enabled, so it has no memory (version `0`); memory exists only for agents with learning enabled
(design §3).

Support's memory (`memory.json`) has one note from a proposal bob approved and one alice wrote
with `PUT .../memory` (`source: manual`). `proposals.json` also has the proposal alice rejected.

The `inventory_admin_reset` edge is **declared** (the orders charter declares that tool) and
denied-only: its one call was refused by the inventory sidecar.

`events-recent.json` is strictly newest first; records with the same `ts` come in reverse write
order (a `service_call` / `agent_call` before the `tool_call` that made it, an
`agent_invocation` before the `guardrail` of its span).

`events.sse` continues from the snapshot:

1. `reset`: the browser reconnected with a `Last-Event-ID` older than the ring (it then refetches
   `/graph` and `/services`, which are the files above);
2. the inventory pod's Connect stream reconnects (`max_connection_age`; a new `instance_id`) and
   acks the memory push;
3. the 11 audit events of one more stock question (the CONTRACT.md §6 trail, in arrival order,
   with `edge_id`/`animate` per the record → edge mapping) and a `graph` event (version `413`);
4. alice (admin: a new `http` origin) stores support's charter version 5, which adds the `http`
   tool `track_parcel` (`GET https://tracking.example/v2/parcels/{parcel_id}`) to
   `support-agent` (`cp_audit` `charter_put`, then `config`): pod `h4k8r` applies it (`ack`,
   then its `config` audit record); pod `r9t2z`, still with a full state volume, does not (`ack`
   with `applied: false` and the error, then its failed `config` record); then `graph`
   (version `414`);
5. three requests at once, their records interleaved in arrival order:
   - orders: `ops-assistant` asks the **local** agent `order-triage` (tool `order_triage`). The
     `order-triage` `agent_invocation` has caller `local` and `caller_agent: ops-assistant`, so
     it animates nothing (the `agent_call` animates the `#order_triage` tool edge); the
     `ops-assistant` invocation, called by the app, animates the `invoke` edge;
   - support: the app asks `faq`, whose model is `mock`: its `model_call` (callee `mock`)
     animates the edge to `model:mock`;
   - support: `support-agent` reads ticket T-2304 and calls `track_parcel` (an `http_call` on
     the edge to `external:https://tracking.example`, which `graph.json` does not have yet: the
     `graph` event that follows announces it), then answers; its reflection (a `model_call`
     answering `NONE`) comes last;

   with `graph` events (versions `415`, `416`) at most every 2 s;
6. `lagged`: a load test against orders while the browser's connection stalls overflows its
   queue: the 1,024 queued events, the one that did not fit and the rest until the browser read
   again, 1,187 in all, are dropped (the ids jump by more: 4 events in between were for other
   namespaces); the browser refetches `/graph` and `/services`;
7. alice rejects support's pending proposal (`proposal` with `status: rejected`, then its
   `cp_audit` record), and a keep-alive comment.
