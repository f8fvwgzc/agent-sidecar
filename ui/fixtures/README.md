# Golden API data

Example responses of the control-plane API (`docs/api/openapi.yaml`, design
`docs/design/agent-platform.md` §10). The UI runs against them with `?fixtures=1`; the
embassy test `services/embassy/tests/fixtures.rs` checks that each file deserializes into its
Rust type in `services/embassy/src/api/types.rs` and serializes back to the same JSON, that the
charters are the example files, and that the files agree with each other.

| File | Answers |
| --- | --- |
| `whoami.json` | `GET /api/v1/whoami` (alice, admin, all namespaces, payloads visible) |
| `graph.json` | `GET /api/v1/graph` at `2026-10-21T10:00:00.000Z`, version `412` |
| `services.json` | `GET /api/v1/services` |
| `charter-orders.json` | `GET /api/v1/services/attache-demo/orders/charter` (version `3`) |
| `charter-inventory.json` | `GET /api/v1/services/attache-demo/inventory/charter` (version `1`) |
| `agent-view.json` | `GET /api/v1/services/attache-demo/orders/agents/ops-assistant` |
| `history.json` | `GET /api/v1/services/attache-demo/orders/charter/history` |
| `memory.json` | `GET /api/v1/services/attache-demo/orders/memory` (version `1`) |
| `proposals.json` | `GET /api/v1/proposals` (all statuses, newest first) |
| `events-recent.json` | `GET /api/v1/events/recent?limit=19` (newest first, just before the snapshot) |
| `events.sse` | `GET /api/v1/events`, the first seconds after the snapshot |

## The world they describe

The demo of the README, managed by the control plane: namespace `attache-demo`, services
`orders` (two pods) and `inventory` (one pod), with the charters of `examples/charters/` —
`orders` runs `ops-assistant` (orchestrator) and `order-triage`, `inventory` runs
`stock-analyst`. `ANTHROPIC_API_KEY` is set, so every model call goes to `model:anthropic`
(`claude-opus-5-5`); `model:mock` does not appear.

Traffic in the 15-minute stats window (09:45–10:00): three stock questions across the mesh
(`ops-assistant` → `inventory/stock-analyst` → `GET /stock/WIDGET-1`), one `lookup_order`, one
local `order_triage` call, the admin reset denied by inventory's `deny-admin` rule, and the input
guardrail (`api_key = …`) refusing an invocation (so `ops-assistant` shows status `denied`).

The orders charter has a history: version 1 was adopted from the sidecar, version 2 (alice)
enabled learning for `ops-assistant` and added an `http` tool `partner_eta` to
`https://api.partner.example`, version 3 rolled back to version 1. That explains:

- the note in `memory.json` and the two proposals (one approved, one still pending) although the
  current charter has no `learning` block, hence the learning badge `enabled: false`, 1 note,
  1 pending;
- the `external:https://api.partner.example` node and the one **undeclared** edge to it
  (`declared: false`, `partner_eta` is no longer a declared tool): its only call, made under
  version 2, was denied with `guardrail.path` (an encoded `/` in the order id).

The `inventory_admin_reset` edge is **declared** (the orders charter declares that tool) and
denied-only: its one call was refused by the inventory sidecar.

`events.sse` continues from the snapshot: the inventory pod's Connect stream reconnects
(`max_connection_age`; a new `instance_id`) and acks the memory push, then the 11 audit events of
one more stock question (the CONTRACT.md §6 trail, in arrival order, with `edge_id`/`animate` per
the record → edge mapping), a `graph` event (version `413`), alice rejecting the pending proposal
(`proposal` with `status: rejected`) and its `cp_audit` record, and a keep-alive comment.
