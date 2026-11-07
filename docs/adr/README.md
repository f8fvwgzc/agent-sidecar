# Architecture decision records

One file per decision that shapes the system and that a reader of the code would otherwise have
to reverse-engineer: what was decided, why, what it costs, and what was turned down. A record is
written when the decision is made and amended, not rewritten, when it changes (a superseding
record links back). The design notes under [`docs/design/`](../design/) describe how a
subsystem works; a record here says why it is the way it is.

| Record | Status | Decision |
| --- | --- | --- |
| [0001](0001-http3-for-the-console.md) | implemented | The console reaches the control plane over HTTP/3 (`embassy serve --http3`); every other hop stays on HTTP/2 or HTTP/1.1 |
| [0002](0002-response-caching.md) | implemented | Two revalidating caches: `ETag`/`304` between the console and the control plane, and a `Cache-Control`-driven response cache on both ends of a service-to-service call |
| [0003](0003-sqlite-store-schema.md) | implemented | `--store sqlite:<path>`: one database with primary and foreign keys, covering indexes on every query path, and triggers that enforce what the file layout only promised |
| [0004](0004-agent-practices-on-by-default.md) | implemented | Agent practices (plan, clarify, brevity) on by default with fixed texts in the runtime; questions keep status `ok` and add a field; lessons cite their evidence; learning stays off by default |
| [0005](0005-agents-in-tutelad.md) | implemented | With a `tutela` section, embassy is an app of `tutelad`: the registry's agents are registered there and disabled on quarantine or retirement by a retrying reconciler, and embassy signs its agents' own tokens (the actor of a delegated token); actions that need `tutelad` fail closed |
| [0006](0006-delegated-agent-tokens.md) | implemented | An `http` tool with `delegation` acts for the invoking person: the sidecar keeps the person's token for the run, embassy verifies it and exchanges it at `tutelad` with its own agent token as the actor, and the call carries the `agent+jwt`; it fails closed |
| [0007](0007-kind-for-the-real-cluster-checks.md) | implemented | `make demo-helm CLUSTER=kind`; the chart is checked on kind at Kubernetes 1.34, 1.31 (the oldest kind v0.31.0 lists) and 1.29 (its `kubeVersion` floor, without the ValidatingAdmissionPolicy API) |

## Format

```text
# <number>. <title>

Status: proposed | implemented | superseded by <record>
Date: <YYYY-MM-DD>

## Context      what was true and what hurt
## Decision     what is built, precisely enough to recognise it in the code
## Consequences what it costs and what it makes possible, including operations
## Alternatives what was turned down and why
```

The number is the next free one. Keep a record short enough to read in one sitting; the code
and the design notes carry the detail.
