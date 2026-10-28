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
