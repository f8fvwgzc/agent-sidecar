# 2. Response caching: console ↔ control plane, and service to service

Status: implemented
Date: 2026-10-24

## Context

Two kinds of repeated reads dominate the traffic:

1. The console refetches the graph (`GET /api/v1/graph`), the service list and the trace list
   after every SSE event, throttled to about once a second. Most of those refetches return the
   same body: an audit record animated an edge, nothing in the graph changed. Each one still
   moved the whole document.
2. Agents call services over the mesh. A run that looks up the same order or stock line twice,
   or a sub-agent that re-reads what its caller just read, paid for two mTLS round trips and two
   app calls, and under load the app saw every repeat.

Neither reader may ever see stale data where it matters: the console drives edits with
`If-Match` on versions, and a run that writes then reads must see its write. So the question
was not whether to cache but how to cache without ever answering with something the origin would
not answer with now.

## Decision

### Console ↔ control plane: validation, never expiry

- **`ETag` on every API `GET`.** `api/cache.rs` is a middleware inside the security guard. A
  `200` whose body is in memory gets an `ETag`: the handlers' version tags stay (`"3"` on a
  charter, an agent view or a memory document, which the console parses as numbers), every other
  body gets a content hash (`"h-<hex>"`, strong, prefixed so it never looks like a version). A
  request whose `If-None-Match` names the tag is answered `304 Not Modified` with no body.
- **`Cache-Control: private, no-cache`, `Vary: Cookie, Authorization`** unless the handler set
  its own. A private cache may keep a copy but must revalidate before every use; nothing is ever
  served on age alone. The SSE stream is `no-store` and, having no known size, is never buffered.
- **The console's transport keeps the last body per URL** (`ui/js/api.js`, `ResponseCache`,
  256 entries, least recently used out) and sends `If-None-Match`; a `304` is answered from the
  copy as a `200` with `cached: true`. The browser's own cache stays off (`cache: 'no-store'`):
  one validation path, the same over HTTP/1.1, HTTP/2 and HTTP/3. Because every request still
  reaches the control plane, a mutation needs no invalidation: the next `GET` revalidates. The
  copies are dropped on sign-out.
- **Console files** stay `no-cache` (so a new embassy is picked up on the next reload, with a
  `304` when nothing changed); `vendor/` files carry their version in their names and are
  `public, max-age=31536000, immutable`.

### Service to service: the app decides, both sidecars keep

- **Opt-in by the app.** A `GET` or `HEAD` the app answers with `Cache-Control: max-age=N` (or
  `s-maxage=N`, which wins: the sidecar is a shared cache) is kept for `N` seconds less its
  `Age`, at most `--mesh-cache-max-age` (default 300 s). A response without `Cache-Control`,
  with `no-store`, `no-cache` or `private`, with `Vary: *`, or with any status but `200` is
  never kept. A cache the app did not ask for would hide its writes from its readers; the app
  knows which of its reads are safe to repeat.
- **Two caches per call** (`agentscd/src/cache.rs`): the callee's sidecar in front of its app
  (`mesh.rs`, `Mesh.InvokeService`), so a peer's repeated read never reaches the app; and the
  caller's sidecar in front of the network (`tools.rs`, `SidecarTools.InvokeService`), so a
  run's repeated read never leaves the pod. A caller-side hit on a response that was itself a
  callee-side hit carries the sum of both ages.
- **Keyed by authorization.** The key is service, caller identity, agent, method and path, plus
  the values of the response's `Vary` headers at store time. Authz runs before every lookup, so
  a hit is only ever served to a caller that may make the call now, and the key keeps one
  caller's data from another even where authz would allow both.
- **Writes invalidate.** Any other method through a sidecar to a service empties that service's
  entries in that sidecar: the callee's on receiving it, the caller's on sending it. A run that
  writes then reads sees its write; a peer's write is seen after the entry's `max-age`, as the
  app asked.
- **Visible.** A hit carries `Age` and `x-agentsc-cache: hit`, still writes its `service_call`
  record (with its own latency) and still marks the run with the tool's taint label: the data
  reached the model either way. `InvokeAgent` (non-deterministic, costed, policy-bearing) and
  `http` tools (the internet, `untrusted` by default) are never cached.
- **Bounded.** `--mesh-cache-bytes` (default 16 MiB, `0` off), least recently used out, in
  memory, per replica.

## Consequences

- An unchanged graph or trace list costs the console a round trip and no payload; the
  computation on the control plane still happens (a server-side result cache would have to be
  scoped per identity and namespace set, and the handlers are cheap in-memory reads; not worth
  the correctness surface yet).
- Apps that want their reads cached add one header; apps that say nothing get exactly today's
  behaviour. The Age header lets an app or a trace reader tell a hit from a fresh answer.
- Cross-replica writes are not seen before `max-age`: an app that cannot tolerate that keeps
  `max-age` short or does not set it. There is no invalidation message between pods, by design.
- `GET /proposals` and the memory document are served with content hashes or version tags like
  everything else; the approve/reject flow keeps using `If-Match` on the memory version and is
  unaffected.

## Alternatives

- **`max-age` on API responses, with SSE-driven invalidation in the console.** Faster in the
  best case, wrong in the worst: a missed event (a lagged stream, a paused console) would show
  stale data with no way to tell. Revalidation costs one round trip and is never wrong.
- **A charter-level `cache:` setting per tool.** Puts a transport detail into policy and into
  the charter schema levels; the app already has the standard vocabulary for this, and the
  sidecar already forwards its headers.
- **Caching `InvokeAgent`.** The same input to an agent is not the same answer (memory, model,
  budgets, taint), and a cached denial or refund would be a policy bypass.
- **Shared cache (Redis) between replicas.** A dependency, a network hop and a second place for
  data to leak between callers, to save repeats that two in-process caches already catch.
