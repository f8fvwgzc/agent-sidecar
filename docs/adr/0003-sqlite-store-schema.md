# 3. The SQLite store: keys, indexes and triggers

Status: implemented (`embassy serve --store sqlite:<path>`)
Date: 2026-10-24

## Context

The control plane had two stores behind one trait (`store::Store`, design §8.4): `file:<dir>`,
a directory of YAML and JSON files with an in-memory index rebuilt at start, and `kubernetes`,
the `Charter` custom resources. Both keep the invariants the design promises (versions monotonic
and never reused, a new epoch after delete, memory only for agents that learn, one decision per
proposal, an append-only audit) in Rust code alone. The file store has no index but the one in
memory, no relation between a service and its history, notes, proposals and audit lines but the
path layout, and nothing stops a stray process from editing `.audit.jsonl`. Operators asked for
a store they could query, back up as one file, and trust to refuse a wrong write.

## Decision

`--store sqlite:<path>`: one SQLite database (`store/sqlite.rs`, schema in `store/schema.sql`,
applied when `PRAGMA user_version` is 0 and versioned from there). Everything the file store
keeps, in five tables. `--auto-adopt` accepts it like the file store; pending adoptions stay in
memory as they do there (a sidecar offers its start-up charter again on every connect).

### Tables and keys

| Table | Primary key | Foreign key | Holds |
| --- | --- | --- | --- |
| `services` | `id` (rowid); `UNIQUE (namespace, service)` | — | one row per service ever seen; `epoch` (NULL = no charter), the charter and memory version counters, `created_at`, `updated_at` |
| `charter_versions` | `(service_id, version)`, `WITHOUT ROWID` | `services (id) ON DELETE CASCADE` | every stored version: YAML as written, the same as JSON, SHA-256, timestamp, actor, kind, role, source |
| `notes` | `(service_id, agent, seq)`, `WITHOUT ROWID` | `services (id) ON DELETE CASCADE` | the memory, one row per note in order; the document's version is `services.memory_version` |
| `proposals` | `id`, `WITHOUT ROWID` | `services (id) ON DELETE CASCADE` | lesson proposals, status, `auto`, the sidecar's `dedup_key`, decision time and actor |
| `cp_audit` | `seq` (rowid) | — | the control-plane audit: the record as JSON next to the columns worth filtering on |

Every table is `STRICT` (a column holds what it declares; a version is an `INTEGER`, never
`"3"` in one row and `3` in the next). `CHECK`s pin the enumerations (`actor_kind`, `source`,
`status`, `result`), the SHA-256 lengths, DNS-label lengths and `json_valid()` on stored JSON.
Composite keys are `WITHOUT ROWID` so the row is the index: a history lookup touches one B-tree.

### Indexes, and the query each one serves

| Index | Query |
| --- | --- |
| `services (namespace, service)` (unique) | every lookup by `ServiceKey` |
| `services_live (namespace, service) WHERE epoch IS NOT NULL` (partial) | `list_services`, in order, from the index alone |
| `charter_versions` primary key | `get_charter` (current version), `history` (`ORDER BY version DESC`), `get_revision` |
| `notes` primary key | `get_memory` (`ORDER BY agent, seq`), the per-service replace in `put_memory` |
| `notes_expiring (expires_at) WHERE expires_at IS NOT NULL` (partial) | a sweep of expired `auto` notes reads only expiring notes |
| `proposals_dedup (service_id, dedup_key) WHERE dedup_key IS NOT NULL` (partial unique) | the sidecar's duplicate check, and the duplicate guard itself |
| `proposals_newest (ts DESC, id DESC)` | `GET /proposals` without a filter |
| `proposals_by_status (status, ts DESC, id DESC)` | `GET /proposals?status=` |
| `proposals_by_service (service_id, status, ts DESC, id DESC)` | `GET /proposals?namespace=&service=[&status=]` |
| `cp_audit_by_ts (ts, seq)`, `cp_audit_by_service (namespace, service, seq) WHERE service IS NOT NULL`, `cp_audit_by_actor (actor, seq)` | operators' questions: what happened when, to a service, by whom |

There is deliberately no index that no query uses: `charter_versions` has nothing beyond its
key, since deleting a service removes its history and the current epoch is therefore all there
is.

### Triggers, and the invariant each one enforces

| Trigger | Enforces |
| --- | --- |
| `charter_versions_next` (BEFORE INSERT) | a stored version is exactly `services.version + 1`: no gaps, no reuse, no two writers racing past each other |
| `charter_versions_bump` (AFTER INSERT) | storing a version moves the service's counter and epoch in the same statement |
| `charter_versions_immutable` (BEFORE UPDATE) | history is written once |
| `services_version_monotonic`, `services_memory_version_monotonic` | the counters never go down, whoever writes them |
| `services_retired` (AFTER UPDATE OF epoch to NULL) | deleting a service drops its history, notes and proposals and keeps the row and counters, so a recreated service continues the sequence in a new epoch |
| `services_touch` | `updated_at` follows every change |
| `proposals_decided_once` | of an approve and a reject racing for one proposal exactly one wins; a decided proposal never changes status again (the `CHECK` on `decided_at` makes the decision time mandatory with the decision) |
| `cp_audit_no_update`, `cp_audit_no_delete` | the audit is append-only, also for a `sqlite3` shell |

The Rust side still checks every precondition first and returns the trait's errors
(`Conflict`, `NotFound`, `NotPending`, `Invalid`); the triggers are the floor under it, not the
error path. What needs the charter's content (learning enabled, `max_notes`, `max_note_chars`)
stays in `decide_proposal`, shared with the other stores.

### Running it

- One connection behind one mutex; every `Store` call is one transaction on tokio's blocking
  pool, so a call is one critical section like the file store's, and a reader never sees a
  half-written service.
- `journal_mode=WAL` (readers never block the writer; a `sqlite3 -readonly` shell is safe while
  embassy runs), `synchronous=NORMAL` (durable across a process crash; the last transactions may
  be lost on a power cut, the same trade the file store's `rename` makes), `foreign_keys=ON`
  (SQLite defaults it off), `busy_timeout=5000`.
- Schema changes are numbered migrations keyed by `user_version`; a file written by a newer
  embassy is refused with a message, never silently downgraded.

## Consequences

- One file to back up (`sqlite3 <path> ".backup <copy>"` while running), one file to inspect,
  and queries by actor, service or time that the file layout could not answer without a script.
- No external editor: charters change through the API, the console or `kubectl`, not by editing
  files next to the database. The file store keeps that feature for the people who want it.
- A single writer, which matches the control plane's one-replica design (the registry and event
  ring are in memory too). A second embassy on the same file would wait on the lock and see
  nothing of the first's memory state; do not run that.
- `rusqlite` with the bundled SQLite adds a C build to the embassy crate (no system library at
  run time) and a lock-file update.
- The audit table repeats what stdout and the `.audit.jsonl` of the file store carry; it is the
  queryable copy, and the immutability triggers make it the one to show an auditor.

## Alternatives

- **PostgreSQL.** The right choice once there are several control-plane replicas or a fleet of
  clusters reporting to one place. Today it would add a server to a single-binary control plane
  for one writer. The schema above is plain SQL with no SQLite-only types; a Postgres store can
  reuse it (partial indexes, `CHECK`s and triggers all exist there) behind the same trait.
- **Indexes on the file store's JSON** (an index file per query). Rebuilt on start and
  unenforced; the gap this record closes is enforcement, not lookups.
- **One `memory` JSON column instead of `notes` rows.** Simpler to write, impossible to index
  by agent or expiry and impossible to constrain; the rows cost nothing extra at the sizes in
  play (at most `max_notes` per agent).
