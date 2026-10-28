# Agent principals and the agent registry

Status: implemented (#23). Contract: [CONTRACT.md](../../CONTRACT.md) §5.3, §6. Part of the
AgentSecOps merge ([agentsecops-merge.md](agentsecops-merge.md) §4, step "Registry").

An agent used to be a name inside its service's charter. Approvals, risk scores, quarantine and
the evidence ledger need to name one agent across charter edits, and Tutela's delegated tokens
need an agent principal (`act.sub = agent:agt_…`). This note says what that principal is, who
mints it, and how the rest of attache learns it.

## Decisions

1. **The principal is Tutela's: `agent:agt_<uuidv7>`.** Tutela defines the principal kinds
   (`tutela-contracts`, `principal.rs`), and other cores will check tokens whose `act.sub` names
   an agent. attache checks Tutela's text rules itself (`agentsc_common::principal`) and does not
   link `tutela-contracts` yet: Tutela has no tagged release, and the rule is to depend only on a
   published crate or a tag (#26). Conformance tests run Tutela's own examples.
2. **embassy mints the ids, from the charter.** Tutela's integration plan makes attache's
   registry the system of record. An id is minted the first time a stored charter declares the
   agent, whatever wrote it (API, adoption, rollback, a file-store edit, a Charter CR, another
   replica): the hub follows the store's `CharterChanged` and `ServiceDeleted` events, and syncs
   everything once at start. Nothing new is needed on the write path, and a charter is still the
   only thing an author edits.
3. **An agent is `(namespace, service, name)`, for good.** Removed from the charter, it is
   `retired`, not deleted; declared again, it is `active` with the same id. Traces and evidence
   that name the id keep resolving, and an id never names a different agent. A new agent of the
   same name in another service is another agent. Triggers in both SQL stores refuse a delete or
   a change of id, service or name.
4. **A charter that cannot be read retires nothing.** Only a charter that is gone (the service
   deleted) or declares other agents retires one; a store error or an unparsable charter leaves
   the registry as it is.
5. **The workload path stays `/ns/<namespace>/svc/<service>`.** Tutela's examples use
   `/ns/<ns>/sa/<sa>`, but its parser accepts any path. attache's path is in every certificate
   embassy issued and every charter's `authz` rules; a service may run under several service
   accounts (`service.service_accounts`); and the agent, not the pod, is now the per-agent
   principal. Tutela is asked to use attache's form in its examples (f8fvwgzc/tutela#29).
6. **The registry lives in the SQL stores.** It is the first AgentSecOps table set, with the
   ledger, approvals and risk to follow: the SQLite store (development, one process) and the
   PostgreSQL store (many replicas) each get a migration (2). The file store, used by the demos,
   keeps it in a SQLite database beside its directory (`<dir>/.secops.sqlite3`). The Kubernetes
   store has none unless `--secops-store sqlite:<path> | postgres` says where; without one the
   API answers `503 secops_unavailable` and sidecars get no ids. A separate `SecOpsStore` trait
   keeps these tables out of the four-backend `Store` trait.
7. **Replicas serialize per service.** A PostgreSQL sync takes a transaction-scoped advisory
   lock on its service, so two replicas that follow the same `CharterChanged` register each new
   agent once (the second finds nothing to do), and only the replica that made a change audits
   it. Every replica pushes the ids to its own sidecars after its sync, so no new notification
   kind is needed.
8. **Sidecars stamp the ids.** `ControlMessage.agent_ids` (`AgentIds`, agent name → id) is sent
   after the charter and memory of each `Connect` stream and after every sync of the service. The
   sidecar's audit writer stamps `agent_id` on every record of a known agent; the field is left
   out, not `null`, when unknown, so an unmanaged sidecar's records are unchanged. embassy fills
   it on records that arrive without it (older sidecars, records sent before the ids).
9. **Aliases for imported names.** nexc-engine names agents `agent://<workspace>/<name>`;
   such names become aliases (admin, audited), so imported traces resolve.

10. **Quarantine is the registry's, not the charter's.** A quarantine is a state of one agent
    (when, why, by whom), set and lifted by an admin (#33). It is not a charter edit, so it
    needs no charter version or schema level, and the sidecars refuse everything the agent does
    (nexc-engine refuses all of a quarantined agent's calls, not some). It is pushed as its own
    `ControlMessage` variant, a full replacement per service, and every replica learns of a
    change through PostgreSQL's `NOTIFY` (a new store event), so sidecars connected anywhere
    get it. A run in flight is stopped at its next tool call, and a release is manual only.

## What it does not do yet

- Create and disable the principal in Tutela (`tutela.admin.v1`) and delegated agent tokens
  (RFC 8693): both need `tutelad`, Tutela phase B (#24, #25). The audit records of every
  registration, retirement and reactivation are what a later sync replays.
- The risk score that quarantines by itself (#34) and human approvals (#35).
