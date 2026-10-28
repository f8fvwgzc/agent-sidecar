# The evidence ledger

Status: implemented: the format and the offline verifier (#28, crate `agentsc-ledger`,
`agentsc verify`), and embassy's storage, sealing and export (#29). Contract:
[CONTRACT.md](../../CONTRACT.md) §6.3. Part of the AgentSecOps merge
([agentsecops-merge.md](agentsecops-merge.md) §3.1, step "Ledger").

Audit records carry a hash of each payload, but nothing linked one record to the next, so a
deleted record, or one edited together with its hashes, could not be shown. The ledger makes
the records evidence: embassy chains them as they arrive, signs the chains, and exports a chain
as a bundle that anyone with the public keys can check offline.

## Decisions

1. **A chain is one run** (the records of one `request_id`, across services and hops), not one
   service or one sidecar stream. A run is what an auditor asks about and what a bundle should
   hold. A chain per service would make every run's bundle carry other runs' records, or need
   inclusion proofs. nexc-engine chains spans per run too (`domain/trace.rs`) and seals each
   run. Records that belong to no run (`config`) chain per service.
2. **The order is embassy's order of arrival.** Sidecars of different services send a run's
   records at different times; embassy appends each as it takes it in, and `ingested_at` is in
   the hash. The chain proves what embassy received and in what order. It cannot prove what a
   sidecar never sent: the sidecar outbox is in memory and drops the oldest when full
   (`Heartbeat.audit_dropped` counts those).
3. **Hashes over canonical JSON.** Every hash and statement is over compact JSON with sorted
   keys (nexc's rule: its canonical structs serialize with sorted keys). The workspace builds
   `serde_json` with `preserve_order`, so the ledger sorts explicitly. A bundle re-indented or
   reordered by a tool still verifies, and a stored record is kept as its canonical text, never
   as a database JSON type that would rewrite numbers.
4. **A tag, then the previous hash, then the entry.** `"agentsc-ledger-entry-v1\0"` keeps a
   ledger hash from being any other protocol's. The entry hashes its own `seq` and `chain`, so it
   cannot be moved within a chain or to another one. A fixed vector is pinned in the tests;
   changing the format means a new tag.
5. **Ed25519 seals over the exact statement text, RFC 7638 key ids.** This is nexc-engine's
   scheme (`domain/seal.rs`, `security/signing.rs`), so one JWKS format and one key id rule
   serve both, and nexc's published keys can sit next to attache's as retired keys after the
   import (step 7). A seal says how many entries it covers: a chain that keeps growing is sealed
   again, and every seal stays valid for its prefix.
6. **The verifier runs every check and names the ones that fail** (`format`, `chain`, `seals`),
   with nexc-verify's exit codes: 0 verifies, 1 a check fails, 2 the input cannot be read.
   "One seal covers every entry" is its own rule, so a record taken off the end, or added after
   the last seal, is found even though the chain left still holds.
7. **Keys come from a file until Tutela's vault has an API for them.** The signing key is a
   32-byte Ed25519 seed in standard base64 (nexc's `NEXC_SIGNING_KEY` form). The crate uses
   `ring`, the provider the workspace's rustls already links. No new crypto dependency.

8. **embassy appends after the drop rules, in one transaction per batch.** What the ledger
   holds is what the control plane accepted, with the `agent_id` it filled. A ledger failure is
   logged and counted, never pushed back on the sidecar: its records still reach the live views.
9. **The database is the floor under the hashes.** Triggers make entries, seals and heads
   append-only, refuse an entry that does not follow its chain's head, and refuse a seal of
   entries that do not exist, so a bug or a hand edit cannot leave a chain that verifies wrong.
   A record is kept as its canonical text (`text` in PostgreSQL, never `jsonb`).
10. **Sealing waits for a quiet chain.** A run's records arrive over seconds from several
    sidecars; sealing each one would sign a statement per record. The sealer signs a chain once
    it has had no new entry for `--ledger-seal-after`; an export seals first, so a bundle is
    always sealed up to its last entry when there is a key. Without a key file the ledger still
    chains, and embassy logs that seals are off.
11. **Scope follows the records.** A run can cross namespaces; its bundle is for callers who may
    see all of them, and payloads (only present with `telemetry.control_plane_payloads`) need
    the payload permission, as in the live views.

## What it does not do yet

- Verify nexc-engine's own bundles (`nexc-evidence-bundle/v1`). That belongs to the data import
  of the merge (step 7), when nexc's spans and audit chain are imported byte for byte.
- Retention and purging of old chains (#31).
- Keys from Tutela's vault instead of a file: the vault has no key-signing API yet.
