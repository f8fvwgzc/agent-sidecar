# Risk scores and automatic quarantine

Status: implemented (#34). Contract: [CONTRACT.md](../../CONTRACT.md) §5.5. Part of the
AgentSecOps merge ([agentsecops-merge.md](agentsecops-merge.md) §3.1 `engine/risk.rs`).

## Decisions

1. **nexc-engine's scoring, ported as is**: its constants (3 runs to learn, z capped at 3 and
   notable from 2, score capped at 10, novelty above 0.8, 20 signatures, 64 new hosts per run),
   its formula, its words for the reasons, and its tests. Shadow comparisons with nexc and its
   baselines (merge step 7) need the same numbers.
2. **Scored from the ledger, once per run.** The ledger holds a run's records from every service
   in arrival order, with the agent's registry id, so the scorer needs nothing new from the
   sidecars. A run is scored once it is quiet (the sealing delay); a replica claims it first, so
   two replicas never learn it twice.
3. **Baselines without lost updates.** A baseline is written only if no other replica wrote it
   since it was read (an optimistic check on its run count), then read and scored again.
4. **One feature less than nexc.** `bytes_out` needs payload sizes; attache's records carry
   hashes, and payloads only with `telemetry.control_plane_payloads`. The other features map one
   to one onto audit record kinds.
5. **The threshold is the control plane's**, in `ControlPlaneConfig.risk.quarantine_score`: a
   security operator's setting, not a charter author's. Absent, nothing is quarantined by score.
   A run that quarantines is not learned (nexc's rule), so an attack does not become the norm.
6. **Mid-run scoring** (nexc scores its external agents live) is not ported: attache's sidecars
   refuse everything at once on a quarantine, and runs are scored seconds after they end.

## What it does not do yet

- Alerts below the quarantine threshold (`alerts.risk_score`, `denials_per_run`, `novelty`):
  part of alerting, a later step of the merge.
