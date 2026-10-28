-- The embassy PostgreSQL store, migration 4 (CONTRACT.md §5.3, secops/mod.rs): an agent's
-- quarantine, as in the SQLite store's migration 4: a time, a reason and an actor, all or none.

ALTER TABLE agents
  ADD COLUMN quarantined_at text,
  ADD COLUMN quarantine_reason text,
  ADD COLUMN quarantined_by text,
  ADD CONSTRAINT agents_quarantine_whole CHECK (
    (quarantined_at IS NULL) = (quarantine_reason IS NULL)
    AND (quarantined_at IS NULL) = (quarantined_by IS NULL)
  );
