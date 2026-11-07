-- The embassy PostgreSQL store, migration 9 (CONTRACT.md §5.3, tutela/sync.rs): an agent's
-- principal in tutelad, as in the SQLite store's migration 9. All four columns are set together or
-- not at all; one principal names one agent.

ALTER TABLE agents
  ADD COLUMN tutela_principal text COLLATE "C"
    CHECK (tutela_principal IS NULL OR (length(tutela_principal) = 46 AND left(tutela_principal, 10) = 'agent:agt_')),
  ADD COLUMN tutela_epoch bigint CHECK (tutela_epoch IS NULL OR tutela_epoch >= 0),
  ADD COLUMN tutela_disabled boolean,
  ADD COLUMN tutela_synced_at text COLLATE "C",
  ADD CONSTRAINT agents_tutela_principal_unique UNIQUE (tutela_principal),
  ADD CONSTRAINT agents_tutela_whole CHECK (
    (tutela_principal IS NULL) = (tutela_epoch IS NULL)
    AND (tutela_principal IS NULL) = (tutela_disabled IS NULL)
    AND (tutela_principal IS NULL) = (tutela_synced_at IS NULL)
  );
