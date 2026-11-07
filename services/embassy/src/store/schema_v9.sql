-- The SQLite store, migration 9 (CONTRACT.md §5.3, tutela/sync.rs): an agent's principal in
-- tutelad, made by tutelad when embassy registers the agent (tutela.admin.v1 RegisterAgent), and
-- what tutelad last answered for it. All four columns are set together or not at all; one
-- principal names one agent. Never edit this file: a change is the next migration.

ALTER TABLE agents ADD COLUMN tutela_principal TEXT
  CHECK (tutela_principal IS NULL OR (length(tutela_principal) = 46 AND substr(tutela_principal, 1, 10) = 'agent:agt_'));
ALTER TABLE agents ADD COLUMN tutela_epoch INTEGER CHECK (tutela_epoch IS NULL OR tutela_epoch >= 0);
ALTER TABLE agents ADD COLUMN tutela_disabled INTEGER CHECK (tutela_disabled IS NULL OR tutela_disabled IN (0, 1));
ALTER TABLE agents ADD COLUMN tutela_synced_at TEXT;

CREATE UNIQUE INDEX agents_tutela_principal ON agents (tutela_principal) WHERE tutela_principal IS NOT NULL;

CREATE TRIGGER agents_tutela_whole BEFORE UPDATE OF tutela_principal, tutela_epoch, tutela_disabled, tutela_synced_at ON agents
WHEN (NEW.tutela_principal IS NULL) <> (NEW.tutela_epoch IS NULL)
  OR (NEW.tutela_principal IS NULL) <> (NEW.tutela_disabled IS NULL)
  OR (NEW.tutela_principal IS NULL) <> (NEW.tutela_synced_at IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'a tutela principal has an epoch, a disabled flag and a time');
END;
