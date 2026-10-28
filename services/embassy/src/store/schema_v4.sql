-- The SQLite store, migration 4 (CONTRACT.md §5.3, secops/mod.rs): an agent's quarantine. While
-- `quarantined_at` is set the agent's sidecars refuse everything it does; a quarantine has a
-- time, a reason and an actor, all or none. Never edit this file: a change is the next migration.

ALTER TABLE agents ADD COLUMN quarantined_at TEXT;
ALTER TABLE agents ADD COLUMN quarantine_reason TEXT;
ALTER TABLE agents ADD COLUMN quarantined_by TEXT;

CREATE TRIGGER agents_quarantine_whole BEFORE UPDATE OF quarantined_at, quarantine_reason, quarantined_by ON agents
WHEN (NEW.quarantined_at IS NULL) <> (NEW.quarantine_reason IS NULL)
  OR (NEW.quarantined_at IS NULL) <> (NEW.quarantined_by IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'a quarantine has a time, a reason and an actor');
END;
