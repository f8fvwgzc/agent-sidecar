-- The SQLite store, migration 6 (CONTRACT.md §5.5, secops/risk.rs): risk scores and baselines.
-- A run's chain is scored once; a score is never changed or removed. Never edit this file.

ALTER TABLE ledger_heads ADD COLUMN risk_scored INTEGER NOT NULL DEFAULT 0 CHECK (risk_scored IN (0, 1));
CREATE INDEX ledger_heads_unscored ON ledger_heads (updated_at) WHERE risk_scored = 0;

CREATE TRIGGER ledger_heads_scored_once BEFORE UPDATE OF risk_scored ON ledger_heads
WHEN NEW.risk_scored < OLD.risk_scored
BEGIN
  SELECT RAISE(ABORT, 'a run is scored once');
END;

CREATE TABLE agent_baselines (
  agent_id   TEXT PRIMARY KEY REFERENCES agents (id),
  runs       INTEGER NOT NULL CHECK (runs >= 0),
  state      TEXT NOT NULL CHECK (json_valid(state)),
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE agent_risk (
  agent_id  TEXT NOT NULL REFERENCES agents (id),
  chain     TEXT NOT NULL,
  score     REAL NOT NULL CHECK (score >= 0),
  reasons   TEXT NOT NULL CHECK (json_valid(reasons)),
  novelty   REAL NOT NULL,
  scored_at TEXT NOT NULL,
  PRIMARY KEY (agent_id, chain)
) STRICT;

CREATE INDEX agent_risk_latest ON agent_risk (agent_id, scored_at);

CREATE TRIGGER agent_risk_no_update BEFORE UPDATE ON agent_risk
BEGIN
  SELECT RAISE(ABORT, 'a risk score is never changed');
END;

CREATE TRIGGER agent_risk_no_delete BEFORE DELETE ON agent_risk
BEGIN
  SELECT RAISE(ABORT, 'a risk score is never removed');
END;
