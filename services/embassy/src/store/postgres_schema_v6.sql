-- The embassy PostgreSQL store, migration 6 (CONTRACT.md §5.5, secops/risk.rs): risk scores and
-- baselines, as in the SQLite store's migration 6.

ALTER TABLE ledger_heads ADD COLUMN risk_scored boolean NOT NULL DEFAULT false;
CREATE INDEX ledger_heads_unscored ON ledger_heads (updated_at) WHERE NOT risk_scored;

CREATE FUNCTION agentsc_ledger_heads_scored_once() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.risk_scored AND NOT NEW.risk_scored THEN
    RAISE EXCEPTION 'a run is scored once';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER ledger_heads_scored_once BEFORE UPDATE OF risk_scored ON ledger_heads
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_heads_scored_once();

CREATE TABLE agent_baselines (
  agent_id   text COLLATE "C" PRIMARY KEY REFERENCES agents (id),
  runs       bigint NOT NULL CHECK (runs >= 0),
  state      text NOT NULL,
  updated_at text NOT NULL
);

CREATE TABLE agent_risk (
  agent_id  text COLLATE "C" NOT NULL REFERENCES agents (id),
  chain     text COLLATE "C" NOT NULL,
  score     double precision NOT NULL CHECK (score >= 0),
  reasons   text NOT NULL,
  novelty   double precision NOT NULL,
  scored_at text COLLATE "C" NOT NULL,
  PRIMARY KEY (agent_id, chain)
);

CREATE INDEX agent_risk_latest ON agent_risk (agent_id, scored_at);

CREATE TRIGGER agent_risk_no_update BEFORE UPDATE OR DELETE ON agent_risk
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();
CREATE TRIGGER agent_risk_no_truncate BEFORE TRUNCATE ON agent_risk
  FOR EACH STATEMENT EXECUTE FUNCTION agentsc_immutable();
