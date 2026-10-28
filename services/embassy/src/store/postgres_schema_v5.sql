-- The embassy PostgreSQL store, migration 5 (CONTRACT.md §5.4, secops/approvals.rs): approvals of
-- tool calls, as in the SQLite store's migration 5: decided once, never removed.

CREATE TABLE approvals (
  id              text COLLATE "C" PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
  namespace       text COLLATE "C" NOT NULL,
  service         text COLLATE "C" NOT NULL,
  agent           text COLLATE "C" NOT NULL,
  agent_id        text,
  tool            text NOT NULL,
  request_id      text NOT NULL,
  trace_id        text NOT NULL,
  args_sha256     text NOT NULL,
  status          text NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  requested_at    text COLLATE "C" NOT NULL,
  expires_at      text COLLATE "C" NOT NULL,
  decided_at      text,
  decided_by      text,
  decision_reason text,
  CHECK ((status = 'pending') = (decided_at IS NULL))
);

CREATE INDEX approvals_pending ON approvals (expires_at) WHERE status = 'pending';
CREATE INDEX approvals_by_service ON approvals (namespace, service, requested_at);
CREATE INDEX approvals_pending_agent ON approvals (namespace, service, agent) WHERE status = 'pending';

CREATE FUNCTION agentsc_approvals_decided_once() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'an approval is decided once';
END $$;

CREATE TRIGGER approvals_decided_once BEFORE UPDATE ON approvals
  FOR EACH ROW WHEN (OLD.status <> 'pending')
  EXECUTE FUNCTION agentsc_approvals_decided_once();

CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();
CREATE TRIGGER approvals_no_truncate BEFORE TRUNCATE ON approvals
  FOR EACH STATEMENT EXECUTE FUNCTION agentsc_immutable();
