-- The SQLite store, migration 5 (CONTRACT.md §5.4, secops/approvals.rs): approvals of tool calls.
-- An approval is decided once (pending, then approved, denied or expired, for good) and never
-- removed. Never edit this file: a change is the next migration.

CREATE TABLE approvals (
  id              TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
  namespace       TEXT NOT NULL,
  service         TEXT NOT NULL,
  agent           TEXT NOT NULL,
  agent_id        TEXT,
  tool            TEXT NOT NULL,
  request_id      TEXT NOT NULL,
  trace_id        TEXT NOT NULL,
  args_sha256     TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  requested_at    TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  decided_at      TEXT,
  decided_by      TEXT,
  decision_reason TEXT,
  CHECK ((status = 'pending') = (decided_at IS NULL))
) STRICT;

CREATE INDEX approvals_pending ON approvals (expires_at) WHERE status = 'pending';
CREATE INDEX approvals_by_service ON approvals (namespace, service, requested_at);
CREATE INDEX approvals_pending_agent ON approvals (namespace, service, agent) WHERE status = 'pending';

CREATE TRIGGER approvals_decided_once BEFORE UPDATE ON approvals
WHEN OLD.status <> 'pending'
BEGIN
  SELECT RAISE(ABORT, 'an approval is decided once');
END;

CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
BEGIN
  SELECT RAISE(ABORT, 'approvals are never removed');
END;
