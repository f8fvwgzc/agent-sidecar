-- The SQLite store, migration 2 (docs/design/agent-registry.md, secops/mod.rs): the agent
-- registry. An agent is never deleted and its id, service and name never change, so an id names
-- one agent for good; a retired agent declared again is active again with the same id. Never
-- edit this file: a change is the next migration.

CREATE TABLE agents (
  id         TEXT PRIMARY KEY CHECK (length(id) = 40 AND substr(id, 1, 4) = 'agt_'),
  namespace  TEXT NOT NULL CHECK (length(namespace) BETWEEN 1 AND 63),
  service    TEXT NOT NULL CHECK (length(service) BETWEEN 1 AND 63),
  name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
  status     TEXT NOT NULL CHECK (status IN ('active', 'retired')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (namespace, service, name)
) STRICT;

CREATE TABLE agent_aliases (
  alias      TEXT PRIMARY KEY CHECK (length(alias) BETWEEN 1 AND 256),
  agent_id   TEXT NOT NULL REFERENCES agents (id),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
) STRICT;

CREATE INDEX agent_aliases_agent ON agent_aliases (agent_id);

CREATE TRIGGER agents_identity_fixed BEFORE UPDATE OF id, namespace, service, name, created_at ON agents
BEGIN
  SELECT RAISE(ABORT, 'an agent''s id, service and name never change');
END;

CREATE TRIGGER agents_never_deleted BEFORE DELETE ON agents
BEGIN
  SELECT RAISE(ABORT, 'agents are never deleted');
END;
