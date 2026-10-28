-- The embassy PostgreSQL store, migration 2 (docs/design/agent-registry.md, secops/mod.rs): the
-- agent registry, as in the SQLite store's migration 2. An agent is never deleted and its id,
-- service and name never change, so an id names one agent for good; a retired agent declared
-- again is active again with the same id.

CREATE TABLE agents (
  id         text COLLATE "C" PRIMARY KEY CHECK (length(id) = 40 AND left(id, 4) = 'agt_'),
  namespace  text COLLATE "C" NOT NULL CHECK (length(namespace) BETWEEN 1 AND 63),
  service    text COLLATE "C" NOT NULL CHECK (length(service) BETWEEN 1 AND 63),
  name       text COLLATE "C" NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
  status     text NOT NULL CHECK (status IN ('active', 'retired')),
  created_at text COLLATE "C" NOT NULL,
  updated_at text COLLATE "C" NOT NULL,
  UNIQUE (namespace, service, name)
);

CREATE TABLE agent_aliases (
  alias      text COLLATE "C" PRIMARY KEY CHECK (length(alias) BETWEEN 1 AND 256),
  agent_id   text COLLATE "C" NOT NULL REFERENCES agents (id),
  created_at text NOT NULL,
  created_by text NOT NULL
);

CREATE INDEX agent_aliases_agent ON agent_aliases (agent_id);

CREATE FUNCTION agentsc_agents_identity_fixed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'an agent''s id, service and name never change';
END $$;

CREATE TRIGGER agents_identity_fixed BEFORE UPDATE OF id, namespace, service, name, created_at ON agents
  FOR EACH ROW EXECUTE FUNCTION agentsc_agents_identity_fixed();

CREATE TRIGGER agents_never_deleted BEFORE DELETE ON agents
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();

CREATE TRIGGER agents_never_truncated BEFORE TRUNCATE ON agents
  FOR EACH STATEMENT EXECUTE FUNCTION agentsc_immutable();
