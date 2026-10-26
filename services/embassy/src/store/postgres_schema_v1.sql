-- The embassy PostgreSQL store, migration 1 (store/postgres.rs, docs/design/agentsecops-merge.md
-- §7): the SQLite store's tables (store/schema.sql) in PostgreSQL types, with the same
-- invariants as triggers, plus `pending_adoptions`, which the single-process stores keep in
-- memory and many replicas must share. Text keys are COLLATE "C", so they sort bytewise like
-- SQLite's. Timestamps of records are RFC 3339 UTC text with milliseconds, as everywhere in the
-- control plane.

CREATE TABLE services (
  id             bigserial PRIMARY KEY,
  namespace      text COLLATE "C" NOT NULL CHECK (length(namespace) BETWEEN 1 AND 63),
  service        text COLLATE "C" NOT NULL CHECK (length(service) BETWEEN 1 AND 63),
  epoch          text,
  version        bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
  memory_version bigint NOT NULL DEFAULT 0 CHECK (memory_version >= 0),
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (namespace, service)
);

CREATE INDEX services_live ON services (namespace, service) WHERE epoch IS NOT NULL;

CREATE TABLE charter_versions (
  service_id bigint NOT NULL REFERENCES services (id) ON DELETE CASCADE,
  version    bigint NOT NULL,
  epoch      text NOT NULL,
  yaml       text NOT NULL,
  json       jsonb NOT NULL,
  sha256     text NOT NULL CHECK (length(sha256) = 64),
  ts         text COLLATE "C" NOT NULL,
  actor      text NOT NULL,
  actor_kind text NOT NULL CHECK (actor_kind IN ('session', 'token', 'sidecar', 'k8s', 'system')),
  actor_role text CHECK (actor_role IN ('viewer', 'editor', 'admin')),
  source     text NOT NULL CHECK (source IN ('api', 'kubernetes', 'adopt', 'rollback', 'file')),
  PRIMARY KEY (service_id, version)
);

CREATE TABLE notes (
  service_id  bigint NOT NULL REFERENCES services (id) ON DELETE CASCADE,
  agent       text COLLATE "C" NOT NULL,
  seq         bigint NOT NULL,
  id          text NOT NULL,
  text        text NOT NULL,
  source      text NOT NULL CHECK (source IN ('review', 'auto', 'manual')),
  request_id  text,
  trace_id    text,
  approved_by text,
  ts          text NOT NULL,
  expires_at  text,
  PRIMARY KEY (service_id, agent, seq)
);

CREATE INDEX notes_expiring ON notes (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE proposals (
  id         text COLLATE "C" PRIMARY KEY,
  service_id bigint NOT NULL REFERENCES services (id) ON DELETE CASCADE,
  agent      text NOT NULL,
  note       text NOT NULL,
  rationale  text NOT NULL,
  request_id text NOT NULL,
  trace_id   text NOT NULL,
  ts         text COLLATE "C" NOT NULL,
  status     text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  auto       boolean NOT NULL,
  dedup_key  text,
  decided_at text,
  decided_by text,
  CHECK ((status = 'pending') = (decided_at IS NULL))
);

CREATE UNIQUE INDEX proposals_dedup ON proposals (service_id, dedup_key) WHERE dedup_key IS NOT NULL;
CREATE INDEX proposals_newest ON proposals (ts DESC, id DESC);
CREATE INDEX proposals_by_status ON proposals (status, ts DESC, id DESC);
CREATE INDEX proposals_by_service ON proposals (service_id, status, ts DESC, id DESC);

-- A sidecar's start-up charter for a service without one (design §7), shared by the replicas.
CREATE TABLE pending_adoptions (
  namespace text COLLATE "C" NOT NULL,
  service   text COLLATE "C" NOT NULL,
  sha256    text NOT NULL CHECK (length(sha256) = 64),
  pod       text NOT NULL,
  ts        text NOT NULL,
  yaml      text NOT NULL,
  PRIMARY KEY (namespace, service)
);

CREATE TABLE cp_audit (
  seq           bigserial PRIMARY KEY,
  ts            text COLLATE "C" NOT NULL,
  actor         text NOT NULL,
  actor_kind    text NOT NULL CHECK (actor_kind IN ('session', 'token', 'sidecar', 'k8s', 'system')),
  role          text CHECK (role IN ('viewer', 'editor', 'admin')),
  action        text NOT NULL,
  namespace     text,
  service       text,
  agent         text,
  from_version  text,
  to_version    text,
  sha256_before text CHECK (sha256_before IS NULL OR length(sha256_before) = 64),
  sha256_after  text CHECK (sha256_after IS NULL OR length(sha256_after) = 64),
  result        text NOT NULL CHECK (result IN ('ok', 'denied', 'invalid', 'error')),
  reason        text,
  record        jsonb NOT NULL
);

CREATE INDEX cp_audit_by_ts ON cp_audit (ts, seq);
CREATE INDEX cp_audit_by_service ON cp_audit (namespace, service, seq) WHERE service IS NOT NULL;
CREATE INDEX cp_audit_by_actor ON cp_audit (actor, seq);

-- ---- triggers ---------------------------------------------------------------------------------

CREATE FUNCTION agentsc_services_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.version < OLD.version THEN
    RAISE EXCEPTION 'a charter version is never reused';
  END IF;
  IF NEW.memory_version < OLD.memory_version THEN
    RAISE EXCEPTION 'a memory version is never reused';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;

CREATE TRIGGER services_guard BEFORE UPDATE ON services
  FOR EACH ROW EXECUTE FUNCTION agentsc_services_guard();

-- Deleting a service retires it: the epoch goes, and with it the history, notes and proposals;
-- the row and its counters stay.
CREATE FUNCTION agentsc_services_retired() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM charter_versions WHERE service_id = NEW.id;
  DELETE FROM notes WHERE service_id = NEW.id;
  DELETE FROM proposals WHERE service_id = NEW.id;
  RETURN NULL;
END $$;

CREATE TRIGGER services_retired AFTER UPDATE OF epoch ON services
  FOR EACH ROW WHEN (NEW.epoch IS NULL AND OLD.epoch IS NOT NULL)
  EXECUTE FUNCTION agentsc_services_retired();

-- A stored charter version is exactly the service's next one, and moves its counter and epoch.
CREATE FUNCTION agentsc_charter_versions_next() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.version <> (SELECT version FROM services WHERE id = NEW.service_id) + 1 THEN
    RAISE EXCEPTION 'a charter version must be the service''s next version';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER charter_versions_next BEFORE INSERT ON charter_versions
  FOR EACH ROW EXECUTE FUNCTION agentsc_charter_versions_next();

CREATE FUNCTION agentsc_charter_versions_bump() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE services SET version = NEW.version, epoch = NEW.epoch WHERE id = NEW.service_id;
  RETURN NULL;
END $$;

CREATE TRIGGER charter_versions_bump AFTER INSERT ON charter_versions
  FOR EACH ROW EXECUTE FUNCTION agentsc_charter_versions_bump();

CREATE FUNCTION agentsc_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;

CREATE TRIGGER charter_versions_immutable BEFORE UPDATE ON charter_versions
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();

-- A decided proposal is decided for good (of an approve and a reject racing, exactly one wins).
CREATE FUNCTION agentsc_proposals_decided_once() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'the proposal is no longer pending';
END $$;

CREATE TRIGGER proposals_decided_once BEFORE UPDATE OF status ON proposals
  FOR EACH ROW WHEN (OLD.status <> 'pending' AND NEW.status <> OLD.status)
  EXECUTE FUNCTION agentsc_proposals_decided_once();

-- The control-plane audit is append-only: no UPDATE, DELETE or TRUNCATE.
CREATE TRIGGER cp_audit_no_update BEFORE UPDATE OR DELETE ON cp_audit
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();

CREATE TRIGGER cp_audit_no_truncate BEFORE TRUNCATE ON cp_audit
  FOR EACH STATEMENT EXECUTE FUNCTION agentsc_immutable();
