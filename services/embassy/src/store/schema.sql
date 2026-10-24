-- The embassy SQLite store, schema version 1 (docs/adr/0003-sqlite-store-schema.md).
--
-- Applied once by store/sqlite.rs when PRAGMA user_version is 0; a later version adds a
-- numbered migration there and never edits this file. Every table is STRICT (a column holds
-- what it declares) and every relation is a FOREIGN KEY with ON DELETE CASCADE, so a service's
-- children can never outlive it. Timestamps are RFC 3339 UTC text with milliseconds, like every
-- other timestamp of the control plane, so they sort as text.
--
-- Counters (charter version, memory version) live on `services`, never reused, and triggers keep
-- them honest: a stored charter version must be exactly the next one, and the counters never go
-- down. The control-plane audit is append-only: triggers refuse UPDATE and DELETE.

-- One row per service ever seen. `epoch` NULL: no charter is stored (never was, or it was
-- deleted; the counters stay so that versions are never reused and a recreated service gets a
-- new epoch, design §8.4).
CREATE TABLE services (
  id             INTEGER PRIMARY KEY,
  namespace      TEXT    NOT NULL,
  service        TEXT    NOT NULL,
  epoch          TEXT,
  version        INTEGER NOT NULL DEFAULT 0,
  memory_version INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  CHECK (length(namespace) BETWEEN 1 AND 63),
  CHECK (length(service) BETWEEN 1 AND 63),
  CHECK (version >= 0),
  CHECK (memory_version >= 0),
  UNIQUE (namespace, service)
) STRICT;

-- `list_services`: the services with a charter, in order, from the index alone.
CREATE INDEX services_live ON services (namespace, service) WHERE epoch IS NOT NULL;

-- Every stored version of a service's charter, exactly as written; the current one is
-- `services.version`. Immutable once written (trigger below); deleted with the service.
CREATE TABLE charter_versions (
  service_id INTEGER NOT NULL REFERENCES services (id) ON DELETE CASCADE,
  version    INTEGER NOT NULL,
  epoch      TEXT    NOT NULL,
  yaml       TEXT    NOT NULL,
  json       TEXT    NOT NULL CHECK (json_valid(json)),
  sha256     TEXT    NOT NULL CHECK (length(sha256) = 64),
  ts         TEXT    NOT NULL,
  actor      TEXT    NOT NULL,
  actor_kind TEXT    NOT NULL CHECK (actor_kind IN ('session', 'token', 'sidecar', 'k8s', 'system')),
  actor_role TEXT             CHECK (actor_role IN ('viewer', 'editor', 'admin')),
  source     TEXT    NOT NULL CHECK (source IN ('api', 'kubernetes', 'adopt', 'rollback', 'file')),
  PRIMARY KEY (service_id, version)
) WITHOUT ROWID, STRICT;

-- The memory (design §3): one row per note, `seq` is its place among the agent's notes (oldest
-- first). The document's version is `services.memory_version`.
CREATE TABLE notes (
  service_id  INTEGER NOT NULL REFERENCES services (id) ON DELETE CASCADE,
  agent       TEXT    NOT NULL,
  seq         INTEGER NOT NULL,
  id          TEXT    NOT NULL,
  text        TEXT    NOT NULL,
  source      TEXT    NOT NULL CHECK (source IN ('review', 'auto', 'manual')),
  request_id  TEXT,
  trace_id    TEXT,
  approved_by TEXT,
  ts          TEXT    NOT NULL,
  expires_at  TEXT,
  PRIMARY KEY (service_id, agent, seq)
) WITHOUT ROWID, STRICT;

-- Expiring `auto` notes (`ts + note_ttl_days`): the sweep reads only this index.
CREATE INDEX notes_expiring ON notes (expires_at) WHERE expires_at IS NOT NULL;

-- Lesson proposals (design §6.5). `dedup_key` is the sidecar's; one per service.
CREATE TABLE proposals (
  id         TEXT    PRIMARY KEY,
  service_id INTEGER NOT NULL REFERENCES services (id) ON DELETE CASCADE,
  agent      TEXT    NOT NULL,
  note       TEXT    NOT NULL,
  rationale  TEXT    NOT NULL,
  request_id TEXT    NOT NULL,
  trace_id   TEXT    NOT NULL,
  ts         TEXT    NOT NULL,
  status     TEXT    NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  auto       INTEGER NOT NULL CHECK (auto IN (0, 1)),
  dedup_key  TEXT,
  decided_at TEXT,
  decided_by TEXT,
  CHECK ((status = 'pending') = (decided_at IS NULL))
) WITHOUT ROWID, STRICT;

CREATE UNIQUE INDEX proposals_dedup ON proposals (service_id, dedup_key) WHERE dedup_key IS NOT NULL;
-- `GET /proposals` without a filter, with `status=`, and per service (`namespace=&service=`),
-- newest first in each case.
CREATE INDEX proposals_newest ON proposals (ts DESC, id DESC);
CREATE INDEX proposals_by_status ON proposals (status, ts DESC, id DESC);
CREATE INDEX proposals_by_service ON proposals (service_id, status, ts DESC, id DESC);

-- The control-plane audit log (design §8.5), one row per record, the record itself as JSON next
-- to the columns worth filtering on. Append-only.
CREATE TABLE cp_audit (
  seq           INTEGER PRIMARY KEY,
  ts            TEXT NOT NULL,
  actor         TEXT NOT NULL,
  actor_kind    TEXT NOT NULL CHECK (actor_kind IN ('session', 'token', 'sidecar', 'k8s', 'system')),
  role          TEXT          CHECK (role IN ('viewer', 'editor', 'admin')),
  action        TEXT NOT NULL,
  namespace     TEXT,
  service       TEXT,
  agent         TEXT,
  from_version  TEXT,
  to_version    TEXT,
  sha256_before TEXT          CHECK (sha256_before IS NULL OR length(sha256_before) = 64),
  sha256_after  TEXT          CHECK (sha256_after IS NULL OR length(sha256_after) = 64),
  result        TEXT NOT NULL CHECK (result IN ('ok', 'denied', 'invalid', 'error')),
  reason        TEXT,
  record        TEXT NOT NULL CHECK (json_valid(record))
) STRICT;

CREATE INDEX cp_audit_by_ts ON cp_audit (ts, seq);
CREATE INDEX cp_audit_by_service ON cp_audit (namespace, service, seq) WHERE service IS NOT NULL;
CREATE INDEX cp_audit_by_actor ON cp_audit (actor, seq);

-- ---- triggers ---------------------------------------------------------------------------------

-- `updated_at` follows every change of a service row (recursive triggers are off, and the guard
-- keeps this from looping even when they are on).
CREATE TRIGGER services_touch AFTER UPDATE ON services
  WHEN NEW.updated_at = OLD.updated_at
BEGIN
  UPDATE services SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

-- Counters never go down.
CREATE TRIGGER services_version_monotonic BEFORE UPDATE OF version ON services
  WHEN NEW.version < OLD.version
BEGIN
  SELECT RAISE(ABORT, 'a charter version is never reused');
END;

CREATE TRIGGER services_memory_version_monotonic BEFORE UPDATE OF memory_version ON services
  WHEN NEW.memory_version < OLD.memory_version
BEGIN
  SELECT RAISE(ABORT, 'a memory version is never reused');
END;

-- A stored charter version is exactly the service's next one ...
CREATE TRIGGER charter_versions_next BEFORE INSERT ON charter_versions
  WHEN NEW.version <> (SELECT version FROM services WHERE id = NEW.service_id) + 1
BEGIN
  SELECT RAISE(ABORT, 'a charter version must be the service''s next version');
END;

-- ... and storing it moves the service's counter and epoch.
CREATE TRIGGER charter_versions_bump AFTER INSERT ON charter_versions
BEGIN
  UPDATE services SET version = NEW.version, epoch = NEW.epoch WHERE id = NEW.service_id;
END;

CREATE TRIGGER charter_versions_immutable BEFORE UPDATE ON charter_versions
BEGIN
  SELECT RAISE(ABORT, 'a stored charter version is immutable');
END;

-- Deleting a service (`DELETE /services/{ns}/{svc}`) retires it: the epoch goes, and with it
-- the history, the notes and the proposals; the row and its counters stay.
CREATE TRIGGER services_retired AFTER UPDATE OF epoch ON services
  WHEN NEW.epoch IS NULL AND OLD.epoch IS NOT NULL
BEGIN
  DELETE FROM charter_versions WHERE service_id = NEW.id;
  DELETE FROM notes WHERE service_id = NEW.id;
  DELETE FROM proposals WHERE service_id = NEW.id;
END;

-- A decided proposal is decided for good (of an approve and a reject racing, exactly one wins).
CREATE TRIGGER proposals_decided_once BEFORE UPDATE OF status ON proposals
  WHEN OLD.status <> 'pending' AND NEW.status <> OLD.status
BEGIN
  SELECT RAISE(ABORT, 'the proposal is no longer pending');
END;

-- The audit log is append-only.
CREATE TRIGGER cp_audit_no_update BEFORE UPDATE ON cp_audit
BEGIN
  SELECT RAISE(ABORT, 'cp_audit is append-only');
END;

CREATE TRIGGER cp_audit_no_delete BEFORE DELETE ON cp_audit
BEGIN
  SELECT RAISE(ABORT, 'cp_audit is append-only');
END;
