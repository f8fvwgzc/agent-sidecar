-- The SQLite store, migration 3 (docs/design/evidence-ledger.md, CONTRACT.md §6.3): the evidence
-- ledger. One chain per run; an entry's hash is computed by embassy (agentsc-ledger) and the
-- triggers are the floor under it: an entry is exactly the next one of its chain and follows its
-- head, entries and seals are never changed or removed, and a head never goes back. Never edit
-- this file: a change is the next migration.

CREATE TABLE ledger_heads (
  chain      TEXT PRIMARY KEY CHECK (length(chain) BETWEEN 1 AND 300),
  entries    INTEGER NOT NULL DEFAULT 0 CHECK (entries >= 0),
  head       TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'
             CHECK (length(head) = 64),
  sealed     INTEGER NOT NULL DEFAULT 0 CHECK (sealed >= 0 AND sealed <= entries),
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX ledger_heads_updated ON ledger_heads (updated_at);
CREATE INDEX ledger_heads_unsealed ON ledger_heads (updated_at) WHERE sealed < entries;

CREATE TABLE ledger_entries (
  chain       TEXT NOT NULL REFERENCES ledger_heads (chain),
  seq         INTEGER NOT NULL CHECK (seq >= 0),
  ingested_at TEXT NOT NULL,
  record      TEXT NOT NULL CHECK (json_valid(record)),
  prev_hash   TEXT NOT NULL CHECK (length(prev_hash) = 64),
  hash        TEXT NOT NULL CHECK (length(hash) = 64),
  namespace   TEXT NOT NULL,
  service     TEXT NOT NULL,
  agent_id    TEXT,
  kind        TEXT NOT NULL,
  PRIMARY KEY (chain, seq)
) STRICT;

CREATE TABLE ledger_chain_services (
  chain     TEXT NOT NULL REFERENCES ledger_heads (chain),
  namespace TEXT NOT NULL,
  service   TEXT NOT NULL,
  PRIMARY KEY (chain, namespace, service)
) STRICT;

CREATE INDEX ledger_chain_services_by_service ON ledger_chain_services (namespace, service);

CREATE TABLE ledger_seals (
  chain     TEXT NOT NULL REFERENCES ledger_heads (chain),
  entries   INTEGER NOT NULL CHECK (entries > 0),
  statement TEXT NOT NULL,
  signature TEXT NOT NULL CHECK (length(signature) = 128),
  kid       TEXT NOT NULL,
  sealed_at TEXT NOT NULL,
  PRIMARY KEY (chain, entries)
) STRICT;

-- an entry is the next one of its chain and follows its head; then it is the head
CREATE TRIGGER ledger_entries_next BEFORE INSERT ON ledger_entries
WHEN NEW.seq <> (SELECT entries FROM ledger_heads WHERE chain = NEW.chain)
  OR NEW.prev_hash <> (SELECT head FROM ledger_heads WHERE chain = NEW.chain)
BEGIN
  SELECT RAISE(ABORT, 'a ledger entry must follow the head of its chain');
END;

CREATE TRIGGER ledger_entries_bump AFTER INSERT ON ledger_entries
BEGIN
  UPDATE ledger_heads SET entries = NEW.seq + 1, head = NEW.hash, updated_at = NEW.ingested_at
  WHERE chain = NEW.chain;
END;

CREATE TRIGGER ledger_entries_no_update BEFORE UPDATE ON ledger_entries
BEGIN
  SELECT RAISE(ABORT, 'the ledger is append-only');
END;

CREATE TRIGGER ledger_entries_no_delete BEFORE DELETE ON ledger_entries
BEGIN
  SELECT RAISE(ABORT, 'the ledger is append-only');
END;

-- a seal covers entries that exist
CREATE TRIGGER ledger_seals_covered BEFORE INSERT ON ledger_seals
WHEN NEW.entries > (SELECT entries FROM ledger_heads WHERE chain = NEW.chain)
BEGIN
  SELECT RAISE(ABORT, 'a seal covers entries that exist');
END;

CREATE TRIGGER ledger_seals_mark AFTER INSERT ON ledger_seals
BEGIN
  UPDATE ledger_heads SET sealed = max(sealed, NEW.entries) WHERE chain = NEW.chain;
END;

CREATE TRIGGER ledger_seals_no_update BEFORE UPDATE ON ledger_seals
BEGIN
  SELECT RAISE(ABORT, 'the ledger is append-only');
END;

CREATE TRIGGER ledger_seals_no_delete BEFORE DELETE ON ledger_seals
BEGIN
  SELECT RAISE(ABORT, 'the ledger is append-only');
END;

CREATE TRIGGER ledger_heads_forward BEFORE UPDATE ON ledger_heads
WHEN NEW.entries < OLD.entries OR NEW.sealed < OLD.sealed OR NEW.chain <> OLD.chain
BEGIN
  SELECT RAISE(ABORT, 'a ledger head never goes back');
END;

CREATE TRIGGER ledger_heads_no_delete BEFORE DELETE ON ledger_heads
BEGIN
  SELECT RAISE(ABORT, 'the ledger is append-only');
END;
