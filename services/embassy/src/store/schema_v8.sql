-- The SQLite store, migration 8 (CONTRACT.md §6.3, secops/ledger.rs): the Append API. Records other
-- services forward go into ordinary chains; this table remembers each one by its (service, id), so
-- a retry is acknowledged with the place it already has, and the same key with another payload is
-- refused. Rows are append-only and outlive a purge of their chain. Never edit this file.

CREATE TABLE ledger_forwarded (
  service      TEXT NOT NULL,
  id           TEXT NOT NULL,
  tenant       TEXT NOT NULL,
  producer_seq INTEGER NOT NULL CHECK (producer_seq > 0),
  digest       TEXT NOT NULL CHECK (length(digest) = 64),
  chain        TEXT NOT NULL,
  seq          INTEGER NOT NULL CHECK (seq >= 0),
  hash         TEXT NOT NULL CHECK (length(hash) = 64),
  received_at  TEXT NOT NULL,
  PRIMARY KEY (service, id)
) STRICT;

CREATE INDEX ledger_forwarded_producer ON ledger_forwarded (service, tenant, producer_seq);

CREATE TRIGGER ledger_forwarded_no_update BEFORE UPDATE ON ledger_forwarded
BEGIN
  SELECT RAISE(ABORT, 'forwarded records are append-only');
END;

CREATE TRIGGER ledger_forwarded_no_delete BEFORE DELETE ON ledger_forwarded
BEGIN
  SELECT RAISE(ABORT, 'forwarded records are append-only');
END;
