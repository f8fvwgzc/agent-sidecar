-- The SQLite store, migration 7 (CONTRACT.md §6.3, secops/ledger.rs): purging old chains. A
-- purge removes a whole chain that a seal covers entirely, and leaves a purge record (its entry
-- count, head and covering seal) first: the delete triggers let rows of a chain go only once that
-- record exists. Purge records are append-only. Never edit this file.

CREATE TABLE ledger_purges (
  chain         TEXT PRIMARY KEY,
  entries       INTEGER NOT NULL CHECK (entries > 0),
  head          TEXT NOT NULL CHECK (length(head) = 64),
  seal          TEXT NOT NULL,
  last_entry_at TEXT NOT NULL,
  purged_at     TEXT NOT NULL,
  purged_by     TEXT NOT NULL
) STRICT;

CREATE TRIGGER ledger_purges_sealed BEFORE INSERT ON ledger_purges
WHEN NOT EXISTS (SELECT 1 FROM ledger_heads WHERE chain = NEW.chain AND entries = NEW.entries
                 AND sealed = entries AND head = NEW.head)
BEGIN
  SELECT RAISE(ABORT, 'only a whole chain a seal covers is purged');
END;

CREATE TRIGGER ledger_purges_no_update BEFORE UPDATE ON ledger_purges
BEGIN
  SELECT RAISE(ABORT, 'purge records are append-only');
END;

CREATE TRIGGER ledger_purges_no_delete BEFORE DELETE ON ledger_purges
BEGIN
  SELECT RAISE(ABORT, 'purge records are append-only');
END;

DROP TRIGGER ledger_entries_no_delete;
CREATE TRIGGER ledger_entries_no_delete BEFORE DELETE ON ledger_entries
WHEN NOT EXISTS (SELECT 1 FROM ledger_purges WHERE chain = OLD.chain)
BEGIN
  SELECT RAISE(ABORT, 'the ledger is append-only');
END;

DROP TRIGGER ledger_seals_no_delete;
CREATE TRIGGER ledger_seals_no_delete BEFORE DELETE ON ledger_seals
WHEN NOT EXISTS (SELECT 1 FROM ledger_purges WHERE chain = OLD.chain)
BEGIN
  SELECT RAISE(ABORT, 'the ledger is append-only');
END;

DROP TRIGGER ledger_heads_no_delete;
CREATE TRIGGER ledger_heads_no_delete BEFORE DELETE ON ledger_heads
WHEN NOT EXISTS (SELECT 1 FROM ledger_purges WHERE chain = OLD.chain)
BEGIN
  SELECT RAISE(ABORT, 'the ledger is append-only');
END;

CREATE TRIGGER ledger_chain_services_no_delete BEFORE DELETE ON ledger_chain_services
WHEN NOT EXISTS (SELECT 1 FROM ledger_purges WHERE chain = OLD.chain)
BEGIN
  SELECT RAISE(ABORT, 'the ledger is append-only');
END;
