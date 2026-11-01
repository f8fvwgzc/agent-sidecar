-- The embassy PostgreSQL store, migration 8 (CONTRACT.md §6.3, secops/ledger.rs): the Append API, as
-- in the SQLite store's migration 8.

CREATE TABLE ledger_forwarded (
  service      text COLLATE "C" NOT NULL,
  id           text COLLATE "C" NOT NULL,
  tenant       text NOT NULL,
  producer_seq bigint NOT NULL CHECK (producer_seq > 0),
  digest       text NOT NULL CHECK (length(digest) = 64),
  chain        text NOT NULL,
  seq          bigint NOT NULL CHECK (seq >= 0),
  hash         text NOT NULL CHECK (length(hash) = 64),
  received_at  text NOT NULL,
  PRIMARY KEY (service, id)
);

CREATE INDEX ledger_forwarded_producer ON ledger_forwarded (service, tenant, producer_seq);

CREATE TRIGGER ledger_forwarded_no_update BEFORE UPDATE OR DELETE ON ledger_forwarded
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();
CREATE TRIGGER ledger_forwarded_no_truncate BEFORE TRUNCATE ON ledger_forwarded
  FOR EACH STATEMENT EXECUTE FUNCTION agentsc_immutable();
