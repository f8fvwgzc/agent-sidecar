-- The embassy PostgreSQL store, migration 7 (CONTRACT.md §6.3, secops/ledger.rs): purging old
-- chains, as in the SQLite store's migration 7: a whole chain a seal covers, after a purge record.

CREATE TABLE ledger_purges (
  chain         text COLLATE "C" PRIMARY KEY,
  entries       bigint NOT NULL CHECK (entries > 0),
  head          text NOT NULL CHECK (length(head) = 64),
  seal          text NOT NULL,
  last_entry_at text NOT NULL,
  purged_at     text NOT NULL,
  purged_by     text NOT NULL
);

CREATE FUNCTION agentsc_ledger_purges_sealed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM ledger_heads WHERE chain = NEW.chain AND entries = NEW.entries
                 AND sealed = entries AND head = NEW.head) THEN
    RAISE EXCEPTION 'only a whole chain a seal covers is purged';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER ledger_purges_sealed BEFORE INSERT ON ledger_purges
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_purges_sealed();
CREATE TRIGGER ledger_purges_no_update BEFORE UPDATE OR DELETE ON ledger_purges
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();
CREATE TRIGGER ledger_purges_no_truncate BEFORE TRUNCATE ON ledger_purges
  FOR EACH STATEMENT EXECUTE FUNCTION agentsc_immutable();

CREATE FUNCTION agentsc_ledger_delete_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM ledger_purges WHERE chain = OLD.chain) THEN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
  END IF;
  RETURN OLD;
END $$;

DROP TRIGGER ledger_entries_no_update ON ledger_entries;
CREATE TRIGGER ledger_entries_no_update BEFORE UPDATE ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();
CREATE TRIGGER ledger_entries_delete_guard BEFORE DELETE ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_delete_guard();

DROP TRIGGER ledger_seals_no_update ON ledger_seals;
CREATE TRIGGER ledger_seals_no_update BEFORE UPDATE ON ledger_seals
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();
CREATE TRIGGER ledger_seals_delete_guard BEFORE DELETE ON ledger_seals
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_delete_guard();

DROP TRIGGER ledger_heads_no_delete ON ledger_heads;
CREATE TRIGGER ledger_heads_delete_guard BEFORE DELETE ON ledger_heads
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_delete_guard();

CREATE TRIGGER ledger_chain_services_delete_guard BEFORE DELETE ON ledger_chain_services
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_delete_guard();
CREATE TRIGGER ledger_chain_services_no_truncate BEFORE TRUNCATE ON ledger_chain_services
  FOR EACH STATEMENT EXECUTE FUNCTION agentsc_immutable();
