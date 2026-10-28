-- The embassy PostgreSQL store, migration 3 (docs/design/evidence-ledger.md, CONTRACT.md §6.3):
-- the evidence ledger, as in the SQLite store's migration 3. A record is kept as its canonical
-- JSON text (never jsonb, which would rewrite it), and the triggers are the floor under the
-- hashes embassy computes: an entry is exactly the next one of its chain and follows its head,
-- entries and seals are never changed or removed, and a head never goes back.

CREATE TABLE ledger_heads (
  chain      text COLLATE "C" PRIMARY KEY CHECK (length(chain) BETWEEN 1 AND 300),
  entries    bigint NOT NULL DEFAULT 0 CHECK (entries >= 0),
  head       text NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'
             CHECK (length(head) = 64),
  sealed     bigint NOT NULL DEFAULT 0 CHECK (sealed >= 0 AND sealed <= entries),
  updated_at text COLLATE "C" NOT NULL
);

CREATE INDEX ledger_heads_updated ON ledger_heads (updated_at);
CREATE INDEX ledger_heads_unsealed ON ledger_heads (updated_at) WHERE sealed < entries;

CREATE TABLE ledger_entries (
  chain       text COLLATE "C" NOT NULL REFERENCES ledger_heads (chain),
  seq         bigint NOT NULL CHECK (seq >= 0),
  ingested_at text NOT NULL,
  record      text NOT NULL,
  prev_hash   text NOT NULL CHECK (length(prev_hash) = 64),
  hash        text NOT NULL CHECK (length(hash) = 64),
  namespace   text COLLATE "C" NOT NULL,
  service     text COLLATE "C" NOT NULL,
  agent_id    text,
  kind        text NOT NULL,
  PRIMARY KEY (chain, seq)
);

CREATE TABLE ledger_chain_services (
  chain     text COLLATE "C" NOT NULL REFERENCES ledger_heads (chain),
  namespace text COLLATE "C" NOT NULL,
  service   text COLLATE "C" NOT NULL,
  PRIMARY KEY (chain, namespace, service)
);

CREATE INDEX ledger_chain_services_by_service ON ledger_chain_services (namespace, service);

CREATE TABLE ledger_seals (
  chain     text COLLATE "C" NOT NULL REFERENCES ledger_heads (chain),
  entries   bigint NOT NULL CHECK (entries > 0),
  statement text NOT NULL,
  signature text NOT NULL CHECK (length(signature) = 128),
  kid       text NOT NULL,
  sealed_at text NOT NULL,
  PRIMARY KEY (chain, entries)
);

CREATE FUNCTION agentsc_ledger_entries_next() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  h ledger_heads%ROWTYPE;
BEGIN
  SELECT * INTO h FROM ledger_heads WHERE chain = NEW.chain FOR UPDATE;
  IF NOT FOUND OR NEW.seq <> h.entries OR NEW.prev_hash <> h.head THEN
    RAISE EXCEPTION 'a ledger entry must follow the head of its chain';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER ledger_entries_next BEFORE INSERT ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_entries_next();

CREATE FUNCTION agentsc_ledger_entries_bump() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE ledger_heads SET entries = NEW.seq + 1, head = NEW.hash, updated_at = NEW.ingested_at
  WHERE chain = NEW.chain;
  RETURN NULL;
END $$;

CREATE TRIGGER ledger_entries_bump AFTER INSERT ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_entries_bump();

CREATE TRIGGER ledger_entries_no_update BEFORE UPDATE OR DELETE ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();
CREATE TRIGGER ledger_entries_no_truncate BEFORE TRUNCATE ON ledger_entries
  FOR EACH STATEMENT EXECUTE FUNCTION agentsc_immutable();

CREATE FUNCTION agentsc_ledger_seals_covered() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.entries > (SELECT entries FROM ledger_heads WHERE chain = NEW.chain) THEN
    RAISE EXCEPTION 'a seal covers entries that exist';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER ledger_seals_covered BEFORE INSERT ON ledger_seals
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_seals_covered();

CREATE FUNCTION agentsc_ledger_seals_mark() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE ledger_heads SET sealed = greatest(sealed, NEW.entries) WHERE chain = NEW.chain;
  RETURN NULL;
END $$;

CREATE TRIGGER ledger_seals_mark AFTER INSERT ON ledger_seals
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_seals_mark();

CREATE TRIGGER ledger_seals_no_update BEFORE UPDATE OR DELETE ON ledger_seals
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();
CREATE TRIGGER ledger_seals_no_truncate BEFORE TRUNCATE ON ledger_seals
  FOR EACH STATEMENT EXECUTE FUNCTION agentsc_immutable();

CREATE FUNCTION agentsc_ledger_heads_forward() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.entries < OLD.entries OR NEW.sealed < OLD.sealed OR NEW.chain <> OLD.chain THEN
    RAISE EXCEPTION 'a ledger head never goes back';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER ledger_heads_forward BEFORE UPDATE ON ledger_heads
  FOR EACH ROW EXECUTE FUNCTION agentsc_ledger_heads_forward();
CREATE TRIGGER ledger_heads_no_delete BEFORE DELETE ON ledger_heads
  FOR EACH ROW EXECUTE FUNCTION agentsc_immutable();
CREATE TRIGGER ledger_heads_no_truncate BEFORE TRUNCATE ON ledger_heads
  FOR EACH STATEMENT EXECUTE FUNCTION agentsc_immutable();
