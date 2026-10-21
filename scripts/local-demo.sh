#!/usr/bin/env bash
# Run the whole demo on this machine, no Kubernetes: two sidecars with mTLS, the real Python runtime,
# the Go orders app and the FastAPI inventory app. Needs cargo, uv, go, python3, curl.
# Exits non-zero when a check fails; CI runs it as the CONTRACT.md §10 gate.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
LOCAL=$ROOT/.local
NS=attache-demo
# This machine may already use 8080/8000; the local demo runs the apps on these ports instead.
ORDERS_PORT=${ORDERS_PORT:-38080}
INVENTORY_PORT=${INVENTORY_PORT:-38000}
mkdir -p "$LOCAL/run/orders" "$LOCAL/run/inventory" "$LOCAL/logs"

# Anything still listening here (often an earlier run) would answer the readiness checks and the calls.
python3 - "$ORDERS_PORT" "$INVENTORY_PORT" 3500 3510 50001 50003 50011 50012 <<'PY'
import socket, sys

def listening(port):
    with socket.socket() as s:
        # A connect to a free port can land on itself when the port is in the ephemeral range.
        return s.connect_ex(("127.0.0.1", port)) == 0 and s.getsockname() != s.getpeername()

busy = [p for p in sys.argv[1:] if listening(int(p))]
if busy:
    sys.exit(f"already in use on 127.0.0.1: {', '.join(busy)} (an earlier run still going?)")
PY

# Every background job leads its own process group (started under `set -m`), so cleanup also stops
# what it spawned: uv's child python, and the runtime each sidecar starts through uv.
PIDS=()
cleanup() {
  set +e
  for p in "${PIDS[@]:-}"; do kill -TERM -- "-$p" 2>/dev/null; done
  for _ in $(seq 1 50); do  # 5 s to stop gracefully, then SIGKILL what is left
    alive=
    for p in "${PIDS[@]:-}"; do kill -0 -- "-$p" 2>/dev/null && alive=1; done
    [[ -z $alive ]] && break
    sleep 0.1
  done
  for p in "${PIDS[@]:-}"; do kill -KILL -- "-$p" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT
trap 'exit 129' HUP   # bash skips the EXIT trap when one of these kills it
trap 'exit 143' TERM

echo "▶ building"
cargo build -q -p attached -p attache-cli -p embassy
(cd runtime && uv sync -q)
(cd examples/orders && go build -o "$LOCAL/orders" .)

echo "▶ certificates (embassy)"
[[ -f $LOCAL/ca/ca.crt ]] || ./target/debug/embassy ca-init --out "$LOCAL/ca" >/dev/null
./target/debug/embassy cert-issue --ca "$LOCAL/ca" --namespace $NS --service orders --out "$LOCAL/tls/orders" >/dev/null
./target/debug/embassy cert-issue --ca "$LOCAL/ca" --namespace $NS --service inventory --out "$LOCAL/tls/inventory" >/dev/null

echo "▶ charters with local peer addresses"
python3 - "$LOCAL" "$ORDERS_PORT" "$INVENTORY_PORT" <<'PY'
import sys, re
local, orders_port, inventory_port = sys.argv[1], sys.argv[2], sys.argv[3]
for name, peer, port in (("orders", "inventory: 127.0.0.1:50012", orders_port), ("inventory", "orders: 127.0.0.1:50011", inventory_port)):
    text = open(f"examples/charters/{name}.charter.yaml").read()
    text = text.replace("agents:\n", f"mesh:\n  peers:\n    {peer}\nagents:\n", 1)
    text = re.sub(r"app_port: \d+", f"app_port: {port}", text, count=1)
    open(f"{local}/{name}.charter.yaml", "w").write(text)
PY

echo "▶ apps"
set -m
(cd examples/inventory && uv run --quiet --with 'fastapi>=0.115' --with 'uvicorn>=0.30' uvicorn app:app --port "$INVENTORY_PORT" --log-level warning >"$LOCAL/logs/inventory-app.log" 2>&1) & PIDS+=($!)
ADDR=127.0.0.1:$ORDERS_PORT ATTACHE_URL=http://127.0.0.1:3500 "$LOCAL/orders" >"$LOCAL/logs/orders-app.log" 2>&1 & PIDS+=($!)

echo "▶ sidecars (audit JSONL → .local/logs/<svc>-audit.jsonl, logs → .local/logs/<svc>-attached.log)"
RUNTIME_CMD="uv run --quiet --project $ROOT/runtime attache-runtime"
./target/debug/attached --charter "$LOCAL/inventory.charter.yaml" --tls-dir "$LOCAL/tls/inventory" \
  --http-addr 127.0.0.1:3510 --grpc-addr 127.0.0.1:50003 --mesh-addr 127.0.0.1:50012 \
  --socket-dir "$LOCAL/run/inventory" --runtime-cmd "$RUNTIME_CMD" \
  >"$LOCAL/logs/inventory-audit.jsonl" 2>"$LOCAL/logs/inventory-attached.log" & PIDS+=($!)
./target/debug/attached --charter "$LOCAL/orders.charter.yaml" --tls-dir "$LOCAL/tls/orders" \
  --http-addr 127.0.0.1:3500 --grpc-addr 127.0.0.1:50001 --mesh-addr 127.0.0.1:50011 \
  --socket-dir "$LOCAL/run/orders" --runtime-cmd "$RUNTIME_CMD" \
  >"$LOCAL/logs/orders-audit.jsonl" 2>"$LOCAL/logs/orders-attached.log" & PIDS+=($!)
set +m  # foreground commands stay in our process group, so Ctrl-C still reaches this script

echo -n "▶ waiting for readiness"
for _ in $(seq 1 120); do
  if curl -sf http://127.0.0.1:3500/readyz >/dev/null 2>&1 && curl -sf http://127.0.0.1:3510/readyz >/dev/null 2>&1 \
     && curl -sf "http://127.0.0.1:$ORDERS_PORT/healthz" >/dev/null 2>&1 && curl -sf "http://127.0.0.1:$INVENTORY_PORT/healthz" >/dev/null 2>&1; then
    echo " ok"; break
  fi
  echo -n "."; sleep 1
done
curl -sf http://127.0.0.1:3500/readyz >/dev/null || { echo; echo "orders sidecar not ready:"; tail -20 "$LOCAL/logs/orders-attached.log"; exit 1; }
curl -sf http://127.0.0.1:3510/readyz >/dev/null || { echo; echo "inventory sidecar not ready:"; tail -20 "$LOCAL/logs/inventory-attached.log"; exit 1; }
curl -s http://127.0.0.1:3500/readyz; echo

json() { python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), indent=2))'; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# audit_has <jsonl> field=value...: waits up to 5 s for a record with those fields and no error.
audit_has() {
  python3 - "$@" <<'PY'
import json, sys, time
path, want = sys.argv[1], dict(a.split("=", 1) for a in sys.argv[2:])

def records():
    with open(path) as f:
        for line in f:
            try:
                yield json.loads(line)
            except ValueError:
                pass  # a record still being written

deadline = time.monotonic() + 5
while True:
    if any(not r.get("error") and all(str(r.get(k)) == v for k, v in want.items()) for r in records()):
        sys.exit(0)
    if time.monotonic() > deadline:
        sys.exit(1)
    time.sleep(0.2)
PY
}
ORDERS_ID=spiffe://attache/ns/$NS/svc/orders

echo; echo "▶ 1. stock question through orders /ask"
R1=$(curl -s -X POST http://127.0.0.1:$ORDERS_PORT/ask -H 'content-type: application/json' -d '{"question":"How many WIDGET-1 do we have in stock and should we reorder?"}')
echo "$R1" | json
T1=$(echo "$R1" | field 'd["trace_id"]')
echo "$R1" | field 'd["status"]=="ok" and any(s["kind"]=="agent_call" and s["decision"]=="allow" for s in d["steps"])' | grep -q True || { echo "✗ call 1 failed"; exit 1; }
# A tool call that failed is still decision "allow" in the response, so the audit logs decide whether
# the call crossed the mesh: inventory saw it arrive from orders' identity, orders saw it come back.
audit_has "$LOCAL/logs/inventory-audit.jsonl" trace_id="$T1" kind=agent_invocation direction=inbound \
  caller="$ORDERS_ID" agent=stock-analyst decision=allow || { echo "✗ call 1 never reached inventory's stock-analyst"; exit 1; }
audit_has "$LOCAL/logs/orders-audit.jsonl" trace_id="$T1" kind=agent_call callee=inventory/stock-analyst \
  decision=allow || { echo "✗ call 1: orders' call to inventory/stock-analyst failed"; exit 1; }

echo; echo "▶ 2. admin reset through orders /ask (must be denied by inventory's charter)"
R2=$(curl -s -X POST http://127.0.0.1:$ORDERS_PORT/ask -H 'content-type: application/json' -d '{"question":"Reset the inventory admin counters"}')
echo "$R2" | json
T2=$(echo "$R2" | field 'd["trace_id"]')
echo "$R2" | field 'any(s["decision"]=="deny" and s.get("rule")=="authz.services.deny-admin" for s in d["steps"])' | grep -q True || { echo "✗ call 2 was not denied"; exit 1; }
audit_has "$LOCAL/logs/inventory-audit.jsonl" trace_id="$T2" kind=service_call direction=inbound \
  caller="$ORDERS_ID" decision=deny rule=authz.services.deny-admin || { echo "✗ call 2: no denial in inventory's audit"; exit 1; }

echo; echo "▶ 3. guardrail: a secret in the input is refused before any model call"
R3=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:$ORDERS_PORT/ask -H 'content-type: application/json' -d '{"question":"our api_key = sk-123 please"}')
echo "HTTP $R3"
[[ $R3 == 403 ]] || { echo "✗ call 3 was not refused with 403"; exit 1; }

echo; echo "▶ 4. audit trail, both sidecars, trace $T1"
sleep 0.5
cat "$LOCAL/logs/orders-audit.jsonl" "$LOCAL/logs/inventory-audit.jsonl" | ./target/debug/attache logs --file - --trace "$T1"
echo; echo "▶ 5. the denial, trace $T2"
cat "$LOCAL/logs/orders-audit.jsonl" "$LOCAL/logs/inventory-audit.jsonl" | ./target/debug/attache logs --file - --trace "$T2" --denied
echo; echo "✓ local demo complete"
