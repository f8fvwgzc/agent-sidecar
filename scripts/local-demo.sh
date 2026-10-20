#!/usr/bin/env bash
# Run the whole demo on this machine, no Kubernetes: two sidecars with mTLS, the real Python runtime,
# the Go orders app and the FastAPI inventory app. Needs cargo, uv, go, python3, curl.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
LOCAL=$ROOT/.local
NS=attache-demo
# This machine may already use 8080/8000; the local demo runs the apps on these ports instead.
ORDERS_PORT=${ORDERS_PORT:-18080}
INVENTORY_PORT=${INVENTORY_PORT:-18000}
mkdir -p "$LOCAL/run/orders" "$LOCAL/run/inventory" "$LOCAL/logs"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

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

echo; echo "▶ 1. stock question through orders /ask"
R1=$(curl -s -X POST http://127.0.0.1:$ORDERS_PORT/ask -H 'content-type: application/json' -d '{"question":"How many WIDGET-1 do we have in stock and should we reorder?"}')
echo "$R1" | json
T1=$(echo "$R1" | field 'd["trace_id"]')
echo "$R1" | field 'd["status"]=="ok" and any(s["kind"]=="agent_call" and s["decision"]=="allow" for s in d["steps"])' | grep -q True || { echo "✗ call 1 failed"; exit 1; }

echo; echo "▶ 2. admin reset through orders /ask (must be denied by inventory's charter)"
R2=$(curl -s -X POST http://127.0.0.1:$ORDERS_PORT/ask -H 'content-type: application/json' -d '{"question":"Reset the inventory admin counters"}')
echo "$R2" | json
T2=$(echo "$R2" | field 'd["trace_id"]')
echo "$R2" | field 'any(s["decision"]=="deny" and s.get("rule")=="authz.services.deny-admin" for s in d["steps"])' | grep -q True || { echo "✗ call 2 was not denied"; exit 1; }

echo; echo "▶ 3. guardrail: a secret in the input is refused before any model call"
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST http://127.0.0.1:$ORDERS_PORT/ask -H 'content-type: application/json' -d '{"question":"our api_key = sk-123 please"}'

echo; echo "▶ 4. audit trail, both sidecars, trace $T1"
sleep 0.5
cat "$LOCAL/logs/orders-audit.jsonl" "$LOCAL/logs/inventory-audit.jsonl" | ./target/debug/attache logs --file - --trace "$T1"
echo; echo "▶ 5. the denial, trace $T2"
cat "$LOCAL/logs/orders-audit.jsonl" "$LOCAL/logs/inventory-audit.jsonl" | ./target/debug/attache logs --file - --trace "$T2" --denied
echo; echo "✓ local demo complete"
