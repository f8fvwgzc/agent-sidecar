#!/usr/bin/env bash
# The v0.2 platform on this machine, no Docker and no Kubernetes: embassy in one process (CA,
# Connect, API and the console UI), the two demo apps, and two sidecars in managed mode that get
# their certificates from embassy with a join token and their charters over Connect.
# Needs cargo, uv, go, python3, curl.
#
#   scripts/local-platform.sh            run the checks, then keep everything running (Ctrl-C stops)
#   CHECK_ONLY=1 scripts/local-platform.sh   run the checks and stop (CI)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
L=$ROOT/.local/platform
NS=agentsc-demo
# Without ANTHROPIC_API_KEY the demo agents run on the deterministic mock instead of being refused.
export AGENTSC_MOCK_FALLBACK=${AGENTSC_MOCK_FALLBACK:-1}
CONSOLE_PORT=${CONSOLE_PORT:-38088}
ORDERS_PORT=${ORDERS_PORT:-38180}
INVENTORY_PORT=${INVENTORY_PORT:-38100}
CP=127.0.0.1:15012
CHECK_ONLY=${CHECK_ONLY:-0}
# scripts/profile.sh sets these: a profiling build of the sidecar, where to write each sidecar's
# CPU profile, and a longer stop grace so the profiles can be written.
AGENTSCD=${AGENTSCD:-./target/debug/agentscd}
PROFILE_DIR=${PROFILE_DIR:-}
STOP_GRACE=${STOP_GRACE:-5}

python3 - "$CONSOLE_PORT" "$ORDERS_PORT" "$INVENTORY_PORT" 15012 3520 3530 50021 50022 50023 50024 <<'PY'
import socket, sys
def listening(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0 and s.getsockname() != s.getpeername()
busy = [p for p in sys.argv[1:] if listening(int(p))]
if busy:
    sys.exit(f"already in use on 127.0.0.1: {', '.join(busy)} (an earlier run still going?)")
PY

PIDS=()
cleanup() {
  set +e
  for p in "${PIDS[@]:-}"; do kill -TERM -- "-$p" 2>/dev/null; done
  for _ in $(seq 1 $((STOP_GRACE * 10))); do
    alive=
    for p in "${PIDS[@]:-}"; do kill -0 -- "-$p" 2>/dev/null && alive=1; done
    [[ -z $alive ]] && break
    sleep 0.1
  done
  for p in "${PIDS[@]:-}"; do kill -KILL -- "-$p" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 143' TERM
trap 'exit 130' INT

echo "▶ building"
cargo build -q -p agentscd -p agentsc-cli -p embassy
(cd runtime && uv sync -q)
mkdir -p "$L"
(cd examples/orders && go build -o "$L/orders" .)

# A fresh control plane each run: CA, tokens, config, store.
rm -rf "$L/ca" "$L/store" "$L/state" "$L/run" "$L/logs" "$L/secrets"
mkdir -p "$L/logs" "$L/secrets" "$L/run/orders" "$L/run/inventory"
chmod 700 "$L/secrets"

echo "▶ CA and tokens"
./target/debug/embassy ca-init --out "$L/ca" >/dev/null
token() {  # token <file> <embassy token create args...>: the token to <file> (0600), its YAML entry to stdout
  local out
  out=$(./target/debug/embassy token create "${@:2}")
  (umask 077 && head -1 <<<"$out" >"$1")
  tail -n +3 <<<"$out" | sed 's/^/    /'
}
{
  echo "apiVersion: agentsc.io/v1alpha1"
  echo "kind: ControlPlaneConfig"
  echo "auth:"
  echo "  tokens:"
  token "$L/secrets/admin-token" --name admin --role admin --namespaces '*' --payloads
  echo "issuance:"
  echo "  kubernetes: false"
  echo "  join_tokens:"
  token "$L/secrets/orders-join-token" --join --name orders-join --namespace $NS --services orders --expires-in 24h
  token "$L/secrets/inventory-join-token" --join --name inventory-join --namespace $NS --services inventory --expires-in 24h
} >"$L/controlplane.yaml"

echo "▶ start-up charters with local peer addresses (adopted by the control plane)"
python3 - "$L" "$ORDERS_PORT" "$INVENTORY_PORT" <<'PY'
import os, sys, re
local, orders_port, inventory_port = sys.argv[1:4]
for name, peer, port in (("orders", "inventory: 127.0.0.1:50024", orders_port),
                         ("inventory", "orders: 127.0.0.1:50022", inventory_port)):
    text = open(f"examples/charters/{name}.charter.yaml").read()
    text = text.replace("agents:\n", f"mesh:\n  peers:\n    {peer}\nagents:\n", 1)
    text = re.sub(r"app_port: \d+", f"app_port: {port}", text, count=1)
    if os.environ.get("RAISE_BUDGETS") == "1":  # load tests: no 429s from the demo's small budgets
        text = re.sub(r"max_calls_per_minute: \d+", "max_calls_per_minute: 1000000", text)
        text = re.sub(r"max_cost_usd_per_day: [0-9.]+", "max_cost_usd_per_day: 1000000.0", text)
    open(f"{local}/{name}.charter.yaml", "w").write(text)
PY

set -m
echo "▶ embassy (CA, Connect, API, console) → $L/logs/embassy.log"
./target/debug/embassy serve --components ca,controlplane,api,ui \
  --ca-dir "$L/ca" --store "file:$L/store" --config "$L/controlplane.yaml" \
  --grpc-addr $CP --http-addr "127.0.0.1:$CONSOLE_PORT" --dns-name localhost --auto-adopt \
  >"$L/logs/embassy.log" 2>&1 & PIDS+=($!)

echo "▶ apps"
(cd examples/inventory && uv run --quiet --with 'fastapi>=0.115' --with 'uvicorn>=0.30' uvicorn app:app --port "$INVENTORY_PORT" --log-level warning >"$L/logs/inventory-app.log" 2>&1) & PIDS+=($!)
ADDR=127.0.0.1:$ORDERS_PORT AGENTSC_URL=http://127.0.0.1:3520 "$L/orders" >"$L/logs/orders-app.log" 2>&1 & PIDS+=($!)

echo "▶ sidecars in managed mode (audit → $L/logs/<svc>-audit.jsonl)"
RUNTIME_CMD="uv run --quiet --project $ROOT/runtime agentsc-runtime"
sidecar() {  # sidecar <service> <app port> <http> <grpc> <mesh>
  local profile=()
  [[ -n $PROFILE_DIR ]] && profile=(env "AGENTSC_PROFILE=$PROFILE_DIR/$1")
  ${profile[@]+"${profile[@]}"} "$AGENTSCD" --control-plane $CP --ca-file "$L/ca/ca.crt" \
    --join-token-file "$L/secrets/$1-join-token" --service "$1" --namespace $NS --app-port "$2" \
    --pod-name "$1-local" --charter "$L/$1.charter.yaml" --state-dir "$L/state/$1" \
    --http-addr "127.0.0.1:$3" --grpc-addr "127.0.0.1:$4" --mesh-addr "127.0.0.1:$5" \
    --socket-dir "$L/run/$1" --runtime-cmd "$RUNTIME_CMD" \
    >"$L/logs/$1-audit.jsonl" 2>"$L/logs/$1-agentscd.log" & PIDS+=($!)
}
sidecar inventory "$INVENTORY_PORT" 3530 50023 50024
sidecar orders "$ORDERS_PORT" 3520 50021 50022
set +m

echo -n "▶ waiting for readiness"
for _ in $(seq 1 120); do
  if curl -sf http://127.0.0.1:3520/readyz >/dev/null 2>&1 && curl -sf http://127.0.0.1:3530/readyz >/dev/null 2>&1 \
     && curl -sf "http://127.0.0.1:$ORDERS_PORT/healthz" >/dev/null 2>&1 && curl -sf "http://127.0.0.1:$INVENTORY_PORT/healthz" >/dev/null 2>&1; then
    echo " ok"; break
  fi
  echo -n "."; sleep 1
done
for s in orders:3520 inventory:3530; do
  curl -sf "http://127.0.0.1:${s#*:}/readyz" >/dev/null || { echo; echo "${s%%:*} sidecar not ready:"; tail -25 "$L/logs/${s%%:*}-agentscd.log"; tail -15 "$L/logs/embassy.log"; exit 1; }
done

ADMIN=$(cat "$L/secrets/admin-token")
api() {  # api <method> <path> [json body] [extra curl args]
  local m=$1 p=$2; shift 2
  local body=${1:-}; [[ $# -gt 0 ]] && shift
  if [[ -n $body ]]; then
    curl -sS -X "$m" "http://localhost:$CONSOLE_PORT/api/v1$p" -H "Authorization: Bearer $ADMIN" \
      -H 'Content-Type: application/json' -H 'X-Agentsc-CSRF: 1' -d "$body" "$@"
  else
    curl -sS -X "$m" "http://localhost:$CONSOLE_PORT/api/v1$p" -H "Authorization: Bearer $ADMIN" "$@"
  fi
}
check() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; tail -20 "$L/logs/embassy.log"; exit 1; }

echo "▶ the control plane sees both services, connected, with their adopted charters"
for _ in $(seq 1 30); do
  n=$(api GET /services | python3 -c 'import json,sys; print(sum(1 for s in json.load(sys.stdin) if s["status"]=="connected" and s["charter_version"]))' 2>/dev/null || echo 0)
  [[ $n == 2 ]] && break; sleep 1
done
[[ $n == 2 ]] && check "2 services connected" || fail "services: $(api GET /services)"

echo "▶ calls through the sidecars"
curl -sf "http://127.0.0.1:$ORDERS_PORT/ask" -H 'content-type: application/json' \
  -d '{"question":"How many WIDGET-1 do we have in stock and should we reorder?"}' >/dev/null || fail "the /ask call failed"
sleep 1
grep -q '"kind":"agent_invocation".*"agent":"stock-analyst".*"direction":"inbound"' "$L/logs/inventory-audit.jsonl" \
  && check "allowed cross-service call: orders/ops-assistant → inventory/stock-analyst over mTLS" \
  || fail "the call did not reach inventory/stock-analyst"
curl -s "http://127.0.0.1:$ORDERS_PORT/ask" -H 'content-type: application/json' \
  -d '{"question":"Please reset the inventory admin counters"}' >/dev/null && check "admin reset asked (denied inside the run)"

echo "▶ live data in the API"
sleep 2
edges=$(api GET /graph | python3 -c 'import json,sys; g=json.load(sys.stdin); print(sum(1 for e in g["edges"] if (e.get("stats") or {}).get("calls",0)>0))')
[[ $edges -gt 0 ]] && check "graph: $edges edges with live traffic" || fail "no live edges in /graph"
mesh=$(api GET /graph | python3 -c 'import json,sys; g=json.load(sys.stdin); print(sum((e.get("stats") or {}).get("calls",0) for e in g["edges"] if e["source"].startswith("agent:") and e["target"].startswith("agent:")))')
[[ $mesh -gt 0 ]] && check "graph: the agent-to-agent edge has $mesh call(s)" || fail "no agent_call traffic in /graph"
runs=$(api GET /traces | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
[[ $runs -gt 0 ]] && check "timeline: $runs runs in /traces" || fail "no runs in /traces"

echo "▶ a live edit of an agent reaches the running sidecar"
v=$(api GET /services/$NS/inventory/charter | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')
view=$(api GET /services/$NS/inventory/agents/stock-analyst | python3 -c 'import json,sys; d=json.load(sys.stdin); d["agent"]["system"]=d["agent"]["system"]+" Keep answers short."; print(json.dumps(d))')
nv=$(api PUT /services/$NS/inventory/agents/stock-analyst "$view" -H "If-Match: \"$v\"" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')
for _ in $(seq 1 20); do
  acked=$(api GET /services | python3 -c "import json,sys; s=[x for x in json.load(sys.stdin) if x['service']=='inventory'][0]; print(all(i.get('acked_version')=='$nv' for i in s['instances']))")
  [[ $acked == True ]] && break; sleep 0.5
done
[[ $acked == True ]] && check "version $nv applied by the inventory sidecar without a restart" || fail "the edit was not acknowledged"

echo
echo "✓ platform demo ready"
echo "  console:  http://localhost:$CONSOLE_PORT   (sign in with the token in $L/secrets/admin-token)"
echo "  orders:   curl http://127.0.0.1:$ORDERS_PORT/ask -H 'content-type: application/json' -d '{\"question\":\"How many WIDGET-1 are in stock?\"}'"
echo "  logs:     $L/logs/"
if [[ $CHECK_ONLY != 1 ]]; then
  echo "  press Ctrl-C to stop"
  wait
fi
