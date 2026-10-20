#!/usr/bin/env bash
# End-to-end demo on minikube (CONTRACT.md §6 lists the records each step produces).
set -euo pipefail
NS=${NS:-attache-demo}
ATTACHE=${ATTACHE:-./target/debug/attache}
KUBE_CONTEXT=${KUBE_CONTEXT:-minikube}
PORT=${PORT:-38081}
kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }

json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d, indent=2))'; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

echo "▶ port-forward svc/orders → localhost:$PORT"
kc -n "$NS" port-forward svc/orders "$PORT:8080" >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -sf "http://localhost:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf "http://localhost:$PORT/healthz" >/dev/null || { echo "orders is not reachable"; exit 1; }

echo
echo "▶ 1. orders /ask → sidecar → ops-assistant → mTLS → inventory sidecar → stock-analyst → GET /stock"
Q1='{"question":"How many WIDGET-1 do we have in stock and should we reorder?"}'
R1=$(curl -s -X POST "http://localhost:$PORT/ask" -H 'content-type: application/json' -d "$Q1")
echo "$R1" | json
STATUS1=$(echo "$R1" | field 'd["status"]')
TRACE1=$(echo "$R1" | field 'd["trace_id"]')
OUT1=$(echo "$R1" | field 'd["output"]')
[[ "$STATUS1" == "ok" ]] || { echo "✗ expected status ok"; exit 1; }
echo "$R1" | field 'any(s["kind"]=="agent_call" and s["name"]=="inventory/stock-analyst" and s["decision"]=="allow" for s in d["steps"])' | grep -q True \
  || { echo "✗ expected an allowed agent_call to inventory/stock-analyst"; exit 1; }
if [[ "$OUT1" == *"[redacted:email]"* ]]; then
  echo "✓ answer received; the warehouse contact email was redacted by the inventory charter (pii_redact)"
else
  echo "✓ answer received (no email in this answer to redact)"
fi

echo
echo "▶ 2. orders /ask → ops-assistant tries inventory POST /admin/reset → denied by inventory's charter"
Q2='{"question":"Reset the inventory admin counters"}'
R2=$(curl -s -X POST "http://localhost:$PORT/ask" -H 'content-type: application/json' -d "$Q2")
echo "$R2" | json
TRACE2=$(echo "$R2" | field 'd["trace_id"]')
echo "$R2" | field 'any(s["decision"]=="deny" and s.get("rule")=="authz.services.deny-admin" for s in d["steps"])' | grep -q True \
  || { echo "✗ expected a denied step with rule authz.services.deny-admin"; exit 1; }
echo "✓ the call was denied with rule authz.services.deny-admin and the agent was told so"

echo
echo "▶ 3. audit trail of call 1 across both pods (same trace_id $TRACE1)"
sleep 1
$ATTACHE logs orders,inventory -n "$NS" --context "$KUBE_CONTEXT" --trace "$TRACE1"
echo
echo "▶ 4. the denial of call 2 in both pods (trace $TRACE2)"
$ATTACHE logs orders,inventory -n "$NS" --context "$KUBE_CONTEXT" --trace "$TRACE2" --denied
echo
echo "✓ demo complete. Raw JSONL: kubectl --context $KUBE_CONTEXT -n $NS logs -l attache.io/service=inventory -c attached"
