#!/usr/bin/env bash
# Full end-to-end test of an installed agent-sidecar (after `make demo-helm`, or the same chart and
# demo apps on any cluster). Every check prints ✓ or ✗; the script exits non-zero on the first ✗.
#   KUBE_CONTEXT=minikube deploy/helm/e2e.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
CTX=${KUBE_CONTEXT:-minikube}
NS=${NS:-agentsc-demo}
CP_NS=${CP_NS:-agentsc-system}
TOKEN=$(head -1 "${TOKEN_FILE:-.local/helm-admin-token}")
API_PORT=${API_PORT:-38070}
ORDERS_PORT=${ORDERS_PORT:-38071}
kc() { kubectl --context "$CTX" "$@"; }
ok() { echo "  ✓ $*"; }
die() { echo "  ✗ $*" >&2; exit 1; }

PF=()
cleanup() { for p in "${PF[@]:-}"; do kill "$p" 2>/dev/null || true; done; kc -n "$NS" delete pod e2e-spoof --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT
forward() {  # forward <svc> <local> <remote> [ns]
  kc -n "${4:-$NS}" port-forward "svc/$1" "$2:$3" >/dev/null 2>&1 & PF+=($!)
  for _ in $(seq 1 30); do curl -s -o /dev/null "http://127.0.0.1:$2/" && return 0; sleep 0.5; done
  die "port-forward to svc/$1 did not come up"
}
api() {  # api <method> <path> [body] [If-Match]
  local args=(-sS -X "$1" "http://localhost:$API_PORT/api/v1$2" -H "Authorization: Bearer $TOKEN")
  [[ -n ${3:-} ]] && args+=(-H 'Content-Type: application/json' -H 'X-Agentsc-CSRF: 1' -d "$3")
  [[ -n ${4:-} ]] && args+=(-H "If-Match: \"$4\"")
  curl "${args[@]}"
}
py() { python3 -c "import json,sys; d=json.load(sys.stdin); $1"; }
ask() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$ORDERS_PORT/ask" -H 'content-type: application/json' -d "{\"question\":\"$1\"}"; }
acked() {  # acked <service> <version>: every instance acknowledged the version
  for _ in $(seq 1 40); do
    [[ $(api GET /services | py "s=[x for x in d if x['service']=='$1'][0]; print(all(i.get('acked_version')=='$2' for i in s['instances']) and len(s['instances'])>0)") == True ]] && return 0
    sleep 0.5
  done
  return 1
}

echo "▶ control plane and data plane"
forward embassy "$API_PORT" 8080 "$CP_NS"
forward orders "$ORDERS_PORT" 8080
n=$(api GET /services | py "print(sum(1 for s in d if s['status']=='connected'))")
[[ $n -ge 2 ]] && ok "$n services connected to the control plane" || die "services: $(api GET /services)"

echo "▶ requests across pods"
[[ $(ask 'How many WIDGET-1 do we have in stock and should we reorder?') == 200 ]] || die "the cross-service call failed"
[[ $(ask 'Please reset the inventory admin counters') == 200 ]] || die "the admin call failed"
sleep 2
calls=$(api GET /graph | py "print(sum((e.get('stats') or {}).get('calls',0) for e in d['edges'] if e['source'].startswith('agent:') and e['target'].startswith('agent:')))")
[[ $calls -gt 0 ]] && ok "agent-to-agent call over mTLS seen in the graph ($calls)" || die "no agent-to-agent traffic in /graph"
denied=$(kc -n "$NS" logs deploy/inventory -c agentscd --tail=500 | grep -c '"rule":"authz.services.deny-admin"' || true)
[[ $denied -gt 0 ]] && ok "admin reset denied by the inventory sidecar ($denied audit lines)" || die "no deny-admin record in inventory"
runs=$(api GET /traces | py "print(len(d))")
[[ $runs -gt 0 ]] && ok "timeline has $runs runs" || die "no runs in /traces"

echo "▶ live edit through the API reaches the running sidecar and the Charter resource"
v=$(api GET /services/$NS/inventory/charter | py "print(d['version'])")
body=$(api GET /services/$NS/inventory/agents/stock-analyst | py "d['agent']['system']=d['agent']['system'].rstrip()+' (e2e edit)'; print(json.dumps(d))")
nv=$(api PUT /services/$NS/inventory/agents/stock-analyst "$body" "$v" | py "print(d['version'])")
acked inventory "$nv" && ok "version $v → $nv applied by the inventory sidecar without a restart" || die "edit not acknowledged"
crv=$(kc -n "$NS" get charter inventory -o jsonpath='{.metadata.annotations.agentsc\.io/version}')
[[ $crv == "$nv" ]] && ok "Charter resource annotated with version $crv" || die "Charter resource version is $crv, want $nv"
hist=$(api GET /services/$NS/inventory/charter/history | py "print(len(d))")
[[ $hist -ge 2 ]] && ok "history keeps $hist versions" || die "history: $hist"

echo "▶ stale writes are refused"
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "http://localhost:$API_PORT/api/v1/services/$NS/inventory/agents/stock-analyst" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -H 'X-Agentsc-CSRF: 1' -H "If-Match: \"$v\"" -d "$body")
[[ $code == 409 ]] && ok "an edit based on version $v gets 409" || die "stale edit answered $code"

echo "▶ kubectl edits of a Charter are validated and pushed"
kc -n "$NS" get charter inventory -o json | python3 -c '
import json,sys; d=json.load(sys.stdin)
for a in d["spec"]["agents"]:
    if a["name"]=="stock-analyst": a["system"]=a["system"].rstrip()+" (kubectl edit)"
d["metadata"]={"name":d["metadata"]["name"],"namespace":d["metadata"]["namespace"],"resourceVersion":d["metadata"]["resourceVersion"]}
d.pop("status",None); print(json.dumps(d))' | kc apply -f - >/dev/null
for _ in $(seq 1 40); do
  kv=$(api GET /services/$NS/inventory/charter | py "print(d['version'])"); [[ $kv != "$nv" ]] && break; sleep 0.5
done
[[ $kv != "$nv" ]] && acked inventory "$kv" && ok "kubectl edit became version $kv and was applied" || die "kubectl edit not picked up"
bad=$(kc -n "$NS" get charter inventory -o json | python3 -c '
import json,sys; d=json.load(sys.stdin); d["spec"]["guardrails"]["pii_redaction"]=True
d["metadata"]={"name":"inventory","namespace":d["metadata"]["namespace"],"resourceVersion":d["metadata"]["resourceVersion"]}; d.pop("status",None); print(json.dumps(d))' \
  | kc apply --dry-run=server -f - 2>&1 || true)
grep -q -i 'denied\|unknown field' <<<"$bad" && ok "a Charter with an unknown field is rejected at admission" || die "invalid Charter admitted: $bad"

echo "▶ injection rules"
out=$(kc -n "$NS" run e2e-noannot --image=agentsc/inventory:dev --image-pull-policy=Never --labels=agentsc.io/inject=true --dry-run=server -o name 2>&1 || true)
grep -q -i 'agentsc.io/service' <<<"$out" && ok "a pod without agentsc.io/service is refused with a clear message" || die "pod without annotations: $out"
own=$(kc -n "$NS" apply --dry-run=server -o name -f - 2>&1 <<'EOF' || true
apiVersion: v1
kind: Pod
metadata:
  name: e2e-own-sidecar
  labels: {agentsc.io/inject: "true"}
  annotations: {agentsc.io/service: orders, agentsc.io/app-port: "8080", agentsc.io/injected: "true"}
spec:
  serviceAccountName: orders
  containers:
    - {name: app, image: agentsc/orders:dev}
    - {name: agentscd, image: agentsc/agentscd:dev}
EOF
)
grep -q 'container named "agentscd"' <<<"$own" && ok "a pod that brings its own agentscd is refused" || die "own sidecar: $own"
# The runtime holds no secret: at most the template's AGENTSC_MOCK_FALLBACK (webhook.rs
# RUNTIME_TEMPLATE_ENV; demo.sh sets injection.mockFallback), each a literal, and no envFrom.
RUNTIME_ENV_ALLOWED="AGENTSC_MOCK_FALLBACK"
rt='{.items[0].spec.initContainers[?(@.name=="agentsc-runtime")]'
rnames=$(kc -n "$NS" get pods -l app=orders -o jsonpath="$rt.env[*].name}")
rfrom=$(kc -n "$NS" get pods -l app=orders -o jsonpath="$rt.env[*].valueFrom}$rt.envFrom}")
unexpected=$(for n in $rnames; do [[ " $RUNTIME_ENV_ALLOWED " == *" $n "* ]] || echo "$n"; done)
[[ -z $unexpected && -z $rfrom ]] \
  && ok "the agentsc-runtime container has no secret in its environment (${rnames:-no env})" \
  || die "agentsc-runtime env: names [$rnames], valueFrom/envFrom [$rfrom]"

echo "▶ identity cannot be borrowed"
# A pod that claims to be orders, but runs as the default service account: the CA refuses it.
kc -n "$NS" run e2e-spoof --image=agentsc/inventory:dev --image-pull-policy=Never \
  --labels=agentsc.io/inject=true --annotations=agentsc.io/service=orders --annotations=agentsc.io/app-port=8000 >/dev/null
for _ in $(seq 1 40); do
  kc -n "$CP_NS" logs deploy/embassy-ca --tail=200 2>/dev/null | grep -q '"action":"cert_denied".*e2e-spoof\|e2e-spoof.*"action":"cert_denied"' && break; sleep 1
done
kc -n "$CP_NS" logs deploy/embassy-ca --tail=300 2>/dev/null | grep '"cert_denied"' | grep -q 'orders' \
  && ok "the CA refused a certificate for orders to a pod with the wrong service account" \
  || die "no cert_denied for the spoofing pod"
ready=$(kc -n "$NS" get pod e2e-spoof -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
[[ $ready != True ]] && ok "the spoofing pod never becomes ready" || die "the spoofing pod is ready"
kc -n "$NS" delete pod e2e-spoof --wait=false >/dev/null

echo "▶ the data plane keeps working while the control plane restarts"
kc -n "$CP_NS" rollout restart deploy/embassy >/dev/null
sleep 2
[[ $(ask 'How many WIDGET-1 do we have in stock and should we reorder?') == 200 ]] && ok "calls succeed during the control-plane restart" || die "call failed during the restart"
kc -n "$CP_NS" rollout status deploy/embassy --timeout=180s >/dev/null
kill "${PF[0]}" 2>/dev/null || true; PF=("${PF[@]:1}"); forward embassy "$API_PORT" 8080 "$CP_NS"
for _ in $(seq 1 60); do
  n=$(api GET /services 2>/dev/null | py "print(sum(1 for s in d if s['status']=='connected'))" 2>/dev/null || echo 0)
  [[ $n -ge 2 ]] && break; sleep 1
done
[[ $n -ge 2 ]] && ok "both sidecars reconnected to the new control plane" || die "sidecars did not reconnect"

echo "▶ short load test through the orders app"
if command -v oha >/dev/null; then
  oha -z 15s -c 8 --no-tui -m POST -H 'content-type: application/json' \
    -d '{"question":"How many WIDGET-1 do we have in stock and should we reorder?"}' "http://127.0.0.1:$ORDERS_PORT/ask" >.local/e2e-load.txt
  rps=$(grep -E 'Requests/sec' .local/e2e-load.txt | awk '{print $2}')
  bad=$(grep -oE '\[[0-9]{3}\] [0-9]+' .local/e2e-load.txt | grep -v '^\[200\]' || true)
  [[ -z $bad ]] && ok "15 s at 8 clients: ${rps} req/s through the port-forward, all 200" || echo "  ! non-200 answers: $bad (the demo's small budgets answer 429 under load)"
fi

echo
echo "✓ end-to-end test passed on context $CTX"
