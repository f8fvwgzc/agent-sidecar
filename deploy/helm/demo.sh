#!/usr/bin/env bash
# `make demo-helm`: the v0.2 demo on minikube through the Helm chart (docs/design/agent-platform.md
# §13). The images are already in minikube's docker (make build). This script installs the chart,
# waits for embassy-ca to arm the webhooks, enables injection for the demo namespace, makes sure the
# Secret agentsc-anthropic exists (ANTHROPIC_API_KEY, empty for the mock model), applies the example
# charters as Charter resources, deploys the two apps without a sidecar in their spec and runs the
# demo calls (scripts/demo.sh). Every kubectl and helm call names the context explicitly.
set -euo pipefail
cd "$(dirname "$0")/../.."

KUBE_CONTEXT=${KUBE_CONTEXT:-minikube}
CP_NS=${CP_NS:-agentsc-system}
RELEASE=${RELEASE:-agent-sidecar}
AGENTSC=${AGENTSC:-./target/debug/agentsc}
EMBASSY=${EMBASSY:-./target/debug/embassy}
TAG=${TAG:-dev}
# The example charters name this namespace (service.namespace, and inventory's authz identities).
NS=agentsc-demo
TOKEN_FILE=.local/helm-admin-token

kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }

if kc -n "$NS" get configmap orders-charter >/dev/null 2>&1; then
  echo "the v0.1 demo (explicit sidecars, make deploy) is installed in $NS; remove it first: make undeploy" >&2
  exit 1
fi

echo "▶ admin token for the console ($TOKEN_FILE)"
mkdir -p .local
if [[ ! -s $TOKEN_FILE ]]; then
  (umask 077 && "$EMBASSY" token create --name demo-admin --role admin --payloads >"$TOKEN_FILE")
fi
SHA256=$(sed -n -E 's/^[- ] *sha256: *([0-9a-f]{64})$/\1/p' "$TOKEN_FILE")
[[ $SHA256 =~ ^[0-9a-f]{64}$ ]] || { echo "no sha256 in $TOKEN_FILE; delete it and retry" >&2; exit 1; }

echo "▶ helm upgrade --install $RELEASE (namespace $CP_NS)"
helm upgrade --install "$RELEASE" deploy/helm/agent-sidecar \
  --kube-context "$KUBE_CONTEXT" --namespace "$CP_NS" --create-namespace \
  --set images.embassy.repository=agentsc/embassy --set "images.embassy.tag=$TAG" \
  --set images.agentscd.repository=agentsc/agentscd --set "images.agentscd.tag=$TAG" \
  --set-json "auth.tokens=[{\"name\":\"demo-admin\",\"role\":\"admin\",\"sha256\":\"$SHA256\",\"namespaces\":[\"*\"],\"payloads\":true}]" \
  --wait --timeout 5m

echo "▶ waiting for embassy-ca to set the webhooks' caBundle"
for kind in mutatingwebhookconfiguration/agentsc-sidecar-injector validatingwebhookconfiguration/agentsc-charter-validator; do
  ca=
  for _ in $(seq 1 60); do
    ca=$(kc get "$kind" -o jsonpath='{.webhooks[0].clientConfig.caBundle}' 2>/dev/null || true)
    [[ -n $ca ]] && break
    sleep 2
  done
  [[ -n $ca ]] || { echo "✗ $kind has no caBundle after 120 s (kubectl -n $CP_NS logs deploy/embassy-ca)" >&2; exit 1; }
done

echo "▶ namespace $NS with injection enabled"
kc create namespace "$NS" --dry-run=client -o yaml | kc apply -f -
kc label namespace "$NS" agentsc.io/injection=enabled --overwrite

# The apps' annotation agentsc.io/anthropic-secret names this Secret. It always exists so pods never
# wait for it: with an empty key the runtime uses the mock model. A key set here, or later with
# `make secret-anthropic`, is never overwritten by a run without one.
if [[ -n ${ANTHROPIC_API_KEY:-} ]]; then
  echo "▶ Secret agentsc-anthropic from ANTHROPIC_API_KEY (real model)"
  # The key goes through stdin, not the command line.
  printf %s "$ANTHROPIC_API_KEY" |
    kc -n "$NS" create secret generic agentsc-anthropic --from-file=ANTHROPIC_API_KEY=/dev/stdin \
      --dry-run=client -o yaml | kc apply -f -
elif ! kc -n "$NS" get secret agentsc-anthropic >/dev/null 2>&1; then
  echo "▶ Secret agentsc-anthropic, empty (mock model; make secret-anthropic switches to the real one)"
  kc -n "$NS" create secret generic agentsc-anthropic --from-literal=ANTHROPIC_API_KEY=
fi

echo "▶ Charter resources from examples/charters (validated by the admission webhook)"
for svc in orders inventory; do
  "$AGENTSC" charter to-cr "examples/charters/$svc.charter.yaml" | kc apply -f -
done

echo "▶ the demo apps (the webhook injects agentscd)"
kc apply -f deploy/helm/demo/apps.yaml
kc -n "$NS" rollout restart deployment/orders deployment/inventory
kc -n "$NS" rollout status deployment/orders --timeout=300s
kc -n "$NS" rollout status deployment/inventory --timeout=300s
# One line per live pod: its init containers.
LIVE_INIT='{{range .items}}{{if not .metadata.deletionTimestamp}}{{range .spec.initContainers}}{{.name}} {{end}}|{{end}}{{end}}'
for svc in orders inventory; do
  pods=$(kc -n "$NS" get pods -l "app=$svc" -o go-template="$LIVE_INIT")
  IFS='|' read -r -a inits <<<"$pods"
  [[ ${#inits[@]} -gt 0 ]] || { echo "✗ no $svc pod" >&2; exit 1; }
  for init in "${inits[@]}"; do
    # the runtime first: agentscd's startup probe waits for its Health
    [[ " $init " == *" agentsc-runtime agentscd "* ]] || { echo "✗ a $svc pod was not injected (init containers: ${init:-none})" >&2; exit 1; }
  done
done
echo "✓ both pods run the injected agentsc-runtime and agentscd sidecars"

# Ready pods are not yet reachable through their Service for a moment after a rollout: wait until
# the orders sidecar can open inventory's mesh port before the first cross-service call.
echo -n "▶ waiting until orders reaches inventory's mesh port"
reached=
for _ in $(seq 1 60); do
  if kc -n "$NS" exec deploy/orders -c agentscd -- python3 -c \
    "import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(s.connect_ex(('inventory.$NS.svc.cluster.local', 50002)))" \
    >/dev/null 2>&1; then
    reached=1; echo " ok"; break
  fi
  echo -n "."; sleep 1
done
[[ -n $reached ]] || { echo; echo "✗ orders cannot reach inventory.$NS.svc:50002" >&2; exit 1; }

AGENTSC=$AGENTSC NS=$NS KUBE_CONTEXT=$KUBE_CONTEXT ./scripts/demo.sh

echo
echo "console: kubectl --context $KUBE_CONTEXT -n $CP_NS port-forward svc/embassy 8080:8080"
echo "         then http://localhost:8080 with the token on the first line of $TOKEN_FILE"
