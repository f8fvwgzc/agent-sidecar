#!/usr/bin/env bash
# Console sign-in against a real Keycloak dev realm (Tutela docs/INTEGRATION.md §1, standalone mode):
# Keycloak in Docker, embassy from this checkout, and a scripted browser (curl with a cookie jar)
# that signs in through Keycloak's own login form. Needs docker, curl and python3.
#
#   make oidc-check            check, then stop everything
#   KEEP=1 make oidc-check     leave it running to try the console: http://localhost:18080
#                              (dev-admin / dev-only-password); stop it with Ctrl-C
#
# Every credential here is a test value of deploy/keycloak/dev-realm.json.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
EMBASSY=${EMBASSY:-$ROOT/target/debug/embassy}
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.0}
KC_PORT=${KC_PORT:-18180}
HTTP_PORT=18080 # the realm registers this redirect URI
ISSUER=http://localhost:$KC_PORT/realms/attache-dev
CONSOLE=http://localhost:$HTTP_PORT
NAME=agentsc-oidc-check-$$
WORK=$(mktemp -d)
EMBASSY_PID=

cleanup() {
  [[ -n $EMBASSY_PID ]] && kill "$EMBASSY_PID" 2>/dev/null || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "oidc-check: FAILED: $*" >&2
  [[ -f $WORK/embassy.log ]] && tail -n 20 "$WORK/embassy.log" >&2
  exit 1
}

[[ -x $EMBASSY ]] || cargo build -q -p embassy --manifest-path "$ROOT/Cargo.toml"

echo "starting Keycloak ($KEYCLOAK_IMAGE)"
docker run -d --rm --name "$NAME" -p "127.0.0.1:$KC_PORT:8080" \
  -e KC_HOSTNAME="http://localhost:$KC_PORT" \
  -v "$ROOT/deploy/keycloak/dev-realm.json:/opt/keycloak/data/import/realm.json:ro" \
  "$KEYCLOAK_IMAGE" start-dev --import-realm >/dev/null
for _ in $(seq 1 120); do
  curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null && break
  sleep 1
done
curl -sf "$ISSUER/.well-known/openid-configuration" >/dev/null || fail "Keycloak did not start"

printf '%s\n' dev-only-client-secret >"$WORK/client-secret"
head -c 32 /dev/urandom >"$WORK/session-key"
cat >"$WORK/config.yaml" <<YAML
apiVersion: agentsc.io/v1alpha1
kind: ControlPlaneConfig
auth:
  session_key_file: $WORK/session-key
  oidc:
    issuer: $ISSUER
    tenant: ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b
    client_id: attache-console
    client_secret_file: $WORK/client-secret
    redirect_url: $CONSOLE/api/v1/auth/oidc/callback
    dev_loopback: true
    users:
      - sub: 0b9f3a1e-7c44-4d7b-9a55-5d3c8e7f1a01
        name: dev-admin
        role: admin
        namespaces: ["*"]
    groups:
      - group: operators
        role: editor
        namespaces: ["*"]
YAML

echo "starting embassy"
"$EMBASSY" ca-init --out "$WORK/ca" >/dev/null
"$EMBASSY" serve --components controlplane,api,ui,ca --ca-dir "$WORK/ca" \
  --store "file:$WORK/store" --config "$WORK/config.yaml" \
  --http-addr "127.0.0.1:$HTTP_PORT" --grpc-addr 127.0.0.1:0 >"$WORK/embassy.log" 2>&1 &
EMBASSY_PID=$!
for _ in $(seq 1 30); do
  curl -sf "$CONSOLE/healthz" >/dev/null && break
  sleep 1
done
curl -sf "$CONSOLE/healthz" >/dev/null || fail "embassy did not start"

# Sign in as a browser would; prints the URL the sign-in ended at. curl does not run the callback
# page's move to the console, so a good sign-in ends on the callback.
sign_in() {
  local user=$1 jar=$2 form action
  form=$(curl -sfL -c "$jar" -b "$jar" "$CONSOLE/api/v1/auth/oidc/login") || fail "the login page did not load"
  action=$(python3 -c '
import html, re, sys
m = re.search(r"<form[^>]*action=\"([^\"]+)\"", sys.stdin.read())
print(html.unescape(m.group(1)) if m else "")' <<<"$form")
  [[ -n $action ]] || fail "no login form from Keycloak"
  curl -s -L -o /dev/null -w '%{url_effective}' -c "$jar" -b "$jar" \
    --data-urlencode "username=$user" --data-urlencode "password=dev-only-password" "$action"
}

jar=$WORK/admin.jar
end=$(sign_in dev-admin "$jar")
[[ $end == "$CONSOLE/api/v1/auth/oidc/callback?"* ]] || fail "dev-admin ended at $end"
grep -q '#HttpOnly_localhost.*agentsc_session' "$jar" || fail "no HttpOnly session cookie"
me=$(curl -sf -b "$jar" "$CONSOLE/api/v1/whoami") || fail "whoami refused the session"
python3 -c 'import json, sys; m = json.loads(sys.argv[1]); assert (m["name"], m["role"]) == ("dev-admin", "admin"), m' "$me" ||
  fail "whoami said $me"
echo "ok: dev-admin signed in through Keycloak: $me"

end=$(sign_in dev-operator "$WORK/operator.jar")
[[ $end == "$CONSOLE/api/v1/auth/oidc/callback?"* ]] || fail "dev-operator ended at $end"
me=$(curl -sf -b "$WORK/operator.jar" "$CONSOLE/api/v1/whoami") || fail "whoami refused dev-operator"
python3 -c 'import json, sys; m = json.loads(sys.argv[1]); assert (m["role"], m["name"][:5]) == ("editor", "oidc:"), m' "$me" ||
  fail "whoami said $me"
echo "ok: dev-operator signed in through its Keycloak group: $me"

end=$(sign_in dev-stranger "$WORK/stranger.jar")
[[ $end == "$CONSOLE/?signin=no_access" ]] || fail "dev-stranger ended at $end"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$WORK/stranger.jar" "$CONSOLE/api/v1/whoami")
[[ $code == 401 ]] || fail "dev-stranger got $code from whoami"
echo "ok: dev-stranger signed in at Keycloak and got no access here"

out=$(curl -sf -X POST -b "$jar" -c "$jar" -H 'X-Agentsc-CSRF: 1' -H 'Content-Type: application/json' "$CONSOLE/api/v1/logout")
python3 -c 'import json, sys; assert "/protocol/openid-connect/logout" in json.loads(sys.argv[1])["end_session_url"]' "$out" ||
  fail "logout said $out"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" "$CONSOLE/api/v1/whoami")
[[ $code == 401 ]] || fail "after sign-out whoami answered $code"
echo "ok: sign-out ended the session and points at Keycloak's own sign-out"

if [[ ${KEEP:-} == 1 ]]; then
  echo "running: console $CONSOLE, Keycloak $ISSUER (dev-admin / dev-only-password). Ctrl-C stops it."
  wait "$EMBASSY_PID"
fi
echo "oidc-check: passed"
