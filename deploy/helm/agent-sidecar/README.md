# agent-sidecar Helm chart

The agent-sidecar control plane for Kubernetes 1.29 or newer (design: `docs/design/agent-platform.md` §13).

| Resource | What it does |
| --- | --- |
| CRD `charters.attache.io` | One `Charter` per service. Rendered when `crds.install` is true. Annotated `helm.sh/resource-policy: keep`, so uninstalling the chart never deletes Charters. |
| Deployment `embassy-ca` (2 replicas, PDB, anti-affinity) | `embassy serve --components ca,webhook`: IssueCertificate on 15012, admission webhooks on 9443. It creates the CA in Secret `attache-ca` (unless `ca.existingSecret`), creates and renews the serving certificate in Secret `embassy-tls`, and sets the webhooks' `caBundle`. It is the only workload that can read the CA key. |
| Deployment `embassy` (1 replica) | `embassy serve --components controlplane,api,ui`: Connect on 15012, REST/SSE API and console on 8080. |
| Services `embassy-ca` (15012, 443→9443), `embassy` (15012, 8080) | |
| `attache-sidecar-injector`, `attache-charter-validator` | Mutating webhook for pods labelled `attache.io/inject: "true"` in namespaces labelled `attache.io/injection=enabled`; validating webhook for Charters. The chart never renders a `caBundle`. |
| Secrets `embassy-config`, `attache-session-key` | The ControlPlaneConfig (API tokens as SHA-256 only) and the session-cookie key. |
| RBAC | ClusterRole `attache-embassy` (both service accounts), Role `attache-embassy-secrets` (embassy-ca only), user ClusterRoles `attache-charter-view` and `attache-charter-edit`. |
| NetworkPolicy `embassy` (optional) | Port 15012 open to sidecars, port 8080 only for `networkPolicy.httpFrom`. |

## Install

```bash
embassy token create --name alice --role admin --payloads   # prints the token once and its entry
helm install agent-sidecar deploy/helm/agent-sidecar -n attache-system --create-namespace \
  --set-json 'auth.tokens=[{"name":"alice","role":"admin","sha256":"<sha256 from the entry>","namespaces":["*"],"payloads":true}]'
kubectl -n attache-system rollout status deployment/embassy-ca deployment/embassy
```

Then, per application namespace and service:

```bash
kubectl label namespace shop attache.io/injection=enabled
attache charter to-cr orders.charter.yaml | kubectl apply -f -
```

and give the pod template the label `attache.io/inject: "true"` and the annotations `attache.io/service: orders` and `attache.io/app-port: "8080"` (optional: `attache.io/anthropic-secret`, `attache.io/sidecar-image`). The pod's service account must be named like the service or be listed in the charter's `service.service_accounts`.

Console: `kubectl -n attache-system port-forward svc/embassy 8080:8080`, then <http://localhost:8080>.

## Values

See [`values.yaml`](values.yaml); [`values.schema.json`](values.schema.json) refuses unknown keys and any token field other than its SHA-256. The main ones:

| Key | Default | |
| --- | --- | --- |
| `images.embassy`, `images.attached` | `ghcr.io/f8fvwgzc/agent-sidecar/{embassy,attached}:<appVersion>` | `digest` wins over `tag` |
| `auth.tokens` | `[]` | `{name, role, sha256, namespaces, payloads}` |
| `auth.sessionKey.existingSecret` | `""` | Secret with key `key`; empty: the chart keeps a random one |
| `issuance.kubernetes`, `issuance.workloadCertTTL`, `issuance.joinTokens` | `true`, `24h`, `[]` | |
| `policy` | `{}` | ControlPlaneConfig `policy` |
| `ca.existingSecret` | `""` | `<namespace>/<name>` of a CA to reuse (read-only) |
| `otlp.endpoint`, `otlp.endpointAllow` | `""`, `[]` | telemetry of injected sidecars |
| `injection.failurePolicy`, `injection.resources`, `injection.securityContext` | `Fail`, 50m/128Mi (limit 512Mi), non-root and read-only | the injected `attached` container |
| `embassy.resources` | requests 100m/256Mi, limit 1Gi | |
| `embassy.httpTLS`, `embassy.dnsNames` | `false`, `[]` | API over TLS; extra Host names (Ingress) |
| `networkPolicy.enabled`, `networkPolicy.httpFrom` | `false`, `[]` | |

## Security notes

- Writing a `Charter` is equivalent to the attache **admin** role for that service: the validating webhook checks the charter and the policy, but no role-on-diff check applies to kubectl. Grant `attache-charter-edit` accordingly (`rbac.charterEditAggregatesTo`, default: the built-in `admin` role only).
- Kubernetes cannot restrict `create` by resource name, so embassy-ca may create any Secret in the release namespace; it can read and update only `attache-ca`, `embassy-tls` and `attache-session-key`.

## Upgrading from v0.1 (explicit sidecars)

1. Install the chart with `ca.existingSecret=<ns>/attache-ca` to keep the v0.1 CA (peers keep trusting each other during the move).
2. Label the namespace `attache.io/injection=enabled`.
3. Convert each charter ConfigMap: `attache charter to-cr <svc>.charter.yaml | kubectl apply -f -`.
4. Add the inject label and annotations to each Deployment and remove its explicit `attached` container and charter/TLS volumes.
5. Delete the old charter ConfigMap and certificate Secret.
