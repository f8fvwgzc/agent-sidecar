# agent-sidecar Helm chart

The agent-sidecar control plane for Kubernetes 1.29 or newer (design: `docs/design/agent-platform.md` §13).

| Resource | What it does |
| --- | --- |
| CRD `charters.attache.io` | One `Charter` per service. Rendered when `crds.install` is true. Annotated `helm.sh/resource-policy: keep`, so uninstalling the chart never deletes Charters. `files/crds/charters.attache.io.yaml` is a symbolic link to the generated `deploy/crds/charters.attache.io.yaml` (Helm follows it and notes so on stderr; a packaged chart holds the content). |
| Deployment `embassy-ca` (2 replicas, PDB, anti-affinity) | `embassy serve --components ca,webhook`: IssueCertificate on 15012, admission webhooks on 9443. It creates the CA in Secret `attache-ca` (unless `ca.existingSecret`), creates and renews the serving certificate in Secret `embassy-tls`, and sets the webhooks' `caBundle`. It is the only workload that can read the CA key. |
| Deployment `embassy` (1 replica) | `embassy serve --components controlplane,api,ui`: Connect on 15012, REST/SSE API and console on 8080. |
| Services `embassy-ca` (15012, 443→9443), `embassy` (15012, 8080) | |
| `attache-sidecar-injector`, `attache-charter-validator` | Mutating webhook for pods labelled `attache.io/inject: "true"` in namespaces labelled `attache.io/injection=enabled`; validating webhook for Charters. The chart never renders a `caBundle`. |
| Secrets `embassy-config`, `attache-session-key` | The ControlPlaneConfig (API tokens as SHA-256 only) and the session-cookie key. |
| RBAC | ClusterRole `attache-embassy` (both service accounts; the design's rules plus `delete` on `charters`, see below), Role `attache-embassy-secrets` (embassy-ca only), user ClusterRoles `attache-charter-view` and `attache-charter-edit`. |
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

and give the pod template the label `attache.io/inject: "true"` and the annotations `attache.io/service: orders` and `attache.io/app-port: "8080"` (optional: `attache.io/anthropic-secret: <Secret with key ANTHROPIC_API_KEY>`, `attache.io/sidecar-image`). The pod's service account must be named like the service or be listed in the charter's `service.service_accounts`.

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

## What embassy-ca reads from the chart

The chart starts both Deployments with the `embassy serve` flags of design §8.1 only. Four more
things cross from the chart to embassy-ca's code (the Kubernetes and CA unit). The design does not
name them yet, so they are listed here; integration folds them into design §13.

| What | Contract |
| --- | --- |
| `ATTACHE_INJECT_TEMPLATE` (env of embassy-ca) | JSON object of Kubernetes `Container` fields that the injector applies to the `attached` container it generates: `imagePullPolicy` (from `images.attached.pullPolicy`), `resources` (`injection.resources`), `securityContext` (`injection.securityContext`) and, when set, `env` with only `OTEL_EXPORTER_OTLP_ENDPOINT` (`otlp.endpoint`) and `ATTACHE_OTLP_ENDPOINT_ALLOW` (`otlp.endpointAllow`, comma-joined), which are the sidecar's own variables (design §6.1, §9). The injector's own env entries (§13: `ATTACHE_CONTROL_PLANE`, `ATTACHE_SERVICE`, ...) are set by the injector and never taken from the template. Absent: the injector's built-in defaults, which should equal this chart's defaults. |
| Control-plane and CA addresses | Not passed: the injector sets `ATTACHE_CONTROL_PLANE=embassy.<cp-namespace>.svc:15012` and `ATTACHE_CA_ADDRESS=embassy-ca.<cp-namespace>.svc:15012` from `--cp-namespace` and the Service names of §13, which the chart fixes. |
| Webhook entry names | `attache-sidecar-injector` has one entry `sidecar-injector.attache.io`; `attache-charter-validator` has one entry `charter-validator.attache.io`. The caBundle reconciler sets `clientConfig.caBundle` on every entry it reads from the live object. |
| `delete` on `charters` | ClusterRole `attache-embassy` has the §13 verbs plus `delete`: `DELETE /api/v1/services/{ns}/{svc}` (§10, admin) deletes the service's Charter in the kubernetes store. |

## Security notes

- Writing a `Charter` is equivalent to the attache **admin** role for that service: the validating webhook checks the charter and the policy, but no role-on-diff check applies to kubectl. Grant `attache-charter-edit` accordingly (`rbac.charterEditAggregatesTo`, default: the built-in `admin` role only).
- Kubernetes cannot restrict `create` by resource name, so embassy-ca may create any Secret in the release namespace; it can read and update only `attache-ca`, `embassy-tls` and `attache-session-key`.

## Upgrading from v0.1 (explicit sidecars)

1. Install the chart with `ca.existingSecret=<ns>/attache-ca` to keep the v0.1 CA (peers keep trusting each other during the move).
2. Label the namespace `attache.io/injection=enabled`.
3. Convert each charter ConfigMap: `attache charter to-cr <svc>.charter.yaml | kubectl apply -f -`.
4. Add the inject label and annotations to each Deployment and remove its explicit `attached` container and charter/TLS volumes.
5. Delete the old charter ConfigMap and certificate Secret.
