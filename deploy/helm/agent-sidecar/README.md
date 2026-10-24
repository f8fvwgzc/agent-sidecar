# agent-sidecar Helm chart

The agent-sidecar control plane for Kubernetes 1.29 or newer (design: `docs/design/agent-platform.md` §13).

| Resource | What it does |
| --- | --- |
| CRD `charters.agentsc.io` | One `Charter` per service. Rendered when `crds.install` is true. Annotated `helm.sh/resource-policy: keep`, so uninstalling the chart never deletes Charters. `files/crds/charters.agentsc.io.yaml` is a symbolic link to the generated `deploy/crds/charters.agentsc.io.yaml` (Helm follows it and notes so on stderr; a packaged chart holds the content). |
| Deployment `embassy-ca` (2 replicas, PDB, anti-affinity) | `embassy serve --components ca,webhook`: IssueCertificate on 15012, admission webhooks on 9443. It creates the CA in Secret `agentsc-ca` (unless `ca.existingSecret`), creates and renews the serving certificate in Secret `embassy-tls`, and sets the webhooks' `caBundle`. It is the only workload that can read the CA key. |
| Deployment `embassy` (1 replica) | `embassy serve --components controlplane,api,ui`: Connect on 15012, REST/SSE API and console on 8080. |
| Services `embassy-ca` (15012, 443→9443), `embassy` (15012, 8080) | |
| `agentsc-sidecar-injector`, `agentsc-charter-validator` | Mutating webhook for pods labelled `agentsc.io/inject: "true"` in namespaces labelled `agentsc.io/injection=enabled`; validating webhook for Charters. The chart never renders a `caBundle`. |
| Secrets `embassy-config`, `agentsc-session-key` | The ControlPlaneConfig (API tokens as SHA-256 only) and the session-cookie key. |
| RBAC | ClusterRole `agentsc-embassy` (both service accounts; the design's rules plus `delete` on `charters`, see below), Role `agentsc-embassy-secrets` (embassy-ca only), user ClusterRoles `agentsc-charter-view` and `agentsc-charter-edit`. |
| NetworkPolicy `embassy` (optional) | Port 15012 open to sidecars, port 8080 only for `networkPolicy.httpFrom`. |

## Install

```bash
embassy token create --name alice --role admin --payloads   # prints the token once and its entry
helm install agent-sidecar deploy/helm/agent-sidecar -n agentsc-system --create-namespace \
  --set-json 'auth.tokens=[{"name":"alice","role":"admin","sha256":"<sha256 from the entry>","namespaces":["*"],"payloads":true}]'
kubectl -n agentsc-system rollout status deployment/embassy-ca deployment/embassy
```

Then, per application namespace and service:

```bash
kubectl label namespace shop agentsc.io/injection=enabled
agentsc charter to-cr orders.charter.yaml | kubectl apply -f -
```

and give the pod template the label `agentsc.io/inject: "true"` and the annotations `agentsc.io/service: orders` and `agentsc.io/app-port: "8080"` (optional: `agentsc.io/anthropic-secret: <Secret with key ANTHROPIC_API_KEY>`, `agentsc.io/sidecar-image`). The pod's service account must be named like the service or be listed in the charter's `service.service_accounts`.

Console: `kubectl -n agentsc-system port-forward svc/embassy 8080:8080`, then <http://localhost:8080>.

## Values

See [`values.yaml`](values.yaml); [`values.schema.json`](values.schema.json) refuses unknown keys and any token field other than its SHA-256. The main ones:

| Key | Default | |
| --- | --- | --- |
| `images.embassy`, `images.agentscd` | `ghcr.io/f8fvwgzc/agent-sidecar/{embassy,agentscd}:<appVersion>` | `digest` wins over `tag` |
| `auth.tokens` | `[]` | `{name, role, sha256, namespaces, payloads}` |
| `auth.sessionKey.existingSecret` | `""` | Secret with key `key`; empty: the chart keeps a random one |
| `issuance.kubernetes`, `issuance.workloadCertTTL`, `issuance.joinTokens` | `true`, `24h`, `[]` | |
| `policy` | `{}` | ControlPlaneConfig `policy` |
| `ca.existingSecret` | `""` | `<namespace>/<name>` of a CA to reuse (read-only) |
| `otlp.endpoint`, `otlp.endpointAllow` | `""`, `[]` | telemetry of injected sidecars |
| `injection.failurePolicy`, `injection.resources`, `injection.securityContext` | `Fail`, 50m/128Mi (limit 512Mi), non-root and read-only | the injected `agentscd` container |
| `embassy.resources` | requests 100m/256Mi, limit 1Gi | |
| `embassy.httpTLS`, `embassy.dnsNames` | `false`, `[]` | API over TLS; extra Host names (Ingress) |
| `embassy.http3` | `false` | API and console over HTTP/3 too (QUIC on UDP 8080, advertised with `Alt-Svc`); needs `httpTLS` |
| `networkPolicy.enabled`, `networkPolicy.httpFrom` | `false`, `[]` | |

## What embassy-ca reads from the chart

The chart starts both Deployments with the `embassy serve` flags of design §8.1 only. Four more
things cross from the chart to embassy-ca's code (the Kubernetes and CA unit). The design does not
name them yet, so they are listed here; integration folds them into design §13.

| What | Contract |
| --- | --- |
| `AGENTSC_INJECT_TEMPLATE` (env of embassy-ca) | JSON object of Kubernetes `Container` fields that the injector applies to the `agentscd` container it generates: `imagePullPolicy` (from `images.agentscd.pullPolicy`), `resources` (`injection.resources`), `securityContext` (`injection.securityContext`) and, when set, `env` with only `OTEL_EXPORTER_OTLP_ENDPOINT` (`otlp.endpoint`) and `AGENTSC_OTLP_ENDPOINT_ALLOW` (`otlp.endpointAllow`, comma-joined), which are the sidecar's own variables (design §6.1, §9). The injector's own env entries (§13: `AGENTSC_CONTROL_PLANE`, `AGENTSC_SERVICE`, ...) are set by the injector and never taken from the template. Absent: the injector's built-in defaults, which should equal this chart's defaults. |
| Control-plane and CA addresses | Not passed: the injector sets `AGENTSC_CONTROL_PLANE=embassy.<cp-namespace>.svc:15012` and `AGENTSC_CA_ADDRESS=embassy-ca.<cp-namespace>.svc:15012` from `--cp-namespace` and the Service names of §13, which the chart fixes. |
| Webhook entry names | `agentsc-sidecar-injector` has one entry `sidecar-injector.agentsc.io`; `agentsc-charter-validator` has one entry `charter-validator.agentsc.io`. The caBundle reconciler sets `clientConfig.caBundle` on every entry it reads from the live object. |
| `delete` on `charters` | ClusterRole `agentsc-embassy` has the §13 verbs plus `delete`: `DELETE /api/v1/services/{ns}/{svc}` (§10, admin) deletes the service's Charter in the kubernetes store. |

## Security notes

- Writing a `Charter` is equivalent to the agentsc **admin** role for that service: the validating webhook checks the charter and the policy, but no role-on-diff check applies to kubectl. Grant `agentsc-charter-edit` accordingly (`rbac.charterEditAggregatesTo`, default: the built-in `admin` role only).
- Kubernetes cannot restrict `create` by resource name, so embassy-ca may create any Secret in the release namespace; it can read and update only `agentsc-ca`, `embassy-tls` and `agentsc-session-key`.

## Upgrading from v0.1 (explicit sidecars)

1. Install the chart with `ca.existingSecret=<ns>/agentsc-ca` to keep the v0.1 CA (peers keep trusting each other during the move).
2. Label the namespace `agentsc.io/injection=enabled`.
3. Convert each charter ConfigMap: `agentsc charter to-cr <svc>.charter.yaml | kubectl apply -f -`.
4. Add the inject label and annotations to each Deployment and remove its explicit `agentscd` container and charter/TLS volumes.
5. Delete the old charter ConfigMap and certificate Secret.
