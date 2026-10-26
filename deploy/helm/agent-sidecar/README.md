# agent-sidecar Helm chart

The agent-sidecar control plane for Kubernetes 1.29 or newer (design: `docs/design/agent-platform.md` §13).

| Resource | What it does |
| --- | --- |
| CRD `charters.agentsc.io` | One `Charter` per service. Rendered when `crds.install` is true. Annotated `helm.sh/resource-policy: keep`, so uninstalling the chart never deletes Charters. `files/crds/charters.agentsc.io.yaml` is a symbolic link to the generated `deploy/crds/charters.agentsc.io.yaml` (Helm follows it and notes so on stderr; a packaged chart holds the content). |
| Deployment `embassy-ca` (2 replicas, PDB, anti-affinity) | `embassy serve --components ca,webhook`: IssueCertificate on 15012, admission webhooks on 9443. It creates the CA in Secret `agentsc-ca` (unless `ca.existingSecret`), creates and renews the serving certificate in Secret `embassy-tls`, and sets the webhooks' `caBundle`. It is the only workload that can read the CA key. |
| Deployment `embassy` (1 replica) | `embassy serve --components controlplane,api,ui`: Connect on 15012, REST/SSE API and console on 8080. |
| Services `embassy-ca` (15012, 443→9443), `embassy` (15012, 8080) | |
| `agentsc-sidecar-injector`, `agentsc-charter-validator` | Mutating webhook for pods labelled `agentsc.io/inject: "true"` in namespaces labelled `agentsc.io/injection=enabled`; validating webhook for Charters. The chart never renders a `caBundle`. |
| ValidatingAdmissionPolicy and Binding `agentsc-sidecar-integrity` | Only where the cluster serves `admissionregistration.k8s.io/v1` ValidatingAdmissionPolicy (Kubernetes 1.30+). The API server's own check of agent pods after every webhook; see [Sidecar integrity](#sidecar-integrity). |
| Secrets `embassy-config`, `agentsc-session-key` | The ControlPlaneConfig (API tokens as SHA-256 only, the sidecar image allow-list) and the session-cookie key. |
| RBAC | ClusterRole `agentsc-embassy` (both service accounts; the design's rules plus `delete` on `charters`, see below), Role `agentsc-embassy-secrets` (embassy-ca only), Role `agentsc-embassy-cp-audit` (both service accounts; the control-plane audit, see below), user ClusterRoles `agentsc-charter-view` and `agentsc-charter-edit`. |
| NetworkPolicy `embassy` (optional) | Port 15012 open to sidecars, port 8080 only for `networkPolicy.httpFrom`. |

## Install

```bash
embassy token create --name alice --role admin --payloads   # prints the token once and its entry
helm install agent-sidecar deploy/helm/agent-sidecar -n agentsc-system --create-namespace \
  --set images.agentscd.digest=sha256:<digest of the release's agentscd image> \
  --set-json 'auth.tokens=[{"name":"alice","role":"admin","sha256":"<sha256 from the entry>","namespaces":["*"],"payloads":true}]'
kubectl -n agentsc-system rollout status deployment/embassy-ca deployment/embassy
```

`images.agentscd.digest` turns the sidecar image allow-list on ([Sidecar integrity](#sidecar-integrity)); leave it out only for development builds.

Then, per application namespace and service:

```bash
kubectl label namespace shop agentsc.io/injection=enabled
agentsc charter to-cr orders.charter.yaml | kubectl apply -f -
```

and give the pod template the label `agentsc.io/inject: "true"` and the annotations `agentsc.io/service: orders` and `agentsc.io/app-port: "8080"` (optional: `agentsc.io/anthropic-secret: <Secret with key ANTHROPIC_API_KEY>`, `agentsc.io/sidecar-image`). The pod's service account must be named like the service or be listed in the charter's `service.service_accounts`. Do not write the sidecar into the pod template: the injector adds two native sidecars, `agentsc-runtime` (the agent runtime) and then `agentscd`, and refuses a pod that brings either of its own.

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
| `injection.failurePolicy`, `injection.resources`, `injection.securityContext` | `Fail`, 50m/128Mi (limit 512Mi), non-root and read-only | the injected `agentscd` and `agentsc-runtime` containers (each gets these resources) |
| `injection.allowedImageDigests` | `[]` | sidecar image digests allowed besides `images.agentscd.digest` ([Sidecar integrity](#sidecar-integrity)) |
| `injection.auditFailClosed` | `false` | `true`: injected sidecars refuse new work (`audit.unavailable`) and report not ready while their audit sink fails (`AGENTSC_AUDIT_FAIL_CLOSED`; their readiness probe then takes the pod out of its Service's endpoints) |
| `embassy.resources` | requests 100m/256Mi, limit 1Gi | |
| `embassy.httpTLS`, `embassy.dnsNames` | `false`, `[]` | API over TLS; extra Host names (Ingress) |
| `embassy.http3` | `false` | API and console over HTTP/3 too (QUIC on UDP 8080, advertised with `Alt-Svc`); needs `httpTLS` |
| `networkPolicy.enabled`, `networkPolicy.httpFrom` | `false`, `[]` | |

## Sidecar integrity

An agent pod's governance lives in its sidecar, so the pod owner must not be able to replace it. Three layers check it:

- **The injector** (`/mutate`) refuses a labelled pod that brings its own `agentscd` or `agentsc-runtime` container (the annotation `agentsc.io/injected` skips nothing), defines or mounts the sidecar's volumes (`agentsc-run`, `agentsc-state`, `agentsc-token`) in another container, projects another service-account token for audience `agentsc`, or sets `shareProcessNamespace` or `hostPID`. The agent runtime runs in its own container, `agentsc-runtime`, with only the socket directory mounted and no environment but `AGENTSC_MOCK_FALLBACK` (with `injection.mockFallback`): the provider API key (`ANTHROPIC_API_KEY` from `agentsc.io/anthropic-secret`) and the workload key (`agentsc-state`) stay in `agentscd`.
- **IssueCertificate** (embassy-ca, so every renewal too) reads the image the kubelet reports as running (`imageID` in `status.initContainerStatuses[]` and `status.containerStatuses[]`) for `agentscd` and `agentsc-runtime`, and refuses a certificate when its digest is not allowed, when the containers run another program than the injected one, or when the pod differs from the injected shape: `agentscd` env other than the injector's (every `agentscd` flag has an env form, such as `AGENTSC_STATE_DIR` or `AGENTSC_RUNTIME_CMD`), `envFrom`, lifecycle hooks, probes other than the exec `agentsc-ready`, other mounts or mount paths, sidecar volumes of other types, a missing `agentsc-runtime`, ephemeral containers, `shareProcessNamespace`/`hostPID`. A pod without the injection label is never seen by the injector, so this is the check it cannot avoid; with the allow-list off (any image) it adds nothing and is skipped. Refusals are audited as `cert_denied`.
- **The ValidatingAdmissionPolicy `agentsc-sidecar-integrity`** (Kubernetes 1.30+) checks agent pods after every webhook, which covers an injector that was bypassed (`injection.failurePolicy: Ignore` while embassy-ca was down). Agent pods are those labelled `agentsc.io/inject: "true"` or with a container named `agentscd` or `agentsc-runtime`, in every namespace but `kube-system` and the release namespace (the injector's exclusions; the namespace label is not needed, so a pod that brings its own sidecar elsewhere is checked too). On CREATE it refuses sidecar containers in a pod without the label `agentsc.io/inject: "true"` (so the injector checks every pod that has them), sidecar images that are not pinned to an allowed digest (allow-list on only), sidecar containers with another command, `shareProcessNamespace` and `hostPID`, other containers mounting the sidecar volumes, `agentsc-runtime` mounting more than `agentsc-run`, and other `agentsc`-audience tokens; on UPDATE a changed sidecar image; and every ephemeral container (`pods/ephemeralcontainers`, `kubectl debug`).

**The allow-list** is ControlPlaneConfig `sidecar_images.allowed_digests`: `images.agentscd.digest` when set, then `injection.allowedImageDigests`. With at least one digest it is enforced: the injector injects only an image pinned to an allowed digest (`<repository>@sha256:<hex>`; a pod's `agentsc.io/sidecar-image` too), and the other two layers refuse anything else. **Empty means not enforced**: development builds such as `make demo-helm`'s `agentsc/agentscd:dev` have no registry digest. embassy-ca then logs a warning at start-up (`SIDECAR IMAGE ALLOW-LIST IS OFF`), and the policy keeps every rule but the image one.

To turn it on in production:

1. Take the digest of the release's image (the multi-arch index the release workflow publishes): the release asset `IMAGE_DIGESTS` has one `<image>@sha256:<hex>` line per image, and `docker buildx imagetools inspect ghcr.io/f8fvwgzc/agent-sidecar/agentscd:<version>` prints the same digest on its `Digest:` line.
2. Set `images.agentscd.digest` to it. The injector then uses `ghcr.io/f8fvwgzc/agent-sidecar/agentscd@<digest>` and the digest is allowed.
3. On an upgrade, keep the previous release's digest in `injection.allowedImageDigests` until every agent pod runs the new one (their renewals still need it), then remove it. List there any other image you name with `agentsc.io/sidecar-image`. Setting `injection.allowedImageDigests` without `images.agentscd.digest` fails to render: the injector would refuse its own tag-only image.

The digest compared at issuance is the one the container runtime reports in `imageID`: containerd and cri-dockerd report the digest the image was pulled by (the index digest above). An image loaded into the node without a registry reports its config digest (`sha256:<hex>` alone), which you would have to list.

Not covered: the image signature itself (the allow-list trusts the digests you list; verifying signatures in the cluster needs an admission controller such as Sigstore policy-controller); with the allow-list on, pod settings outside the sidecar containers of a pod that brings its own sidecar where the injector does not run (outside injection-enabled namespaces, or while it is bypassed), such as `hostAliases`, privileged containers or `hostPath` volumes (require Pod Security `baseline` on agent namespaces); with the allow-list off, a pod's own sidecar with any image; `pods/exec` into the sidecar (grant `pods/exec` like access to the sidecar's secrets); and anyone who may create pod-bound tokens for the pod's service account (`serviceaccounts/token`).

## What embassy-ca reads from the chart

The chart starts both Deployments with the `embassy serve` flags of design §8.1 only. Five more
things cross from the chart to embassy-ca's code (the Kubernetes and CA unit). The design does not
name them yet, so they are listed here; integration folds them into design §13.

| What | Contract |
| --- | --- |
| `AGENTSC_INJECT_TEMPLATE` (env of embassy-ca) | JSON object of Kubernetes `Container` fields that the injector applies to the `agentscd` container it generates: `imagePullPolicy` (from `images.agentscd.pullPolicy`), `resources` (`injection.resources`), `securityContext` (`injection.securityContext`) and, when set, `env` with only `OTEL_EXPORTER_OTLP_ENDPOINT` (`otlp.endpoint`) and `AGENTSC_OTLP_ENDPOINT_ALLOW` (`otlp.endpointAllow`, comma-joined), which are the sidecar's own variables (design §6.1, §9), `AGENTSC_AUDIT_FAIL_CLOSED=true` with `injection.auditFailClosed: true`, and `AGENTSC_MOCK_FALLBACK=1` with `injection.mockFallback: true` (demos only: without `ANTHROPIC_API_KEY`, agents run on the mock instead of being refused). The `agentsc-runtime` container gets the same `imagePullPolicy`, `resources` and `securityContext`, and of the `env` only `AGENTSC_MOCK_FALLBACK` (the runtime reads it; it is not a secret). The injector's own env entries (§13: `AGENTSC_CONTROL_PLANE`, `AGENTSC_SERVICE`, ...) are set by the injector and never taken from the template. Absent: the injector's built-in defaults, which should equal this chart's defaults. |
| `sidecar_images.allowed_digests` (in Secret `embassy-config`) | The sidecar image allow-list: `images.agentscd.digest`, then `injection.allowedImageDigests` ([Sidecar integrity](#sidecar-integrity)). embassy-ca reloads it with the rest of the config; the ValidatingAdmissionPolicy carries the same list, so change it through the chart. |
| Control-plane and CA addresses | Not passed: the injector sets `AGENTSC_CONTROL_PLANE=embassy.<cp-namespace>.svc:15012` and `AGENTSC_CA_ADDRESS=embassy-ca.<cp-namespace>.svc:15012` from `--cp-namespace` and the Service names of §13, which the chart fixes. |
| Webhook entry names | `agentsc-sidecar-injector` has one entry `sidecar-injector.agentsc.io`; `agentsc-charter-validator` has one entry `charter-validator.agentsc.io`. The caBundle reconciler sets `clientConfig.caBundle` on every entry it reads from the live object. |
| `delete` on `charters` | ClusterRole `agentsc-embassy` has the §13 verbs plus `delete`: `DELETE /api/v1/services/{ns}/{svc}` (§10, admin) deletes the service's Charter in the kubernetes store. |
| Control-plane audit | The kubernetes store keeps the control-plane audit (§8.5: who changed which charter, approvals, issuance, connections) in a ring of 16 ConfigMaps `agentsc-cp-audit-0` .. `agentsc-cp-audit-15` in the release namespace, about 256 KiB of JSON lines each (the newest ~4 MiB are kept; `kubectl get cm -l agentsc.io/cp-audit`). Role `agentsc-embassy-cp-audit` grants `get`/`update` on exactly those names and `create` in the release namespace, nothing else on ConfigMaps. They are not part of the release, so `helm uninstall` keeps them. Records are written in the background, at most about one segment write per second per process (each an etcd revision); refusals of unauthenticated requests reach the ring once per kind per minute, with a count (operations guide, "Control-plane audit in the stores"). `GET /api/v1/readyz` reports `cp_audit.append_failures`. |

## Security notes

- Writing a `Charter` is equivalent to the agentsc **admin** role for that service: the validating webhook checks the charter and the policy, but no role-on-diff check applies to kubectl. Grant `agentsc-charter-edit` accordingly (`rbac.charterEditAggregatesTo`, default: the built-in `admin` role only).
- Kubernetes cannot restrict `create` by resource name, so embassy-ca may create any Secret in the release namespace; it can read and update only `agentsc-ca`, `embassy-tls` and `agentsc-session-key`.
- For the same reason embassy and embassy-ca may create any ConfigMap in the release namespace; they can read and update only the 16 `agentsc-cp-audit-<n>` segments. Whoever may update ConfigMaps in that namespace can edit the control-plane audit: keep that namespace to control-plane admins, and ship embassy's stdout (every record is also a JSON line there) to append-only storage.

## Upgrading from v0.1 (explicit sidecars)

1. Install the chart with `ca.existingSecret=<ns>/agentsc-ca` to keep the v0.1 CA (peers keep trusting each other during the move).
2. Label the namespace `agentsc.io/injection=enabled`.
3. Convert each charter ConfigMap: `agentsc charter to-cr <svc>.charter.yaml | kubectl apply -f -`.
4. Add the inject label and annotations to each Deployment and remove its explicit `agentscd` container and charter/TLS volumes.
5. Delete the old charter ConfigMap and certificate Secret.
