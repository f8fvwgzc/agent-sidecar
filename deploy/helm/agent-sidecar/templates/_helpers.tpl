{{/*
Fixed object names: RBAC resourceNames and embassy's flags refer to them (design §13).
*/}}
{{- define "agent-sidecar.caSecretName" -}}agentsc-ca{{- end -}}
{{- define "agent-sidecar.tlsSecretName" -}}embassy-tls{{- end -}}
{{- define "agent-sidecar.sessionKeySecretName" -}}agentsc-session-key{{- end -}}
{{- define "agent-sidecar.configSecretName" -}}embassy-config{{- end -}}
{{- define "agent-sidecar.injectorName" -}}agentsc-sidecar-injector{{- end -}}
{{- define "agent-sidecar.validatorName" -}}agentsc-charter-validator{{- end -}}

{{- define "agent-sidecar.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agentsc
{{- end -}}

{{/* Selector labels of one component: pass (dict "root" $ "component" "embassy-ca"). */}}
{{- define "agent-sidecar.selectorLabels" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "agent-sidecar.componentLabels" -}}
{{ include "agent-sidecar.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* An image reference: pass (dict "image" .Values.images.embassy "root" $). */}}
{{- define "agent-sidecar.image" -}}
{{- $tag := .image.tag | default .root.Chart.AppVersion -}}
{{- if .image.digest -}}
{{ .image.repository }}@{{ .image.digest }}
{{- else -}}
{{ .image.repository }}:{{ $tag }}
{{- end -}}
{{- end -}}

{{/* --ca-secret: the existing CA Secret, or agentsc-ca in the release namespace. */}}
{{- define "agent-sidecar.caSecretRef" -}}
{{- if .Values.ca.existingSecret -}}
{{- if ne (len (splitList "/" .Values.ca.existingSecret)) 2 -}}
{{- fail "ca.existingSecret must be <namespace>/<name>" -}}
{{- end -}}
{{ .Values.ca.existingSecret }}
{{- else -}}
{{ .Release.Namespace }}/{{ include "agent-sidecar.caSecretName" . }}
{{- end -}}
{{- end -}}

{{- define "agent-sidecar.sessionKeySecret" -}}
{{- .Values.auth.sessionKey.existingSecret | default (include "agent-sidecar.sessionKeySecretName" .) -}}
{{- end -}}

{{/*
AGENTSC_INJECT_TEMPLATE for embassy-ca: Kubernetes Container fields the injector applies to the
agentscd container it generates. Only imagePullPolicy, resources, securityContext and env; env
holds only sidecar variables of design §6.1 and §9 (OTEL_EXPORTER_OTLP_ENDPOINT,
AGENTSC_OTLP_ENDPOINT_ALLOW, AGENTSC_AUDIT_FAIL_CLOSED), AGENTSC_CLUSTER_DOMAIN when clusterDomain is
not cluster.local, and the runtime's AGENTSC_MOCK_FALLBACK. The control-plane and CA addresses are not here: the injector derives
them from --cp-namespace and the fixed Service names (embassy.<ns>.svc:15012,
embassy-ca.<ns>.svc:15012); the trust domain neither: the injector hands the sidecar its own
--trust-domain.
*/}}
{{- define "agent-sidecar.injectTemplate" -}}
{{- $env := list -}}
{{- with .Values.otlp.endpoint -}}
{{- $env = append $env (dict "name" "OTEL_EXPORTER_OTLP_ENDPOINT" "value" .) -}}
{{- end -}}
{{- with .Values.otlp.endpointAllow -}}
{{- $env = append $env (dict "name" "AGENTSC_OTLP_ENDPOINT_ALLOW" "value" (join "," .)) -}}
{{- end -}}
{{- if ne .Values.clusterDomain "cluster.local" -}}
{{- $env = append $env (dict "name" "AGENTSC_CLUSTER_DOMAIN" "value" .Values.clusterDomain) -}}
{{- end -}}
{{- if .Values.injection.mockFallback -}}
{{- $env = append $env (dict "name" "AGENTSC_MOCK_FALLBACK" "value" "1") -}}
{{- end -}}
{{- if .Values.injection.auditFailClosed -}}
{{- $env = append $env (dict "name" "AGENTSC_AUDIT_FAIL_CLOSED" "value" "true") -}}
{{- end -}}
{{- $t := dict
  "imagePullPolicy" .Values.images.agentscd.pullPolicy
  "resources" .Values.injection.resources
  "securityContext" .Values.injection.securityContext
-}}
{{- if $env -}}
{{- $_ := set $t "env" $env -}}
{{- end -}}
{{- toJson $t -}}
{{- end -}}

{{/*
The sidecar image allow-list as a JSON list (ControlPlaneConfig sidecar_images.allowed_digests and
the ValidatingAdmissionPolicy): images.agentscd.digest, when the injector image is pinned by
digest, then injection.allowedImageDigests. Empty: not enforced (development builds). With digests
listed, the injector injects only images pinned to one of them, so the injector image must be
pinned too.
*/}}
{{- define "agent-sidecar.sidecarImageDigests" -}}
{{- $digests := list -}}
{{- with .Values.images.agentscd.digest -}}
{{- $digests = append $digests . -}}
{{- end -}}
{{- if and .Values.injection.allowedImageDigests (not .Values.images.agentscd.digest) -}}
{{- fail "injection.allowedImageDigests needs images.agentscd.digest: with the sidecar image allow-list on, the injector injects only an image pinned to an allowed digest" -}}
{{- end -}}
{{- concat $digests .Values.injection.allowedImageDigests | uniq | toJson -}}
{{- end -}}

{{/* The DNS names of a Service: pass (dict "root" $ "service" "embassy"). */}}
{{- define "agent-sidecar.serviceDNSNames" -}}
{{- $ns := .root.Release.Namespace -}}
{{- list .service (printf "%s.%s" .service $ns) (printf "%s.%s.svc" .service $ns) (printf "%s.%s.svc.%s" .service $ns .root.Values.clusterDomain) | toJson -}}
{{- end -}}

{{/*
The ControlPlaneConfig (design §8.2). Tokens carry SHA-256 only (values.schema.json refuses any
other field). embassy-ca applies sidecar_images; embassy reads the same file and ignores it.
*/}}
{{- define "agent-sidecar.controlPlaneConfig" -}}
{{- $tokens := list -}}
{{- range .Values.auth.tokens -}}
{{- $tokens = append $tokens (dict "name" .name "role" .role "sha256" .sha256 "namespaces" (.namespaces | default (list "*")) "payloads" (.payloads | default false)) -}}
{{- end -}}
{{- $joinTokens := list -}}
{{- range .Values.issuance.joinTokens -}}
{{- $joinTokens = append $joinTokens (dict "name" .name "sha256" .sha256 "namespace" .namespace "services" .services "expires_at" .expires_at) -}}
{{- end -}}
{{- $cfg := dict
  "apiVersion" "agentsc.io/v1alpha1"
  "kind" "ControlPlaneConfig"
  "auth" (dict
    "tokens" $tokens
    "anonymous" "none"
    "session_key_file" "/etc/agentsc/session/key")
  "issuance" (dict
    "kubernetes" .Values.issuance.kubernetes
    "workload_cert_ttl" .Values.issuance.workloadCertTTL
    "join_tokens" $joinTokens)
  "sidecar_images" (dict "allowed_digests" (include "agent-sidecar.sidecarImageDigests" . | fromJsonArray))
  "events" (dict "retain_bytes" (int64 .Values.events.retainBytes))
-}}
{{- if .Values.policy -}}
{{- $_ := set $cfg "policy" .Values.policy -}}
{{- end -}}
{{- toYaml $cfg -}}
{{- end -}}
