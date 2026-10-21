{{/*
Fixed object names: RBAC resourceNames and embassy's flags refer to them (design §13).
*/}}
{{- define "agent-sidecar.caSecretName" -}}attache-ca{{- end -}}
{{- define "agent-sidecar.tlsSecretName" -}}embassy-tls{{- end -}}
{{- define "agent-sidecar.sessionKeySecretName" -}}attache-session-key{{- end -}}
{{- define "agent-sidecar.configSecretName" -}}embassy-config{{- end -}}
{{- define "agent-sidecar.injectorName" -}}attache-sidecar-injector{{- end -}}
{{- define "agent-sidecar.validatorName" -}}attache-charter-validator{{- end -}}

{{- define "agent-sidecar.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: attache
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

{{/* --ca-secret: the existing CA Secret, or attache-ca in the release namespace. */}}
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

{{/* host:port of a control-plane Service's gRPC port. */}}
{{- define "agent-sidecar.grpcAddress" -}}
{{ .name }}.{{ .root.Release.Namespace }}.svc:15012
{{- end -}}

{{/* The DNS names of a Service: pass (dict "root" $ "service" "embassy"). */}}
{{- define "agent-sidecar.serviceDNSNames" -}}
{{- $ns := .root.Release.Namespace -}}
{{- list .service (printf "%s.%s" .service $ns) (printf "%s.%s.svc" .service $ns) (printf "%s.%s.svc.%s" .service $ns .root.Values.clusterDomain) | toJson -}}
{{- end -}}

{{/*
The ControlPlaneConfig (design §8.2). Tokens carry SHA-256 only (values.schema.json refuses any
other field).
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
  "apiVersion" "attache.io/v1alpha1"
  "kind" "ControlPlaneConfig"
  "auth" (dict
    "tokens" $tokens
    "anonymous" "none"
    "session_key_file" "/etc/attache/session/key")
  "issuance" (dict
    "kubernetes" .Values.issuance.kubernetes
    "workload_cert_ttl" .Values.issuance.workloadCertTTL
    "join_tokens" $joinTokens)
  "events" (dict "retain_bytes" (int64 .Values.events.retainBytes))
-}}
{{- if .Values.policy -}}
{{- $_ := set $cfg "policy" .Values.policy -}}
{{- end -}}
{{- toYaml $cfg -}}
{{- end -}}
