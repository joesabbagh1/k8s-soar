{{/* Common labels */}}
{{- define "k8s-soar.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: k8s-soar
{{- end }}

{{/* Container image: k8s-soar.image (dict "root" . "name" "k8s-soar-actions") */}}
{{- define "k8s-soar.image" -}}
{{- printf "%s/%s:%s" .root.Values.image.registry .name (default .root.Chart.AppVersion .root.Values.image.tag) }}
{{- end }}

{{/* Kyverno exclude block for trusted namespaces */}}
{{- define "k8s-soar.kyvernoExclude" -}}
exclude:
  any:
    - resources:
        namespaces:
          {{- toYaml .Values.trustedNamespaces | nindent 10 }}
{{- end }}

{{/* Names shared between templates */}}
{{- define "k8s-soar.responderSA" -}}soar-responder{{- end }}
{{- define "k8s-soar.agentSA" -}}soar-agent{{- end }}
{{- define "k8s-soar.eventSource" -}}soar-webhook{{- end }}
{{- define "k8s-soar.webhookService" -}}soar-webhook-eventsource-svc{{- end }}
{{- define "k8s-soar.agentUrl" -}}
{{- if .Values.ai.enabled }}http://soar-agent.{{ .Release.Namespace }}.svc.cluster.local:8080{{ end }}
{{- end }}

{{/* Container spec shared by all workflow steps: k8s-soar.step (dict "root" . "args" (list ...)) */}}
{{/* Env var -> key in the integrations Secret (all optional; written by ./k8s-soar setup or make secrets). */}}
{{- define "k8s-soar.integrationKeys" -}}
SLACK_WEBHOOK_URL: slack-webhook-url
TEAMS_WEBHOOK_URL: teams-webhook-url
GOOGLE_CHAT_WEBHOOK_URL: google-chat-webhook-url
WEBHOOK_URL: webhook-url
WEBHOOK_SECRET: webhook-secret
SMTP_HOST: smtp-host
SMTP_PORT: smtp-port
SMTP_TLS: smtp-tls
SMTP_USERNAME: smtp-username
SMTP_PASSWORD: smtp-password
SMTP_FROM: smtp-from
SMTP_TO: smtp-to
PAGERDUTY_ROUTING_KEY: pagerduty-routing-key
JIRA_URL: jira-url
JIRA_EMAIL: jira-email
JIRA_API_TOKEN: jira-api-token
JIRA_PROJECT_KEY: jira-project-key
GRAFANA_API_TOKEN: grafana-api-token
{{- end }}

{{/*
Dev mode (`./k8s-soar dev on`): the Python source from the repo on the node is
mounted over the installed package, so code changes are live without building
images. Console and agent reload on save; workflow steps use it from the next case.
*/}}
{{- define "k8s-soar.devEnv" -}}
{{- if .Values.dev.enabled }}
- name: PYTHONPATH
  value: /dev-src
- name: SOAR_DEV_RELOAD
  value: "true"
{{- end }}
{{- end }}
{{- define "k8s-soar.devMount" -}}
{{- if .Values.dev.enabled }}
- name: dev-src
  mountPath: /dev-src
  readOnly: true
{{- end }}
{{- end }}
{{- define "k8s-soar.devVolume" -}}
{{- if .Values.dev.enabled }}
- name: dev-src
  hostPath:
    path: {{ required "dev.sourcePath is required when dev.enabled" .Values.dev.sourcePath }}
    type: Directory
{{- end }}
{{- end }}
{{- define "k8s-soar.devNode" -}}
{{- if and .Values.dev.enabled .Values.dev.node }}
nodeSelector:
  kubernetes.io/hostname: {{ .Values.dev.node | quote }}
{{- end }}
{{- end }}

{{- define "k8s-soar.step" -}}
image: {{ include "k8s-soar.image" (dict "root" .root "name" .root.Values.response.actions.image) }}
imagePullPolicy: {{ .root.Values.image.pullPolicy }}
# Explicit, so Argo's emissary executor never has to query the registry for the entrypoint.
command: [soar-actions]
args: {{ toJson .args }}
envFrom:
  - configMapRef:
      name: soar-config
env:
  {{- range $env, $key := include "k8s-soar.integrationKeys" . | fromYaml }}
  - name: {{ $env }}
    valueFrom:
      secretKeyRef:
        name: {{ $.root.Values.integrations.secretName }}
        key: {{ $key }}
        optional: true
  {{- end }}
  {{- include "k8s-soar.devEnv" .root | nindent 2 }}
resources:
  {{- toYaml .root.Values.response.actions.resources | nindent 2 }}
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
  seccompProfile:
    type: RuntimeDefault
volumeMounts:
  - name: outputs
    mountPath: /tmp/outputs
  {{- include "k8s-soar.devMount" .root | nindent 2 }}
{{- end }}
{{- define "k8s-soar.output" -}}
- name: {{ . }}
  valueFrom:
    path: /tmp/outputs/{{ . }}
    default: "{}"
{{- end }}
