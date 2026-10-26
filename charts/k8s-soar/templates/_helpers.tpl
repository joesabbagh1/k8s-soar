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
{{- define "k8s-soar.step" -}}
image: {{ include "k8s-soar.image" (dict "root" .root "name" .root.Values.response.actions.image) }}
imagePullPolicy: {{ .root.Values.image.pullPolicy }}
args: {{ toJson .args }}
envFrom:
  - configMapRef:
      name: soar-config
env:
  {{- range $env, $key := dict "SLACK_WEBHOOK_URL" "slack-webhook-url" "JIRA_URL" "jira-url" "JIRA_EMAIL" "jira-email" "JIRA_API_TOKEN" "jira-api-token" "JIRA_PROJECT_KEY" "jira-project-key" "GRAFANA_API_TOKEN" "grafana-api-token" }}
  - name: {{ $env }}
    valueFrom:
      secretKeyRef:
        name: {{ $.root.Values.integrations.secretName }}
        key: {{ $key }}
        optional: true
  {{- end }}
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
{{- end }}
{{- define "k8s-soar.output" -}}
- name: {{ . }}
  valueFrom:
    path: /tmp/outputs/{{ . }}
    default: "{}"
{{- end }}
