#!/usr/bin/env bash
# Create/update the Kubernetes Secrets k8s-soar reads. Idempotent.
#
#   deploy/secrets.env (gitignored, see deploy/secrets.env.example) provides
#   integration credentials. Missing values are simply not set; existing
#   values in the cluster are kept unless the file sets them.
#
#   grafana-admin (monitoring)     generated once if absent
#   soar-integrations (k8s-soar)   notification channels, JIRA_*, GRAFANA_API_TOKEN
#
# SOAR_SECRETS_REPLACE=true rebuilds soar-integrations from the file alone, so
# channels removed from it are removed from the cluster (./k8s-soar configure).
#   soar-ai (k8s-soar)             AI_API_KEY
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${K8S_SOAR_SECRETS_FILE:-${ROOT}/deploy/secrets.env}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

ensure_ns() {
  kubectl get namespace "$1" >/dev/null 2>&1 || kubectl create namespace "$1" >/dev/null
}

# apply_secret <namespace> <name> key=value...   (empty values are skipped)
apply_secret() {
  local ns=$1 name=$2; shift 2
  local args=() kv
  for kv in "$@"; do
    [[ -n "${kv#*=}" ]] && args+=("--from-literal=${kv}")
  done
  [[ ${#args[@]} -gt 0 ]] || return 0
  ensure_ns "$ns"
  local existed=true
  kubectl get secret -n "$ns" "$name" >/dev/null 2>&1 || existed=false
  if [[ "$existed" == true ]]; then
    # Merge: patch only the provided keys.
    local patch="" key value
    for kv in "${args[@]}"; do
      kv=${kv#--from-literal=}; key=${kv%%=*}; value=${kv#*=}
      patch+="\"${key}\":\"$(printf '%s' "$value" | base64 | tr -d '\n')\","
    done
    kubectl patch secret -n "$ns" "$name" -p "{\"data\":{${patch%,}}}" >/dev/null
    echo "updated ${ns}/${name}"
  else
    kubectl create secret generic -n "$ns" "$name" "${args[@]}" >/dev/null
    echo "created ${ns}/${name}"
  fi
}

# Grafana admin: generate once, never rotate implicitly.
if ! kubectl get secret -n monitoring grafana-admin >/dev/null 2>&1; then
  # Read a fixed amount first: `tr </dev/urandom | head` dies of SIGPIPE under pipefail.
  password="${GRAFANA_ADMIN_PASSWORD:-$(head -c 1024 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')}"
  password=${password:0:24}
  apply_secret monitoring grafana-admin "admin-user=admin" "admin-password=${password}"
  echo "Grafana admin password stored in monitoring/grafana-admin (make grafana-password)"
fi

if [[ "${SOAR_SECRETS_REPLACE:-false}" == true ]]; then
  kubectl delete secret -n k8s-soar soar-integrations --ignore-not-found >/dev/null
fi
apply_secret k8s-soar soar-integrations \
  "slack-webhook-url=${SLACK_WEBHOOK_URL:-}" \
  "teams-webhook-url=${TEAMS_WEBHOOK_URL:-}" \
  "google-chat-webhook-url=${GOOGLE_CHAT_WEBHOOK_URL:-}" \
  "webhook-url=${WEBHOOK_URL:-}" \
  "webhook-secret=${WEBHOOK_SECRET:-}" \
  "smtp-host=${SMTP_HOST:-}" \
  "smtp-port=${SMTP_PORT:-}" \
  "smtp-tls=${SMTP_TLS:-}" \
  "smtp-username=${SMTP_USERNAME:-}" \
  "smtp-password=${SMTP_PASSWORD:-}" \
  "smtp-from=${SMTP_FROM:-}" \
  "smtp-to=${SMTP_TO:-}" \
  "pagerduty-routing-key=${PAGERDUTY_ROUTING_KEY:-}" \
  "jira-url=${JIRA_URL:-}" \
  "jira-email=${JIRA_EMAIL:-}" \
  "jira-api-token=${JIRA_API_TOKEN:-}" \
  "jira-project-key=${JIRA_PROJECT_KEY:-}" \
  "grafana-api-token=${GRAFANA_API_TOKEN:-}"

apply_secret k8s-soar soar-ai "api-key=${AI_API_KEY:-}"
