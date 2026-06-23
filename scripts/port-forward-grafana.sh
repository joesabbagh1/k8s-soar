#!/usr/bin/env bash
# Port-forward Grafana from the monitoring namespace.
set -euo pipefail

MONITORING_NS="${K8S_SOAR_MONITORING_NS:-monitoring}"
KPS_RELEASE="${K8S_SOAR_KPS_RELEASE:-kube-prometheus-stack}"
LOCAL_PORT="${GRAFANA_LOCAL_PORT:-3000}"

svc="${KPS_RELEASE}-grafana"

if ! kubectl get svc -n "$MONITORING_NS" "$svc" >/dev/null 2>&1; then
  echo "ERROR: service ${MONITORING_NS}/${svc} not found (is observability enabled?)" >&2
  exit 1
fi

echo "Grafana admin password (default): k8s-soar"
echo "Open http://127.0.0.1:${LOCAL_PORT} — dashboard: k8s-soar — Falco Findings"
echo "Press Ctrl+C to stop port-forward."
kubectl port-forward -n "$MONITORING_NS" "svc/${svc}" "${LOCAL_PORT}:80"
