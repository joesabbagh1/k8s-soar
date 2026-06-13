#!/usr/bin/env bash
# Re-render Falco values, upgrade the release, and recycle pods so falcoctl
# re-installs k8smeta + container plugins (required for k8s-soar rules).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GENERATED_DIR="${ROOT_DIR}/.generated"
HELM_WAIT_TIMEOUT="${K8S_SOAR_HELM_TIMEOUT:-15m}"

chart_version() {
  grep -A2 "name: falco" "${ROOT_DIR}/Chart.lock" | grep 'version:' | awk '{print $2}'
}

FALCO_VER="$(chart_version)"

echo ">>> Rendering Falco values..."
"${SCRIPT_DIR}/render-helm-values.sh"

echo ">>> Upgrading Falco (plugins + rules + sidekick)..."
helm upgrade --install falco "${ROOT_DIR}/charts/falco-${FALCO_VER}.tgz" \
  --namespace falco \
  --create-namespace \
  -f "${GENERATED_DIR}/falco-values.yaml" \
  --wait \
  --timeout "$HELM_WAIT_TIMEOUT"

echo ">>> Waiting for Falco daemonset..."
kubectl rollout status daemonset -n falco -l app.kubernetes.io/name=falco --timeout=600s

echo ">>> Checking plugin init container..."
pod="$(kubectl get pod -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')"
init_state="$(kubectl get pod -n falco "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="falcoctl-artifact-install")].state.terminated.reason}' 2>/dev/null || true)"
if [[ "$init_state" != "Completed" ]]; then
  echo "WARN: falcoctl-artifact-install did not complete (reason=${init_state:-unknown})"
  kubectl logs -n falco "$pod" -c falcoctl-artifact-install --tail=80 2>/dev/null || true
else
  echo ">>> falcoctl-artifact-install: Completed"
fi

if kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=120 2>/dev/null \
  | grep -q 'please make sure to install them'; then
  echo "WARN: Falco still reports missing plugins — check ghcr.io connectivity from the node"
  kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=40 2>/dev/null || true
  exit 1
fi

echo ">>> Falco plugins OK"
kubectl get deploy -n falco -l app.kubernetes.io/name=k8s-metacollector 2>/dev/null || \
  kubectl get deploy -n falco 2>/dev/null | grep -i metacollector || true
