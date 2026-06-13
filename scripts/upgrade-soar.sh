#!/usr/bin/env bash
# Upgrade k8s-soar release (SOAR responder) and roll pods so ConfigMap changes apply.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GENERATED_DIR="${ROOT_DIR}/.generated"
RELEASE="${K8S_SOAR_RELEASE:-k8s-soar}"
NAMESPACE="${K8S_SOAR_NAMESPACE:-k8s-soar}"
HELM_WAIT_TIMEOUT="${K8S_SOAR_HELM_TIMEOUT:-15m}"

"${SCRIPT_DIR}/render-helm-values.sh"

echo ">>> Upgrading ${RELEASE} (SOAR responder)..."
helm upgrade --install "$RELEASE" "${ROOT_DIR}" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  -f "${GENERATED_DIR}/k8s-soar-values.yaml" \
  --wait \
  --timeout "$HELM_WAIT_TIMEOUT"

echo ">>> Waiting for SOAR responder rollout..."
kubectl rollout status deployment/k8s-soar-responder -n "$NAMESPACE" --timeout=300s

if kubectl get configmap -n "$NAMESPACE" k8s-soar-responder -o yaml 2>/dev/null | grep -q 'output_fields'; then
  echo ">>> SOAR responder config: output_fields parser present"
else
  echo "WARN: ConfigMap may be stale — check helm upgrade output"
fi

echo ">>> SOAR upgrade complete"
