#!/usr/bin/env bash
# Install or upgrade k8s-soar with Falco rules, policies, and lab applied automatically.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GENERATED_DIR="${ROOT_DIR}/.generated"
OVERLAY="${GENERATED_DIR}/helm-values.yaml"
RELEASE="${K8S_SOAR_RELEASE:-k8s-soar}"
NAMESPACE="${K8S_SOAR_NAMESPACE:-k8s-soar}"

mkdir -p "$GENERATED_DIR"
"${SCRIPT_DIR}/render-helm-values.sh" "$OVERLAY"

cd "$ROOT_DIR"
helm dependency build .

helm upgrade --install "$RELEASE" . \
  --namespace "$NAMESPACE" \
  --create-namespace \
  -f "$OVERLAY" \
  --wait \
  --timeout 15m \
  "$@"

echo ">>> k8s-soar installed (stack + Falco rules + policies + lab)"
if [[ -n "${KUBECONFIG:-}" ]] || [[ -f "${HOME}/.kube/config" ]]; then
  "${SCRIPT_DIR}/verify-stack.sh" || true
fi
