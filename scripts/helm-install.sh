#!/usr/bin/env bash
# Install or upgrade k8s-soar: Helm stack, then kubectl apply for policies/lab.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GENERATED_DIR="${ROOT_DIR}/.generated"
OVERLAY="${GENERATED_DIR}/helm-values.yaml"
RELEASE="${K8S_SOAR_RELEASE:-k8s-soar}"
NAMESPACE="${K8S_SOAR_NAMESPACE:-k8s-soar}"
HELM_WAIT_TIMEOUT="${K8S_SOAR_HELM_TIMEOUT:-15m}"

mkdir -p "$GENERATED_DIR"
"${SCRIPT_DIR}/render-helm-values.sh" "$OVERLAY"

cd "$ROOT_DIR"
helm dependency build .

helm_args=(
  upgrade --install "$RELEASE" .
  --namespace "$NAMESPACE"
  --create-namespace
  -f "$OVERLAY"
  --wait
  --timeout "$HELM_WAIT_TIMEOUT"
)

echo ">>> Installing k8s-soar core stack (Cilium, Falco, Tetragon, Kyverno)..."
helm "${helm_args[@]}" \
  --set tetragon.crds.installMethod=operator \
  "$@"

"${SCRIPT_DIR}/wait-for-policy-crds.sh"

"${SCRIPT_DIR}/apply-policies-lab.sh"

echo ">>> k8s-soar installed (stack + Falco rules + policies + lab)"
if [[ -n "${KUBECONFIG:-}" ]] || [[ -f "${HOME}/.kube/config" ]]; then
  "${SCRIPT_DIR}/verify-stack.sh" || true
fi
