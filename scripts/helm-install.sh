#!/usr/bin/env bash
# Install k8s-soar as separate Helm releases (avoids 1MB release Secret limit).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GENERATED_DIR="${ROOT_DIR}/.generated"
RELEASE="${K8S_SOAR_RELEASE:-k8s-soar}"
NAMESPACE="${K8S_SOAR_NAMESPACE:-k8s-soar}"
HELM_WAIT_TIMEOUT="${K8S_SOAR_HELM_TIMEOUT:-15m}"

chart_version() {
  grep -A2 "name: $1" "${ROOT_DIR}/Chart.lock" | grep 'version:' | awk '{print $2}'
}

CILIUM_VER="$(chart_version cilium)"
FALCO_VER="$(chart_version falco)"
TETRAGON_VER="$(chart_version tetragon)"
KYVERNO_VER="$(chart_version kyverno)"

"${SCRIPT_DIR}/render-helm-values.sh"

cd "$ROOT_DIR"
helm dependency build .

helm_wait=(--wait --timeout "$HELM_WAIT_TIMEOUT")

echo ">>> [1/6] Cilium (CNI) → kube-system"
helm upgrade --install cilium "${ROOT_DIR}/charts/cilium-${CILIUM_VER}.tgz" \
  --namespace kube-system \
  --create-namespace \
  -f "${GENERATED_DIR}/cilium-values.yaml" \
  "${helm_wait[@]}" \
  "$@"

echo ">>> Waiting for nodes after Cilium..."
kubectl wait --for=condition=Ready nodes --all --timeout=600s

echo ">>> [2/6] Kyverno → kyverno"
helm upgrade --install kyverno "${ROOT_DIR}/charts/kyverno-${KYVERNO_VER}.tgz" \
  --namespace kyverno \
  --create-namespace \
  -f "${GENERATED_DIR}/kyverno-values.yaml" \
  "${helm_wait[@]}" \
  "$@"

echo ">>> [3/6] Falco → falco"
helm upgrade --install falco "${ROOT_DIR}/charts/falco-${FALCO_VER}.tgz" \
  --namespace falco \
  --create-namespace \
  -f "${GENERATED_DIR}/falco-values.yaml" \
  "${helm_wait[@]}" \
  "$@"

echo ">>> [4/6] Tetragon → kube-system"
helm upgrade --install tetragon "${ROOT_DIR}/charts/tetragon-${TETRAGON_VER}.tgz" \
  --namespace kube-system \
  -f "${GENERATED_DIR}/tetragon-values.yaml" \
  --set crds.installMethod=operator \
  "${helm_wait[@]}" \
  "$@"

echo ">>> [5/6] k8s-soar extras (SOAR responder) → ${NAMESPACE}"
helm upgrade --install "$RELEASE" "${ROOT_DIR}" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  -f "${GENERATED_DIR}/k8s-soar-values.yaml" \
  "${helm_wait[@]}" \
  "$@"

echo ">>> [6/6] Policies and security-lab (kubectl)"
"${SCRIPT_DIR}/wait-for-policy-crds.sh"
"${SCRIPT_DIR}/apply-policies-lab.sh"

echo ">>> k8s-soar installed (split Helm releases + policies + lab)"
if [[ -n "${KUBECONFIG:-}" ]] || [[ -f "${HOME}/.kube/config" ]]; then
  "${SCRIPT_DIR}/verify-stack.sh" || true
fi
