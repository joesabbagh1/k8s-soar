#!/usr/bin/env bash
# Install k8s-soar as separate Helm releases (avoids 1MB release Secret limit).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GENERATED_DIR="${ROOT_DIR}/.generated"
RELEASE="${K8S_SOAR_RELEASE:-k8s-soar}"
NAMESPACE="${K8S_SOAR_NAMESPACE:-k8s-soar}"
HELM_WAIT_TIMEOUT="${K8S_SOAR_HELM_TIMEOUT:-15m}"
MONITORING_NS="${K8S_SOAR_MONITORING_NS:-monitoring}"
KPS_RELEASE="${K8S_SOAR_KPS_RELEASE:-kube-prometheus-stack}"

chart_version() {
  grep -A2 "name: $1" "${ROOT_DIR}/Chart.lock" | grep 'version:' | awk '{print $2}'
}

observability_enabled() {
  if [[ -n "${K8S_SOAR_ENABLE_OBSERVABILITY:-}" ]]; then
    [[ "${K8S_SOAR_ENABLE_OBSERVABILITY}" == "1" ]]
    return
  fi
  [[ "$(python3 - <<PY
import yaml
from pathlib import Path
values = yaml.safe_load(Path("${ROOT_DIR}/values.yaml").read_text()) or {}
print("1" if (values.get("observability") or {}).get("enabled", True) else "0")
PY
)" == "1" ]]
}

CILIUM_VER="$(chart_version cilium)"
FALCO_VER="$(chart_version falco)"
TETRAGON_VER="$(chart_version tetragon)"
KYVERNO_VER="$(chart_version kyverno)"

"${SCRIPT_DIR}/render-helm-values.sh"

cd "$ROOT_DIR"
helm dependency build .

helm_wait=(--wait --timeout "$HELM_WAIT_TIMEOUT")
total_steps=6
if observability_enabled; then
  total_steps=10
  KPS_VER="$(chart_version kube-prometheus-stack)"
  LOKI_VER="$(chart_version loki)"
  PROMTAIL_VER="$(chart_version promtail)"
fi

echo ">>> [1/${total_steps}] Cilium (CNI) → kube-system"
helm upgrade --install cilium "${ROOT_DIR}/charts/cilium-${CILIUM_VER}.tgz" \
  --namespace kube-system \
  --create-namespace \
  -f "${GENERATED_DIR}/cilium-values.yaml" \
  "${helm_wait[@]}" \
  "$@"

echo ">>> Waiting for nodes after Cilium..."
kubectl wait --for=condition=Ready nodes --all --timeout=600s

echo ">>> [2/${total_steps}] Kyverno → kyverno"
helm upgrade --install kyverno "${ROOT_DIR}/charts/kyverno-${KYVERNO_VER}.tgz" \
  --namespace kyverno \
  --create-namespace \
  -f "${GENERATED_DIR}/kyverno-values.yaml" \
  "${helm_wait[@]}" \
  "$@"

if observability_enabled; then
  echo ">>> [3/${total_steps}] Loki → ${MONITORING_NS}"
  helm upgrade --install loki "${ROOT_DIR}/charts/loki-${LOKI_VER}.tgz" \
    --namespace "$MONITORING_NS" \
    --create-namespace \
    -f "${GENERATED_DIR}/loki-values.yaml" \
    "${helm_wait[@]}" \
    "$@"

  echo ">>> [4/${total_steps}] Promtail → ${MONITORING_NS}"
  helm upgrade --install promtail "${ROOT_DIR}/charts/promtail-${PROMTAIL_VER}.tgz" \
    --namespace "$MONITORING_NS" \
    -f "${GENERATED_DIR}/promtail-values.yaml" \
    "${helm_wait[@]}" \
    "$@"

  echo ">>> [5/${total_steps}] kube-prometheus-stack → ${MONITORING_NS}"
  helm upgrade --install "$KPS_RELEASE" "${ROOT_DIR}/charts/kube-prometheus-stack-${KPS_VER}.tgz" \
    --namespace "$MONITORING_NS" \
    -f "${GENERATED_DIR}/kube-prometheus-stack-values.yaml" \
    "${helm_wait[@]}" \
    "$@"
fi

falco_step=3
if observability_enabled; then
  falco_step=6
fi

echo ">>> [${falco_step}/${total_steps}] Falco → falco"
helm upgrade --install falco "${ROOT_DIR}/charts/falco-${FALCO_VER}.tgz" \
  --namespace falco \
  --create-namespace \
  -f "${GENERATED_DIR}/falco-values.yaml" \
  "${helm_wait[@]}" \
  "$@"

tetragon_step=$((falco_step + 1))
echo ">>> [${tetragon_step}/${total_steps}] Tetragon → kube-system"
helm upgrade --install tetragon "${ROOT_DIR}/charts/tetragon-${TETRAGON_VER}.tgz" \
  --namespace kube-system \
  -f "${GENERATED_DIR}/tetragon-values.yaml" \
  --set crds.installMethod=operator \
  "${helm_wait[@]}" \
  "$@"

soar_step=$((tetragon_step + 1))
echo ">>> [${soar_step}/${total_steps}] k8s-soar extras (SOAR responder) → ${NAMESPACE}"
helm upgrade --install "$RELEASE" "${ROOT_DIR}" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  -f "${GENERATED_DIR}/k8s-soar-values.yaml" \
  "${helm_wait[@]}" \
  "$@"

policies_step=$((soar_step + 1))
echo ">>> [${policies_step}/${total_steps}] Policies and security-lab (kubectl)"
"${SCRIPT_DIR}/wait-for-policy-crds.sh"
"${SCRIPT_DIR}/apply-policies-lab.sh"

if observability_enabled; then
  echo ">>> [${total_steps}/${total_steps}] Reconcile Falco metrics/Loki wiring"
  helm upgrade falco "${ROOT_DIR}/charts/falco-${FALCO_VER}.tgz" \
    --namespace falco \
    -f "${GENERATED_DIR}/falco-values.yaml" \
    "${helm_wait[@]}" \
    "$@"
fi

echo ">>> k8s-soar installed (split Helm releases + policies + lab)"
if observability_enabled; then
  echo ">>> Grafana: ./scripts/port-forward-grafana.sh  (admin / k8s-soar)"
fi
if [[ -n "${KUBECONFIG:-}" ]] || [[ -f "${HOME}/.kube/config" ]]; then
  "${SCRIPT_DIR}/verify-stack.sh" || true
fi
