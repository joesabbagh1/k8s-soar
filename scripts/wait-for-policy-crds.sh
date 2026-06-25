#!/usr/bin/env bash
# Wait until CRDs required by bundled policies/lab manifests are established.
set -euo pipefail

TIMEOUT="${K8S_SOAR_CRD_WAIT_TIMEOUT:-600}"

wait_crd() {
  local crd=$1
  echo ">>> Waiting for CRD ${crd} to appear (timeout ${TIMEOUT}s)..."
  local end=$((SECONDS + TIMEOUT))
  until kubectl get crd "${crd}" >/dev/null 2>&1; do
    if (( SECONDS >= end )); then
      echo "ERROR: CRD ${crd} never appeared" >&2
      exit 1
    fi
    sleep 5
  done
  echo ">>> Waiting for CRD ${crd} to become Established..."
  kubectl wait --for=condition=Established "crd/${crd}" --timeout="${TIMEOUT}s"
}

wait_api_resource() {
  local resource=$1
  local group=$2
  echo ">>> Waiting for API resource ${resource}.${group}..."
  local end=$((SECONDS + TIMEOUT))
  until kubectl api-resources --api-group="${group}" 2>/dev/null | awk '{print $1}' | grep -qx "${resource}"; do
    if (( SECONDS >= end )); then
      echo "ERROR: timed out waiting for ${resource}.${group}" >&2
      kubectl api-resources --api-group="${group}" 2>/dev/null || true
      exit 1
    fi
    sleep 5
  done
}

wait_crd clusterpolicies.kyverno.io
wait_crd ciliumnetworkpolicies.cilium.io
wait_crd tracingpolicies.cilium.io

wait_api_resource clusterpolicies kyverno.io
wait_api_resource ciliumnetworkpolicies cilium.io
wait_api_resource tracingpolicies cilium.io

echo ">>> Waiting for Kyverno admission controller to be ready..."
kubectl wait --for=condition=available deployment -n kyverno -l app.kubernetes.io/component=admission-controller --timeout="${TIMEOUT}s" || true
# Additional sleep to ensure endpoints are fully propagated to the apiserver
sleep 10

echo ">>> Policy CRDs are ready."
