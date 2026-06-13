#!/usr/bin/env bash
# Wait until CRDs required by bundled policies/lab manifests are established.
set -euo pipefail

TIMEOUT="${K8S_SOAR_CRD_WAIT_TIMEOUT:-600}"

wait_crd() {
  local crd=$1
  echo ">>> Waiting for CRD ${crd} (timeout ${TIMEOUT}s)..."
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

echo ">>> Policy CRDs are ready."
