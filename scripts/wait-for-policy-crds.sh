#!/usr/bin/env bash
# Wait until CRDs required by bundled policies/lab manifests are established.
set -euo pipefail

TIMEOUT="${K8S_SOAR_CRD_WAIT_TIMEOUT:-600}"

CRDS=(
  clusterpolicies.kyverno.io
  ciliumnetworkpolicies.cilium.io
  tracingpolicies.cilium.io
)

for crd in "${CRDS[@]}"; do
  echo ">>> Waiting for CRD ${crd} (timeout ${TIMEOUT}s)..."
  kubectl wait --for=condition=Established "crd/${crd}" --timeout="${TIMEOUT}s"
done

echo ">>> Policy CRDs are ready."
