#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')
echo ">>> Exec into ${POD} (security-lab)..."

if kubectl exec -n security-lab "$POD" --request-timeout=30s -- sh -c 'echo k8s-soar-scenario-01; id'; then
  echo ">>> Exec OK"
else
  echo ">>> Exec failed — spawning one-shot shell pod in security-lab..."
  kubectl run scenario-01-shell -n security-lab --rm -i --restart=Never \
    --labels="scenario-target=true" \
    --image=busybox:1.36 \
    -- sh -c 'echo k8s-soar-scenario-01; id'
fi

echo ">>> Waiting for Falco..."
sleep 8
"${ROOT}/scripts/capture-scenario-evidence.sh" 3m 'k8s-soar|Shell spawned|scenario-01'
