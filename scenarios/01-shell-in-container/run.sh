#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')
echo ">>> Verify kubectl exec into ${POD} (Tetragon must not block)..."

if kubectl exec -n security-lab "$POD" --request-timeout=30s -- sh -c 'id'; then
  echo ">>> Exec OK"
else
  echo ">>> Exec failed — check Tetragon TracingPolicy k8s-soar-block-sensitive-writes"
  exit 1
fi

echo ">>> Spawn shell in security-lab for Falco (spawned_process)..."
SCENARIO_POD="scenario-01-shell"
# Left over if a prior --rm run was interrupted (Ctrl+C, network blip, etc.).
kubectl delete pod "$SCENARIO_POD" -n security-lab --ignore-not-found --wait=true --timeout=60s
kubectl run "$SCENARIO_POD" -n security-lab --rm -i --restart=Never \
  --labels="scenario-target=true" \
  --image=busybox:1.36 \
  -- sh -c 'echo k8s-soar-scenario-01; id; sleep 3'

echo ">>> Waiting for Falco..."
sleep 12
"${ROOT}/scripts/capture-scenario-evidence.sh" 3m 'K8sSoar Shell In Victim Container|Shell spawned|scenario-01'
