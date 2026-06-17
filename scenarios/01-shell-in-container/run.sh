#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/scenario-lib.sh
source "${ROOT}/scripts/scenario-lib.sh"

SCENARIO_ID="01"
SCENARIO_POD="scenario-01-shell"

scenario_cleanup "$SCENARIO_ID"

echo ">>> Spawn shell in security-lab (scenario ${SCENARIO_ID})..."
kubectl delete pod "$SCENARIO_POD" -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s
kubectl run "$SCENARIO_POD" -n "$SCENARIO_NS" --rm -i --restart=Never \
  --labels="${SCENARIO_LABEL_KEY}=${SCENARIO_ID},scenario-target=true" \
  --image=busybox:1.36 \
  -- sh -c 'echo k8s-soar-scenario-01; id; sleep 3'

echo ">>> Waiting for Falco..."
sleep 12
"${ROOT}/scripts/capture-scenario-evidence.sh" 3m 'K8sSoar Shell In Victim Container|Shell spawned|scenario-01'
