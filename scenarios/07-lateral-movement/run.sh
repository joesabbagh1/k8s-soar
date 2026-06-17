#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/scenario-lib.sh
source "${ROOT}/scripts/scenario-lib.sh"

SCENARIO_ID="07"
ATTACKER="scenario-07-attacker"
PEER="scenario-07-peer"

scenario_cleanup "$SCENARIO_ID"
kubectl delete pod "$ATTACKER" "$PEER" -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s 2>/dev/null || true

kubectl run "$PEER" -n "$SCENARIO_NS" --restart=Never \
  --labels="${SCENARIO_LABEL_KEY}=${SCENARIO_ID},scenario-role=peer" \
  --image=busybox:1.36 --command -- sleep 3600
kubectl run "$ATTACKER" -n "$SCENARIO_NS" --restart=Never \
  --labels="${SCENARIO_LABEL_KEY}=${SCENARIO_ID},scenario-role=attacker" \
  --image=busybox:1.36 --command -- sleep 3600
kubectl wait -n "$SCENARIO_NS" --for=condition=Ready "pod/${PEER}" "pod/${ATTACKER}" --timeout=90s

PEER_IP=$(kubectl get pod -n "$SCENARIO_NS" "$PEER" -o jsonpath='{.status.podIP}')
echo ">>> Pod-to-pod probe from ${ATTACKER} to ${PEER} (${PEER_IP})..."
kubectl exec -n "$SCENARIO_NS" "$ATTACKER" -- sh -c "wget -T 2 -qO- http://${PEER_IP} || echo blocked"

scenario_cleanup "$SCENARIO_ID"
