#!/usr/bin/env bash
# Read the System V IPC table from a pod that shares the node's IPC namespace.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="16"
POD="scenario-16-host-ipc"
RULE="K8sSoar Host IPC Access"

scenario_require_namespace
kubectl delete pod "$POD" -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true

kubectl apply -n "$SCENARIO_NS" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  labels:
    ${SCENARIO_LABEL_KEY}: "${SCENARIO_ID}"
    scenario-target: "true"
spec:
  hostIPC: true
  restartPolicy: Never
  containers:
    - name: attacker
      image: busybox:1.36
      command: ["sh", "-c", "cat /proc/sysvipc/shm; sleep 3600"]
EOF
kubectl wait -n "$SCENARIO_NS" --for=condition=Ready "pod/${POD}" --timeout=90s
scenario_expect_case "$POD" "$RULE"
scenario_review "$POD"
