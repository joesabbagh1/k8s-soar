#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT}/scripts/scenario-lib.sh"

SCENARIO_ID="09"
SCENARIO_NS="security-lab"
KUBE="sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf"

echo ">>> Simulating Scenario 09: Host IPC Breakout Attempt..."

$KUBE apply -f - <<EOF_MANIFEST || true
apiVersion: v1
kind: Pod
metadata:
  name: scenario-09-ipc
  namespace: ${SCENARIO_NS}
  labels:
    scenario-target: "true"
spec:
  hostIPC: true
  containers:
  - name: memory-sniffer
    image: busybox:1.36
    command: ["sleep", "3600"]
EOF_MANIFEST

echo ">>> Checking Cluster Admission Prevention Response..."
$KUBE get pod scenario-09-ipc -n ${SCENARIO_NS} 2>&1 || true
