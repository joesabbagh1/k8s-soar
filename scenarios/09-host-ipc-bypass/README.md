# Scenario 09 — Host IPC Namespace Sharing Breakout

**MITRE:** T1611 — Escape to Host

## Attack

Attempt to deploy an unisolated container that requests `hostIPC: true`. This breaks standard namespace boundaries, mounting the host operating system's shared memory segments, semaphores, and message queues straight into the container. The run script verifies that the Admission Controllers actively block execution before scheduling completes.

## Run

```bash
./run.sh
kubectl get events -n security-lab --sort-by='.metadata.creationTimestamp' | grep -i forbidden
cat << 'EOF' > run.sh
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT}/scripts/scenario-lib.sh"

SCENARIO_ID="09"
SCENARIO_NS="security-lab"

echo ">>> Simulating Scenario 09: Host IPC Breakout Attempt..."

kubectl apply -f - <<EOF || true
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
