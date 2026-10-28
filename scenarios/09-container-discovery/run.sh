#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="09"

echo "Deploying Scenario 09 - Container and Resource Discovery..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: scenario-09-discovery
  namespace: ${SCENARIO_NS}
  labels:
    ${SCENARIO_LABEL_KEY}: "${SCENARIO_ID}"
    scenario-target: "true"
spec:
  restartPolicy: Never
  containers:
  - name: attacker
    image: busybox:1.36
    command:
    - sh
    - -c
    - |
      echo "========== MITRE ATT&CK T1613 =========="
      echo

        echo "[1] Hostname"
        hostname

        echo
        echo "[2] Cgroup (container identity)"
        cat /proc/1/cgroup

        echo
        echo "[3] Mount table"
        cat /proc/self/mountinfo

        echo
        echo "[4] Environment Variables"
        env

        echo
        echo "[5] Network Interfaces"
        ip addr || true

        echo
        echo "[6] Routing Table"
        ip route || true

        echo
        echo "[7] DNS Configuration"
        cat /etc/resolv.conf

        echo
        echo "Discovery completed."

        sleep 3600
EOF

echo
echo "Waiting for Pod..."

kubectl wait \
  --for=condition=Ready \
  pod/scenario-09-discovery \
  -n "$SCENARIO_NS" \
  --timeout=90s || true

echo
kubectl get pod scenario-09-discovery -n "$SCENARIO_NS"

echo
echo "View Results:"
echo "kubectl logs -n $SCENARIO_NS scenario-09-discovery"

echo
echo "Open Shell:"
echo "kubectl exec -it -n $SCENARIO_NS scenario-09-discovery -- sh"

scenario_expect_case scenario-09-discovery "K8sSoar Container Discovery"