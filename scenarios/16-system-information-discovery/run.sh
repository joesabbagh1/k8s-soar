#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="16"

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: scenario-16-system-information
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
        echo "MITRE ATT&CK T1082 - System Information Discovery"

        echo
        echo "[1] Hostname"
        hostname

        echo
        echo "[2] Operating System"
        cat /etc/os-release

        echo
        echo "[3] Kernel Information"
        uname -a

        echo
        echo "[4] CPU Architecture"
        uname -m

        echo
        echo "[5] Current User"
        id

        echo
        echo "[6] System Uptime"
        uptime || true

        echo
        echo "System information discovery completed."

        sleep 3600
EOF

kubectl wait \
  --for=condition=Ready \
  pod/scenario-16-system-information \
  -n "$SCENARIO_NS" \
  --timeout=90s || true

echo
echo "Scenario 16 deployed."

kubectl get pod scenario-16-system-information -n "$SCENARIO_NS"

echo
echo "View logs:"
echo "kubectl logs -n $SCENARIO_NS scenario-16-system-information"

echo
echo "Open shell:"
echo "kubectl exec -it -n $SCENARIO_NS scenario-16-system-information -- sh"