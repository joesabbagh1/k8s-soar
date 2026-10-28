#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="14"

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: scenario-14-process-discovery
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
        echo "MITRE ATT&CK T1057 - Process Discovery"

        echo
        echo "Current User"
        id

        echo
        echo "Running Processes"
        ps

        echo
        echo "Current Shell"
        echo "$SHELL"

        echo
        echo "Process discovery completed."

        sleep 3600
EOF

kubectl wait \
  --for=condition=Ready \
  pod/scenario-14-process-discovery \
  -n "$SCENARIO_NS" \
  --timeout=90s || true

echo
echo "Scenario 14 deployed."

kubectl get pod scenario-14-process-discovery -n "$SCENARIO_NS"

echo
echo "View logs:"
echo "kubectl logs -n $SCENARIO_NS scenario-14-process-discovery"

echo
echo "Open shell:"
echo "kubectl exec -it -n $SCENARIO_NS scenario-14-process-discovery -- sh"

scenario_expect_case scenario-14-process-discovery "K8sSoar Process Discovery"