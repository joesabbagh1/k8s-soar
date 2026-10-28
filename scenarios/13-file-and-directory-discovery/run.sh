#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="13"

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: scenario-13-file-discovery
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
        echo "MITRE ATT&CK T1083 - File and Directory Discovery"

        echo
        echo "Root Directory"
        ls /

        echo
        echo "/etc Directory"
        ls /etc | head -20

        echo
        echo "/var Directory"
        ls /var

        echo
        echo "/tmp Directory"
        ls /tmp

        echo
        echo "Discovery completed."

        sleep 3600
EOF

kubectl wait \
  --for=condition=Ready \
  pod/scenario-13-file-discovery \
  -n "$SCENARIO_NS" \
  --timeout=90s || true

echo
echo "Scenario 13 deployed."

kubectl get pod scenario-13-file-discovery -n "$SCENARIO_NS"

echo
echo "View logs:"
echo "kubectl logs -n $SCENARIO_NS scenario-13-file-discovery"

echo
echo "Open shell:"
echo "kubectl exec -it -n $SCENARIO_NS scenario-13-file-discovery -- sh"

scenario_expect_case scenario-13-file-discovery "K8sSoar File and Directory Discovery"