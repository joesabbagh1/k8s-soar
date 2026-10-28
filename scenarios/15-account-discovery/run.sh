#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="15"

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: scenario-15-account-discovery
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
        echo "MITRE ATT&CK T1087 - Account Discovery"

        echo
        echo "Current User"
        whoami

        echo
        echo "User ID"
        id

        echo
        echo "Available Groups"
        groups || true

        echo
        echo "/etc/passwd"
        head -10 /etc/passwd

        echo
        echo "/etc/group"
        head -10 /etc/group

        echo
        echo "Account discovery completed."

        sleep 3600
EOF

kubectl wait \
  --for=condition=Ready \
  pod/scenario-15-account-discovery \
  -n "$SCENARIO_NS" \
  --timeout=90s || true

echo
echo "Scenario 15 deployed."

kubectl get pod scenario-15-account-discovery -n "$SCENARIO_NS"

echo
echo "View logs:"
echo "kubectl logs -n $SCENARIO_NS scenario-15-account-discovery"

echo
echo "Open shell:"
echo "kubectl exec -it -n $SCENARIO_NS scenario-15-account-discovery -- sh"

scenario_expect_case scenario-15-account-discovery "K8sSoar Account Discovery"