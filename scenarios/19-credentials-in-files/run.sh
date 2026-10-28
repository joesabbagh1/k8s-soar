#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="11"

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: scenario-11-credentials
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
        echo "MITRE ATT&CK T1552.001 - Credentials in Files"

        echo
        echo "Checking common credential locations..."

        for file in \
          /etc/shadow \
          /etc/passwd \
          /root/.ssh/id_rsa \
          /root/.kube/config \
          /app/.env \
          /config/config.yaml
        do
          echo "---- $file"
          cat "$file" 2>/dev/null | head -c 80 || echo "[unreadable] $file"
          echo
        done

        echo
        echo "Searching for configuration files..."

        find /etc -maxdepth 2 \( -name "*.conf" -o -name "*.yaml" -o -name "*.json" \) 2>/dev/null | head -10

        echo
        echo "Credential discovery finished."

        sleep 3600
EOF

kubectl wait \
  --for=condition=Ready \
  pod/scenario-11-credentials \
  -n "$SCENARIO_NS" \
  --timeout=90s || true

echo
echo "Scenario 11 deployed successfully."

kubectl get pod scenario-11-credentials -n "$SCENARIO_NS"

echo
echo "View logs:"
echo "kubectl logs -n $SCENARIO_NS scenario-11-credentials"

echo
echo "Open shell:"
echo "kubectl exec -it -n $SCENARIO_NS scenario-11-credentials -- sh"

scenario_expect_case scenario-11-credentials "K8sSoar Sensitive File Read"
scenario_expect_quarantine scenario-11-credentials
scenario_review scenario-11-credentials