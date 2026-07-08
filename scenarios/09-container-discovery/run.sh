#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=scripts/scenario-lib.sh
source "${ROOT}/scripts/scenario-lib.sh"

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
      echo "[2] Namespace"
      cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

      echo
      echo "[3] Service Account Files"
      ls -l /var/run/secrets/kubernetes.io/serviceaccount

      echo
      echo "[4] Environment Variables"
      env

      echo
      echo "[5] Mounted File Systems"
      mount

      echo
      echo "[6] Network Interfaces"
      ip addr

      echo
      echo "[7] Routing Table"
      ip route

      echo
      echo "[8] DNS Configuration"
      cat /etc/resolv.conf

      echo
      echo "[9] Kubernetes API"
      echo \$KUBERNETES_SERVICE_HOST
      echo \$KUBERNETES_SERVICE_PORT

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