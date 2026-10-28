#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="10"

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: scenario-10-serviceaccount
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
        echo "MITRE ATT&CK T1528 - Steal Application Access Token"

        echo
        echo "[1] Namespace"
        cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

        echo
        echo "[2] ServiceAccount Files"
        ls -l /var/run/secrets/kubernetes.io/serviceaccount

        echo
        echo "[3] Token Status"
        if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
          echo "ServiceAccount token is mounted."
        else
          echo "ServiceAccount token not found."
        fi

        echo
        echo "[4] CA Certificate"
        if [ -f /var/run/secrets/kubernetes.io/serviceaccount/ca.crt ]; then
          echo "CA certificate is available."
        else
          echo "CA certificate not found."
        fi

        echo
        echo "[5] Kubernetes API"
        echo "Host: \$KUBERNETES_SERVICE_HOST"
        echo "Port: \$KUBERNETES_SERVICE_PORT"

        sleep 3600
EOF

kubectl wait \
  --for=condition=Ready \
  pod/scenario-10-serviceaccount \
  -n "$SCENARIO_NS" \
  --timeout=90s || true

echo "Scenario 10 deployed."

kubectl get pod scenario-10-serviceaccount -n "$SCENARIO_NS"

echo
echo "Logs:"
echo "kubectl logs -n $SCENARIO_NS scenario-10-serviceaccount"

echo
echo "Shell:"
echo "kubectl exec -it -n $SCENARIO_NS scenario-10-serviceaccount -- sh"