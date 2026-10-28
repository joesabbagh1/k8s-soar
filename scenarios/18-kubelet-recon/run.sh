#!/usr/bin/env bash
# TCP connect to the node's kubelet port from inside a pod.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="18"
POD="scenario-18-kubelet"
RULE="K8sSoar Kubelet Probe"

scenario_require_namespace
kubectl delete pod "$POD" -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true

kubectl apply -n "$SCENARIO_NS" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  labels:
    ${SCENARIO_LABEL_KEY}: "${SCENARIO_ID}"
    scenario-target: "true"
spec:
  restartPolicy: Never
  containers:
    - name: attacker
      image: busybox:1.36
      env:
        - name: NODE_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
      command:
        - sh
        - -c
        - wget -T 3 -O /dev/null "http://\${NODE_IP}:10250/pods" || true; sleep 3600
EOF
kubectl wait -n "$SCENARIO_NS" --for=condition=Ready "pod/${POD}" --timeout=90s
scenario_expect_case "$POD" "$RULE"
scenario_review "$POD"
