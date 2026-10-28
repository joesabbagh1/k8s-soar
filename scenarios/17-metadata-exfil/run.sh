#!/usr/bin/env bash
# Query the cloud metadata address from inside a pod. The connect is the
# signal; on bare metal nothing answers and the rule still matches.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="17"
POD="scenario-17-metadata"
RULE="K8sSoar Cloud Metadata Access"

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
      command:
        - sh
        - -c
        - wget -T 3 -O /dev/null http://169.254.169.254/latest/meta-data/ || true; sleep 3600
EOF
kubectl wait -n "$SCENARIO_NS" --for=condition=Ready "pod/${POD}" --timeout=90s
scenario_expect_case "$POD" "$RULE"
scenario_review "$POD"
