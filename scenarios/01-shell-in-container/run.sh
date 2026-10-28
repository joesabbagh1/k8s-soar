#!/usr/bin/env bash
# A TTY-attached shell. K8sSoar Terminal Shell In Container requires proc.tty != 0,
# so the pod spec allocates a terminal; `kubectl run -i` without a TTY does not match.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="01"
SCENARIO_POD="scenario-01-shell"
RULE="K8sSoar Terminal Shell In Container"

scenario_require_namespace
scenario_cleanup "$SCENARIO_ID"
kubectl delete pod "$SCENARIO_POD" -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s >/dev/null

kubectl apply -n "$SCENARIO_NS" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${SCENARIO_POD}
  labels:
    ${SCENARIO_LABEL_KEY}: "${SCENARIO_ID}"
    scenario-target: "true"
spec:
  restartPolicy: Never
  containers:
    - name: shell
      image: busybox:1.36
      stdin: true
      tty: true
      command: ["sh", "-c", "id; sleep 3600"]
EOF
kubectl wait -n "$SCENARIO_NS" --for=condition=Ready "pod/${SCENARIO_POD}" --timeout=90s
scenario_expect_case "$SCENARIO_POD" "$RULE"
echo "Review it: make cases"
