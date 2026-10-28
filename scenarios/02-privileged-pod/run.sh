#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="02"
scenario_require_namespace
scenario_cleanup "$SCENARIO_ID"
kubectl delete pod scenario-02-privileged -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s 2>/dev/null || true

kubectl apply -f - <<EOF || true
apiVersion: v1
kind: Pod
metadata:
  name: scenario-02-privileged
  namespace: ${SCENARIO_NS}
  labels:
    ${SCENARIO_LABEL_KEY}: "${SCENARIO_ID}"
    scenario-target: "true"
spec:
  containers:
    - name: bad
      image: busybox:1.36
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /
        type: Directory
EOF
echo ">>> Admission result:"
if kubectl wait -n "$SCENARIO_NS" --for=condition=Ready pod/scenario-02-privileged --timeout=60s >/dev/null 2>&1; then
  echo "Pod is running (admission allowed it). Waiting for the Falco case."
  scenario_expect_case scenario-02-privileged "K8sSoar Privileged Container Started"
  scenario_expect_quarantine scenario-02-privileged
  scenario_review scenario-02-privileged
else
  echo "Admission blocked the privileged pod before it ran, so Falco has no process to alert on."
  kubectl get pod scenario-02-privileged -n "$SCENARIO_NS" 2>&1 || true
fi
echo ">>> Kyverno PolicyReports (audit):"
kubectl get policyreport -A 2>/dev/null | grep -i "$SCENARIO_NS" || echo "    (none yet — background scan may take a minute)"
