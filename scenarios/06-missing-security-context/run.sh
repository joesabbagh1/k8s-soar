#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="06"
scenario_require_namespace
scenario_cleanup "$SCENARIO_ID"
kubectl delete pod scenario-06-insecure -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s 2>/dev/null || true

kubectl apply -f - <<EOF || true
apiVersion: v1
kind: Pod
metadata:
  name: scenario-06-insecure
  namespace: ${SCENARIO_NS}
  labels:
    ${SCENARIO_LABEL_KEY}: "${SCENARIO_ID}"
    scenario-target: "true"
spec:
  containers:
    - name: app
      image: nginx:latest
      command: ["sleep", "3600"]
EOF
echo ">>> Admission result:"
if kubectl wait -n "$SCENARIO_NS" --for=condition=Ready pod/scenario-06-insecure --timeout=90s >/dev/null 2>&1; then
  echo "Pod is running. Waiting for the Falco case (:latest image)."
  scenario_expect_case scenario-06-insecure "K8sSoar Latest Tag Image Started"
  scenario_review scenario-06-insecure
else
  echo "Admission blocked the pod before it ran, so Falco has no process to alert on."
  kubectl get pod scenario-06-insecure -n "$SCENARIO_NS" 2>&1 || true
fi
echo ">>> Kyverno PolicyReports (audit):"
kubectl get policyreport -A 2>/dev/null | grep -i "$SCENARIO_NS" || echo "    (none yet — background scan may take a minute)"
