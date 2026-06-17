#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/scenario-lib.sh
source "${ROOT}/scripts/scenario-lib.sh"

SCENARIO_ID="06"
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
echo ">>> Pod created (Kyverno audit — not blocked in Audit mode):"
kubectl get pod scenario-06-insecure -n "$SCENARIO_NS" 2>&1 || true
echo ">>> Kyverno PolicyReports (audit):"
kubectl get policyreport -A 2>/dev/null | grep -i security-lab || echo "    (none yet — background scan may take a minute)"
