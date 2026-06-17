#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/scenario-lib.sh
source "${ROOT}/scripts/scenario-lib.sh"

SCENARIO_ID="02"
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
echo ">>> Admission result (PSA baseline blocks privileged + hostPath):"
kubectl get pod scenario-02-privileged -n "$SCENARIO_NS" 2>&1 || true
echo ">>> Kyverno PolicyReports (audit):"
kubectl get policyreport -A 2>/dev/null | grep -i security-lab || echo "    (none yet — background scan may take a minute)"
