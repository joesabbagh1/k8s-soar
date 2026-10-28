#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="11"

echo "Deploying Scenario 11 - Advanced Attack Chain..."

kubectl apply -f "${ROOT}/scenarios/11-attack-chain/01-dvwa.yaml"

echo
echo "Waiting for DVWA Pod..."

kubectl wait \
  --for=condition=Ready \
  pod \
  -l app=dvwa \
  -n "$SCENARIO_NS" \
  --timeout=180s

POD=$(kubectl get pod -n "$SCENARIO_NS" -l app=dvwa -o jsonpath='{.items[0].metadata.name}')
echo ">>> Stage 2: read the service-account token in ${POD}"
kubectl exec -n "$SCENARIO_NS" "$POD" -- cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null
scenario_expect_case "$POD" "K8sSoar Service Account Token Read By Shell Tool"
scenario_expect_quarantine "$POD"

echo
kubectl get pod -l app=dvwa -n "$SCENARIO_NS"

echo
echo "=========================================================="
echo "Scenario 11 Deployed Successfully"
echo "=========================================================="
echo "This is a multi-stage attack chain."
echo 
echo "To begin Stage 1 (Initial Foothold), open a shell in the victim pod:"
echo "  kubectl exec -it -n $SCENARIO_NS deploy/dvwa -- sh"
echo
echo "Inside the pod, you can execute the subsequent stages:"
echo "  - Stage 2: cat /var/run/secrets/kubernetes.io/serviceaccount/token"
echo "  - Stage 3: Attempt to list pods via API with the stolen token"
echo "  - Stage 4: Open a reverse shell"
echo "  - Stage 5: Run check.php / escalate.php (included in this dir)"
echo "=========================================================="
scenario_review "$POD"
