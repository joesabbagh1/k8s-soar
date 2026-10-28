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
  --timeout=90s || true

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
