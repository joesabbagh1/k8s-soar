#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/scenario-lib.sh
source "${ROOT}/scripts/scenario-lib.sh"

SCENARIO_ID="03"
POD="scenario-03-token"

scenario_cleanup "$SCENARIO_ID"
scenario_ensure_pod "$SCENARIO_ID" "$POD" busybox:1.36 --command -- sleep 3600 >/dev/null

echo ">>> Read SA token from ${POD} (scenario ${SCENARIO_ID})..."
kubectl exec -n "$SCENARIO_NS" "$POD" -- sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 40; echo ...'

echo ">>> Waiting for Falco..."
sleep 8
"${ROOT}/scripts/capture-scenario-evidence.sh" 3m 'K8sSoar Sensitive Credential Access|Sensitive credential|scenario-03'

scenario_cleanup "$SCENARIO_ID"
