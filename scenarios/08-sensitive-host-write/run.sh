#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/scenario-lib.sh
source "${ROOT}/scripts/scenario-lib.sh"

SCENARIO_ID="08"
POD="scenario-08-writer"

scenario_cleanup "$SCENARIO_ID"
scenario_ensure_pod "$SCENARIO_ID" "$POD" busybox:1.36 --command -- sleep 3600 >/dev/null

echo ">>> Attempt sensitive write from ${POD} (Tetragon scoped to scenario ${SCENARIO_ID})..."
kubectl exec -n "$SCENARIO_NS" "$POD" -- sh -c 'echo probe >> /etc/shadow' 2>/dev/null || echo "write denied (expected)"

scenario_cleanup "$SCENARIO_ID"
