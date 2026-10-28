#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="08"
POD="scenario-08-writer"
RULE="K8sSoar Sensitive File Write"

scenario_require_namespace
scenario_cleanup "$SCENARIO_ID"
scenario_ensure_pod "$SCENARIO_ID" "$POD" busybox:1.36 --command -- sleep 3600 >/dev/null

echo ">>> Append to /etc/shadow from ${POD}"
kubectl exec -n "$SCENARIO_NS" "$POD" -- sh -c 'echo probe >> /etc/shadow' 2>/dev/null || true

scenario_expect_case "$POD" "$RULE"
scenario_expect_quarantine "$POD"
scenario_review "$POD"
