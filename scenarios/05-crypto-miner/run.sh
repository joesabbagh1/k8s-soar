#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="05"
SCENARIO_POD="scenario-05-miner"

scenario_cleanup "$SCENARIO_ID"

echo ">>> Spawn miner-like process in ${SCENARIO_NS} (scenario ${SCENARIO_ID})..."
kubectl delete pod "$SCENARIO_POD" -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s
kubectl run "$SCENARIO_POD" -n "$SCENARIO_NS" --restart=Never \
  --labels="${SCENARIO_LABEL_KEY}=${SCENARIO_ID},scenario-target=true" \
  --image=debian:bookworm-slim --command -- \
  sh -c 'cp "$(command -v sleep)" /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig 3600'
kubectl wait -n "$SCENARIO_NS" --for=condition=Ready "pod/${SCENARIO_POD}" --timeout=120s
scenario_expect_case "$SCENARIO_POD" "K8sSoar Crypto Miner Execution"
scenario_expect_quarantine "$SCENARIO_POD"
scenario_review "$SCENARIO_POD"
