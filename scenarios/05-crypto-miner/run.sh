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
kubectl run "$SCENARIO_POD" -n "$SCENARIO_NS" --rm -i --restart=Never \
  --labels="${SCENARIO_LABEL_KEY}=${SCENARIO_ID},scenario-target=true" \
  --image=debian:bookworm-slim \
  -- sh -c 'cp "$(command -v sleep)" /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig 5'

echo ">>> Waiting for Falco..."
sleep 8
"${ROOT}/scripts/lab/capture-scenario-evidence.sh" 3m 'K8sSoar Crypto Miner Process|Crypto miner|scenario-05'
