#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# busybox uses argv[0] as applet name — symlinks/exec -a named xmrig fail inside busybox.
# Copy coreutils sleep to /tmp/xmrig in a one-shot pod so Falco sees proc.name=xmrig.
SCENARIO_POD="scenario-05-miner"
echo ">>> Spawn miner-like process in security-lab (${SCENARIO_POD})..."
kubectl delete pod "$SCENARIO_POD" -n security-lab --ignore-not-found --wait=true --timeout=60s
kubectl run "$SCENARIO_POD" -n security-lab --rm -i --restart=Never \
  --labels="scenario-target=true" \
  --image=debian:bookworm-slim \
  -- sh -c 'cp "$(command -v sleep)" /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig 5'

echo ">>> Waiting for Falco..."
sleep 8
"${ROOT}/scripts/capture-scenario-evidence.sh" 3m 'K8sSoar Crypto Miner Process|Crypto miner|scenario-05'
