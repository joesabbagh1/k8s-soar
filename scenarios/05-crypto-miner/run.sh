#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')

echo ">>> Simulate miner-like process in ${POD}..."
kubectl exec -n security-lab "$POD" -- sh -c 'ln -sf /bin/sleep /tmp/xmrig; /tmp/xmrig 1'

echo ">>> Waiting for Falco..."
sleep 8
"${ROOT}/scripts/capture-scenario-evidence.sh" 3m 'K8sSoar Crypto Miner Process|Crypto miner|scenario-05'
