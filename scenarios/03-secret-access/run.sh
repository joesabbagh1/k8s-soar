#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')

echo ">>> Read SA token from ${POD} (security-lab)..."
kubectl exec -n security-lab "$POD" -- sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 40; echo ...'

echo ">>> Waiting for Falco..."
sleep 8
"${ROOT}/scripts/capture-scenario-evidence.sh" 3m 'K8sSoar Sensitive Credential Access|Sensitive credential|scenario-03'
