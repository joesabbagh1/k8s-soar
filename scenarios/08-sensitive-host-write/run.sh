#!/usr/bin/env bash
set -euo pipefail
POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n security-lab "$POD" -- sh -c 'echo probe >> /etc/shadow' 2>/dev/null || echo "write denied (expected)"
