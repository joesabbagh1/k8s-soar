#!/usr/bin/env bash
set -euo pipefail
POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')
echo ">>> Exec into ${POD} (security-lab)..."
kubectl exec -n security-lab "$POD" --request-timeout=30s -- sh -c 'echo k8s-soar-scenario-01; id'
echo ">>> Done. Check Falco: kubectl logs -n falco -l app.kubernetes.io/name=falco --since=2m | grep -i k8s-soar"
