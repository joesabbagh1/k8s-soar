#!/usr/bin/env bash
set -euo pipefail

POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')
echo ">>> Exec into ${POD} (security-lab)..."

if kubectl exec -n security-lab "$POD" --request-timeout=30s -- sh -c 'echo k8s-soar-scenario-01; id'; then
  echo ">>> Done. Check Falco:"
  echo "    kubectl logs -n falco -l app.kubernetes.io/name=falco --since=2m | grep -i k8s-soar"
  exit 0
fi

echo ">>> Exec failed — spawning one-shot shell pod in security-lab (same detection surface)..."
kubectl run scenario-01-shell -n security-lab --rm -i --restart=Never \
  --labels="scenario-target=true" \
  --image=busybox:1.36 \
  -- sh -c 'echo k8s-soar-scenario-01; id'
echo ">>> Check Falco:"
echo "    kubectl logs -n falco -l app.kubernetes.io/name=falco --since=2m | grep -i k8s-soar"
