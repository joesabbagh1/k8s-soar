#!/usr/bin/env bash
set -euo pipefail
POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n security-lab "$POD" -- sh -c 'ln -sf /bin/sleep /tmp/xmrig; /tmp/xmrig 1'
