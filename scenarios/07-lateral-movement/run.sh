#!/usr/bin/env bash
set -euo pipefail
POD=$(kubectl get pod -n security-lab -l app=victim -o jsonpath='{.items[0].metadata.name}')
kubectl run -n security-lab scenario-07-peer --image=busybox:1.36 --restart=Never --command -- sleep 3600
kubectl wait -n security-lab --for=condition=Ready pod/scenario-07-peer --timeout=60s
PEER_IP=$(kubectl get pod -n security-lab scenario-07-peer -o jsonpath='{.status.podIP}')
kubectl exec -n security-lab "$POD" -- sh -c "wget -T 2 -qO- http://${PEER_IP} || echo blocked"
