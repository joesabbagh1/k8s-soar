#!/usr/bin/env bash
set -euo pipefail
kubectl apply -f - <<EOF || true
apiVersion: v1
kind: Pod
metadata:
  name: scenario-06-insecure
  namespace: security-lab
spec:
  containers:
    - name: app
      image: nginx:latest
      command: ["sleep", "3600"]
EOF
