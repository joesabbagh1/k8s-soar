#!/usr/bin/env bash
set -euo pipefail
kubectl apply -f - <<EOF || true
apiVersion: v1
kind: Pod
metadata:
  name: scenario-02-privileged
  namespace: security-lab
spec:
  containers:
    - name: bad
      image: busybox:1.36
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /
        type: Directory
EOF
echo "Check Kyverno PolicyReports — pod may be blocked when policies are Enforce mode."
