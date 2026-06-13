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
echo ">>> Admission result (PSA baseline blocks privileged + hostPath):"
kubectl get pod scenario-02-privileged -n security-lab 2>&1 || true
echo ">>> Kyverno PolicyReports (audit):"
kubectl get policyreport -A 2>/dev/null | grep -i security-lab || echo "    (none yet — background scan may take a minute)"
