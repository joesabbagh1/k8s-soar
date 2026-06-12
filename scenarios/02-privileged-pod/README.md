# Scenario 02 — Privileged Pod / hostPath

**MITRE:** T1611 — Escape to Host

## Attack

Attempt to deploy a privileged pod with hostPath mount in security-lab.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kyverno | PolicyReport audit for `k8s-soar-disallow-privileged` / `k8s-soar-disallow-host-path` |
| Falco | Alert if pod somehow runs |
| Tetragon | — |

## Capture

```bash
kubectl get policyreport -A
kubectl describe cpol k8s-soar-disallow-privileged
```
