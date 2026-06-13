# Scenario 01 — Shell in Victim Container

**MITRE:** T1059 — Command and Script Interpreter

## Attack

Spawn an interactive shell inside the victim pod (busybox lab workload).

## Run

```bash
./run.sh
sleep 5
kubectl logs -n falco -l app.kubernetes.io/name=falco --since=2m | grep -i k8s-soar
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Shell In Victim Container` or default terminal shell rule |
| Kyverno | — |
| Tetragon | process exec event in security-lab |

## Capture

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco --since=2m | grep -i shell
```
