# Scenario 01 — Shell in Victim Container

**MITRE:** T1059 — Command and Script Interpreter

## Attack

Spawn an interactive shell inside `security-lab`. The run script verifies `kubectl exec`
into the victim pod (Tetragon must not block), then starts a one-shot shell pod so Falco
reliably sees `spawned_process`.

## Run

```bash
./run.sh
# or
./scripts/capture-scenario-evidence.sh 3m 'K8sSoar Shell In Victim Container'
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Shell In Victim Container` |
| falcosidekick | Webhook POST success (no `422 missing pod identity`) |
| SOAR responder | `quarantined pod security-lab/...` in logs; pod label `security.quarantine=true` |
| Kyverno | — |
| Tetragon | process exec event in security-lab |

## Capture

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco --since=2m | grep -i shell
```
