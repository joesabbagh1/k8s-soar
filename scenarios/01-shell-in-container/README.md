# Scenario 01 — Shell in Container

**MITRE:** T1059 — Command and Script Interpreter

## Attack

After compromising a container, an adversary spawns an interactive shell to run commands, explore the filesystem, and prepare follow-on actions. Shell execution inside a production namespace is a common post-exploitation step and a strong signal of hands-on-keyboard activity.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | An interactive shell (`sh`) is spawned inside a container running in the **`security-lab`** namespace — simulating post-exploitation command execution. |
| 2. **Detection** | Falco | Rule `K8sSoar Shell In Victim Container` fires on `spawned_process` in `security-lab`. |
| 3. **Triage** | falcosidekick | Alert is forwarded as JSON to the in-cluster webhook (priority ≥ Warning). |
| 4. **Response** | SOAR responder | Webhook handler labels the pod `security.quarantine=true`. |
| 5. **Containment** | Cilium / NetworkPolicy | Quarantine policy denies ingress and egress for labeled pods. |

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Shell In Victim Container` with `proc.name=sh` |
| falcosidekick | Webhook POST success (HTTP 200) |
| SOAR responder | Log line `quarantined pod security-lab/scenario-01-shell` |
| Containment | `kubectl get pod -n security-lab scenario-01-shell -o jsonpath='{.metadata.labels.security\.quarantine}'` → `true` |

## Capture

```bash
../../scripts/capture-scenario-evidence.sh 3m 'K8sSoar Shell In Victim Container'
kubectl get pod -n security-lab -l security.quarantine=true
```
