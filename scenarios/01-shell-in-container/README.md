# Scenario 01 — Shell in Victim Container

**MITRE:** T1059 — Command and Script Interpreter

## Attack

Spawn an interactive shell in a **dedicated** pod labeled `scenario=01`. Scenarios do not share workloads — Tetragon enforce policies and SOAR quarantine only affect the scenario pod, not the baseline victim deployment.

## Run

```bash
./run.sh
# reset leftover scenario pods / quarantine labels:
../../scripts/reset-scenario-lab.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Shell In Victim Container` |
| falcosidekick | Webhook POST success (no `422 missing pod identity`) |
| SOAR responder | `quarantined pod security-lab/scenario-01-shell` in logs |
| Kyverno | — |
| Tetragon | — (not in scope for this scenario) |

## Capture

```bash
../../scripts/capture-scenario-evidence.sh 3m 'K8sSoar Shell In Victim Container'
```
