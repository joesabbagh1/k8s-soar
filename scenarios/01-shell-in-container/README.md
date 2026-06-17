# Scenario 01 — Shell in Victim Container

**MITRE:** T1059 — Command and Script Interpreter

## Attack

An adversary with access to a running container spawns an interactive shell (`sh`) inside a workload in `security-lab`. This represents post-exploitation activity: establishing a command interface to explore the environment, run tools, or prepare further actions.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Shell In Victim Container` |
| falcosidekick | Webhook POST success (no `422 missing pod identity`) |
| SOAR responder | `quarantined pod security-lab/scenario-01-shell` in logs |
| Kyverno | — |
| Tetragon | — |

## Capture

```bash
../../scripts/capture-scenario-evidence.sh 3m 'K8sSoar Shell In Victim Container'
```
