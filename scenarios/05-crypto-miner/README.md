# Scenario 05 — Crypto Miner Process (simulated)

**MITRE:** T1496 — Resource Hijacking

## Attack

Run a process named like a miner inside the victim pod.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Crypto Miner Process` |
| SOAR | Optional quarantine label if falcosidekick + responder enabled |
