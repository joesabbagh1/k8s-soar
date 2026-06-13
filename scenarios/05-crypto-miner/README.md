# Scenario 05 — Crypto Miner Process (simulated)

**MITRE:** T1496 — Resource Hijacking

## Attack

Run a process with `proc.name=xmrig` inside the victim pod (`exec -a` on busybox).

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Crypto Miner Process` |
| SOAR | Optional quarantine label if falcosidekick + responder enabled |
