# Scenario 05 — Crypto Miner Process (simulated)

**MITRE:** T1496 — Resource Hijacking

## Attack

An adversary executes a process whose name matches a known cryptocurrency miner (e.g. `xmrig`) inside a container in `security-lab`, simulating resource hijacking and unauthorized compute consumption.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Crypto Miner Process` |
| SOAR | Optional quarantine label if falcosidekick + responder enabled |
