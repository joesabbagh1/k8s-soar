# Scenario 05 — Crypto Miner Process (simulated)

**MITRE:** T1496 — Resource Hijacking

## Attack

Spawn a process with `proc.name=xmrig` in `security-lab`. The victim pod uses busybox (multiplexed binary), so the script runs a one-shot `debian:bookworm-slim` pod that copies `sleep` to `/tmp/xmrig` and executes it — Falco matches on the process name.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Crypto Miner Process` |
| SOAR | Optional quarantine label if falcosidekick + responder enabled |
