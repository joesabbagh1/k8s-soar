# Scenario 08 — Sensitive Host Path Write (simulated)

**MITRE:** T1611 — Escape to Host

## Attack

Attempt write to `/etc/shadow` from pod `scenario-08-writer` (`scenario=08` label). Tetragon enforcement applies **only** to that pod — not the baseline victim workload.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | File access alerts |
| Tetragon | `k8s-soar-block-sensitive-writes` action (when policy loaded) |
