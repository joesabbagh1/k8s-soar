# Scenario 08 — Sensitive Host Path Write (simulated)

**MITRE:** T1611 — Escape to Host

## Attack

Attempt write to sensitive path inside container filesystem.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | File access alerts |
| Tetragon | `k8s-soar-block-sensitive-writes` action (when policy loaded) |
