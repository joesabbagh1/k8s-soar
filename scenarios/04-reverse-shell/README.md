# Scenario 04 — Reverse Shell (simulated)

**MITRE:** T1059 — Execution

## Attack

Simulate reverse-shell setup with outbound TCP from victim pod (connect to blackhole IP).

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Reverse Shell Outbound` |
| Tetragon | tcp_connect event via `k8s-soar-detect-reverse-shell` |

## Note

Uses a non-routable target; does not establish a real C2 session.
