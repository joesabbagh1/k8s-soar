# Scenario 04 — Reverse Shell (simulated)

**MITRE:** T1059 — Execution

## Attack

From inside a container in `security-lab`, initiate an outbound TCP connection using shell built-ins (`/dev/tcp`), consistent with reverse-shell staging. The simulation targets a non-routable address — no real command-and-control session is established.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Reverse Shell Outbound` |
| Tetragon | tcp_connect event via `k8s-soar-detect-reverse-shell` |
