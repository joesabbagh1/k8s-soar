# Scenario 07 — Lateral Movement (pod-to-pod)

**MITRE:** T1021 — Remote Services

## Attack

A compromised pod in `security-lab` attempts to connect to another pod in the same namespace over the network, simulating lateral movement after initial access. Default-deny network policy should block the connection.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| NetworkPolicy | Connection blocked or timeout |
| Hubble | Denied flow (when Cilium/Hubble enabled) |
| SOAR | Manual quarantine demo: `kubectl label pod -n security-lab <pod> security.quarantine=true` |
