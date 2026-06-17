# Scenario 07 — Lateral Movement (pod-to-pod)

**MITRE:** T1021 — Remote Services

## Attack

Attempt pod-to-pod traffic between **dedicated** attacker and peer pods (both `scenario=07`), blocked by default-deny NetworkPolicy.

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
