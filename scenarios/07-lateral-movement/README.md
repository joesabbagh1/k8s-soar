# Scenario 07 — Lateral Movement (pod-to-pod)

**MITRE:** T1021 — Remote Services

## Attack

After compromising one pod, an adversary probes or connects to **another pod** in the same namespace — for example, hitting a peer service on its pod IP. East-west movement inside a namespace is a common step toward reaching higher-value targets.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | In the **`security-lab`** namespace, pod `scenario-07-attacker` sends an HTTP probe to the pod IP of `scenario-07-peer` — simulating east-west lateral movement. |
| 2. **Prevention** | NetworkPolicy | Default-deny policy in **`security-lab`** blocks pod-to-pod traffic — the connection **times out**. |
| 3. **Detection** | Cilium Hubble | Denied flow visible in Hubble observe (optional). |
| 4. **Response (manual demo)** | Operator / SOAR | Label suspect pod `security.quarantine=true` to apply quarantine NetworkPolicy and stop any allowed paths. |

Runtime Falco rules are not the primary control here — **network segmentation** contains lateral movement before exfiltration.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| NetworkPolicy | `wget: download timed out` or `blocked` |
| Hubble | Dropped verdict between attacker and peer pods (if Hubble enabled) |
| Falco | — |
| SOAR | Manual quarantine demo (see below) |

## Manual quarantine demo

```bash
kubectl label pod -n security-lab scenario-07-attacker security.quarantine=true --overwrite
kubectl exec -n security-lab scenario-07-attacker -- wget -T 2 -qO- http://1.1.1.1 || echo isolated
```

## Capture

```bash
hubble observe --namespace security-lab --verdict Dropped
kubectl get networkpolicy -n security-lab
```
