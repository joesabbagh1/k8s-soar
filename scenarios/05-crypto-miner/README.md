# Scenario 05 — Crypto Miner Process (simulated)

**MITRE:** T1496 — Resource Hijacking

## Attack

An adversary runs a process whose name matches known cryptocurrency miners (e.g. `xmrig`) inside a container. Miners consume CPU for unauthorized profit and are a common sign of cluster compromise or vulnerable exposed workloads.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | A process named `xmrig` is executed inside a pod in the **`security-lab`** namespace (simulated by renaming a `sleep` binary). |
| 2. **Detection** | Falco | Rule `K8sSoar Crypto Miner Process` fires on `spawned_process` where `proc.name` matches miner names. |
| 3. **Triage** | falcosidekick | Alert forwarded to SOAR webhook. |
| 4. **Response** | SOAR responder | Pod labeled `security.quarantine=true`. |
| 5. **Containment** | Network policy | Miner pod isolated from cluster and external networks. |

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Crypto Miner Process` with `proc.name=xmrig` |
| falcosidekick | Webhook POST success |
| SOAR responder | Quarantine label on `scenario-05-miner` |

## Capture

```bash
../../scripts/capture-scenario-evidence.sh 3m 'K8sSoar Crypto Miner Process'
kubectl get pod -n security-lab -l security.quarantine=true
```
