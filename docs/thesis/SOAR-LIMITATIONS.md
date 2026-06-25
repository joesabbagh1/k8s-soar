# SOAR Limitations and Extensions

## Implemented scope (Detect → Isolate)

1. Falco detects runtime threat (JSON output)
2. falcosidekick forwards alert to in-cluster webhook
3. SOAR responder labels pod `security.quarantine=true`
4. CiliumNetworkPolicy / NetworkPolicy denies traffic to quarantined pods

## Limitations

| Limitation | Impact |
|------------|--------|
| **Latency** | Seconds between exec detection and network isolation |
| **False positives** | Benign shell exec may trigger quarantine — tune Falco priority/rules |
| **Node-level compromise** | Pod quarantine does not isolate a compromised node |
| **Data already exfiltrated** | Network deny cannot retract exfiltrated data |
| **Non-Cilium CNI** | Use `policies/network/quarantine-networkpolicy.yaml` fallback |
| **Admission vs runtime** | Kyverno cannot block already-running pods — Falco/Tetragon required |
| **Webhook availability** | If responder is down, isolation does not occur |

## Proposed extensions (optional thesis work)

- **CRIU memory snapshots** on quarantine for forensic preservation
- **Argo Workflows** — wipe pod + redeploy from verified image digest
- **Policy signing** — Sigstore/Cosign for Kyverno policy bundles
- **External SOAR** — integrate PagerDuty/Slack via falcosidekick fan-out

## Enabling SOAR

In `ansible/group_vars/all.yml`:

```yaml
enable_soar: true
```

Then re-run `./ansible/setup.sh`, or:

```bash
K8S_SOAR_ENABLE_SOAR=1 ./ansible/setup.sh
```

Test isolate manually:

```bash
kubectl label pod -n security-lab <victim-pod> security.quarantine=true --overwrite
kubectl exec -n security-lab <victim-pod> -- wget -T 2 -qO- http://example.com || echo isolated
```
