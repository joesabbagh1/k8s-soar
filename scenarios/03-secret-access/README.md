# Scenario 03 — Service Account Token Access

**MITRE:** T1552 — Unsecured Credentials

## Attack

From inside a running pod, an adversary reads the automatically mounted Kubernetes service account token. That JWT can authenticate to the API server and enable lateral movement, privilege escalation, or data access depending on RBAC bindings.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | From a pod in the **`security-lab`** namespace, `cat` reads the mounted service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. |
| 2. **Detection** | Falco | Rule `K8sSoar Sensitive Credential Access` fires on `open_read` of the token path. |
| 3. **Triage** | falcosidekick | Alert forwarded to the SOAR webhook. |
| 4. **Response** | SOAR responder | Offending pod is labeled `security.quarantine=true`. |
| 5. **Containment** | Network policy | Quarantined pod loses network connectivity. |
| 6. **Governance** | Kyverno | Background audit on `k8s-soar-restrict-sa-automount` flags workloads that mount tokens by default (preventive control for future deploys). |

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Falco | `K8sSoar Sensitive Credential Access` with `fd.name` under `.../serviceaccount` |
| falcosidekick | Webhook POST success |
| SOAR responder | `quarantined pod security-lab/scenario-03-token` |
| Kyverno | Audit hit on `k8s-soar-restrict-sa-automount` (background scan) |

## Capture

```bash
../../scripts/capture-scenario-evidence.sh 3m 'K8sSoar Sensitive Credential Access'
kubectl get policyreport -A | grep -i automount
```
