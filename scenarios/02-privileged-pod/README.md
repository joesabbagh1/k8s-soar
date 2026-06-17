# Scenario 02 — Privileged Pod / hostPath

**MITRE:** T1611 — Escape to Host

## Attack

An attacker (or a misconfigured manifest) attempts to schedule a **privileged** pod that mounts the **host root filesystem** via `hostPath`. This is a classic container-escape pattern: full node privileges plus direct access to host paths.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | A pod manifest is submitted to the **`security-lab`** namespace requesting `privileged: true` and a `hostPath` volume mounted at the host root (`/`). |
| 2. **Prevention** | Pod Security Admission | The **`security-lab`** namespace enforces **baseline** Pod Security — the request is **rejected** at admission. |
| 3. **Detection** | Kyverno | Policies `k8s-soar-disallow-privileged` and `k8s-soar-disallow-host-path` record violations in **PolicyReports** (Audit mode). |
| 4. **Response** | Platform | Pod never starts; no runtime containment required. In **Enforce** mode, Kyverno would also reject the manifest at admission. |

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Admission | `Forbidden` — violates PodSecurity `baseline` (privileged + hostPath) |
| Kyverno | PolicyReport entries for `k8s-soar-disallow-privileged` / `k8s-soar-disallow-host-path` |
| Falco | — (pod does not run) |
| SOAR | — (nothing to quarantine) |

## Capture

```bash
kubectl get pod scenario-02-privileged -n security-lab
kubectl get policyreport -A | grep -i security-lab
kubectl describe cpol k8s-soar-disallow-privileged
```
