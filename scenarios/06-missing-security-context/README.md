# Scenario 06 — Missing Security Context / :latest Tag

**MITRE:** Best practice / misconfiguration (CIS Benchmark)

## Attack

A developer deploys a workload using an **unpinned `:latest` image tag** and **no `runAsNonRoot` security context**. This does not exploit a CVE directly, but widens blast radius: mutable images and root-by-default containers are a frequent root cause of successful attacks.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary / misconfig | A pod manifest is submitted to the **`security-lab`** namespace using the unpinned image `nginx:latest` with no `runAsNonRoot` security context. |
| 2. **Admission** | Kubernetes | Pod Security **baseline** in **`security-lab`** allows the manifest — the pod **starts**. |
| 3. **Detection** | Kyverno | Policies `k8s-soar-disallow-latest-tag` and `k8s-soar-require-non-root` record violations in **PolicyReports** (Audit mode). |
| 4. **Response (current)** | Operator | Review PolicyReports; open ticket for team to pin digest and add securityContext. |
| 5. **Response (target state)** | Kyverno Enforce | Same manifest rejected at admission before any pod runs. |

This scenario demonstrates the **audit → tune → enforce** governance path: measure violations first, fix workloads, then block.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kubernetes | Pod `scenario-06-insecure` reaches **Running** |
| Kyverno | PolicyReport violations for latest-tag and non-root policies |
| Falco | — (no runtime attack) |
| SOAR | — (no alert configured for this misconfig) |

## Capture

```bash
kubectl get pod scenario-06-insecure -n security-lab
kubectl get policyreport -A | grep -i security-lab
kubectl describe cpol k8s-soar-disallow-latest-tag
```
