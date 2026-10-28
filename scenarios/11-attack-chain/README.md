# Scenario 11 — Advanced Attack Chain (T1190, T1059, T1613, T1071, T1611)

This scenario simulates a multi-stage advanced attack chain to demonstrate defense-in-depth, visibility gaps, and response architectures across multiple layers of the cluster.

The attack progresses through 5 stages:

## Stage 1 — Initial Foothold (T1190 / T1059)
**Action:** Exploiting a known vulnerable web application (DVWA) to gain a reverse shell inside the cluster.
The victim workload is a standard web application exposed via NodePort without strict network policies. The attacker gains a shell as the `www-data` user inside the container.

## Stage 2 — Credential Access (T1528)
**Action:** Reading the default mounted Kubernetes ServiceAccount token.
```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```
**Detection:** Tetragon's process-execution instrumentation captures the exact command and its outcome at the kernel level.
**Implication:** This step alone does not compromise anything — Kubernetes RBAC determines what the token is actually good for. This token will be used in Stages 3 and 5.

## Stage 3 — Discovery (T1613)
**Action:** Using the stolen token, attempted to list pods in the `security-lab` namespace via the Kubernetes API from inside the compromised DVWA pod.
**Result (Blocked):** The API server correctly rejected the request with 403 Forbidden because the default service account lacks RBAC bindings for listing pods.
**Detection Gap:** Falco's stock rule "Contact K8S API Server From Container" did not fire for this specific request. This demonstrates a documented detection gap for pods created after Falco's own startup.

## Stage 4 — Command & Control (T1071)
**Action:** From the Stage 1 foothold shell, opened a second reverse shell back to the attacker, simulating C2 expansion.
**Detection:** Tetragon's `k8s-soar-detect-reverse-shell` TracingPolicy fired successfully.
**Response Gap:** The connection was not blocked. Tetragon's policy is `action: Post` (log-only), and Tetragon detections are not currently wired into the SOAR quarantine loop (which relies solely on Falco).

## Stage 5 — Privilege Escalation (T1611 / T1548)
**Action:** Enumerated the pod's runtime security posture, finding no viable capability-based escape. Pivoted to identity abuse using the stolen SA token against the Kubernetes API (`check.php` and `escalate.php`).
- Queried `SelfSubjectRulesReview` to see authorized actions.
- Attempted to create a privileged, host-mounting pod (`hostPID: true`, `privileged: true`, `hostPath: /`).
**Result (Blocked):** Rejected by RBAC before reaching OPA admission policies. The default SA is restricted to self-introspection.
**Detection Gap:** The cluster lacks an API server audit log, so this denied escalation attempt left no Kubernetes-native audit record.

## Evidence & Logs
See the `logs/` directory for raw Tetragon and API response artifacts from the various stages of this chain.
