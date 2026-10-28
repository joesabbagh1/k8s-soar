# Scenario 10 — ServiceAccount Token Exposure

**MITRE:** T1528 — Steal Application Access Token

## Attack

Kubernetes automatically mounts a ServiceAccount into many pods unless this behavior is disabled. An attacker who compromises a container may discover that a ServiceAccount token, namespace information, and cluster CA certificate are available inside the pod.

This scenario demonstrates the presence of these resources without exposing or using the token.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | Deploy a pod in the **`security-lab`** namespace. |
| 2. **Discovery** | Container | Check whether a ServiceAccount token is mounted. |
| 3. **Observation** | Kubernetes | Verify namespace, ServiceAccount files, cluster CA certificate, and Kubernetes API endpoint are available. |
| 4. **Response (manual demo)** | Operator / SOAR | Review the pod, investigate why the ServiceAccount is mounted, and consider disabling automatic token mounting or using a minimally privileged ServiceAccount where appropriate. |

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kubernetes | Pod `scenario-10-serviceaccount` created successfully |
| Pod Logs | Shows whether a ServiceAccount token file is mounted, namespace, CA certificate presence, and API endpoint environment variables |
| Runtime Security (optional) | Visibility into access to the ServiceAccount directory |
| SOAR | Manual investigation and containment demonstration |

## Manual investigation

```bash
kubectl logs -n security-lab scenario-10-serviceaccount
```

```bash
kubectl describe pod -n security-lab scenario-10-serviceaccount
```

```bash
kubectl exec -it -n security-lab scenario-10-serviceaccount -- sh
```

## Capture

```bash
kubectl get pod -n security-lab scenario-10-serviceaccount -o wide
```

```bash
kubectl logs -n security-lab scenario-10-serviceaccount
```

```bash
kubectl describe pod -n security-lab scenario-10-serviceaccount
```