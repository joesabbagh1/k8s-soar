# Scenario 11 — Credentials in Files

**MITRE:** T1552.001 — Credentials in Files

## Attack

After compromising a container, an attacker searches the file system for commonly used credential and configuration files. These files may contain sensitive information such as usernames, passwords, SSH keys, API tokens, or application secrets. Misconfigured containers and applications often store these files in predictable locations.

This scenario demonstrates credential discovery without exposing or reading sensitive data.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | A pod named **`scenario-11-credentials`** is deployed in the **`security-lab`** namespace. |
| 2. **Discovery** | Container | The pod checks common locations for credential and configuration files. |
| 3. **Detection** | Runtime Security | Security tools may detect file enumeration in sensitive directories. |
| 4. **Response (manual demo)** | Operator / SOAR | Review pod activity, investigate why sensitive files are accessible, and remove unnecessary credentials or restrict access. |

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kubernetes | Pod `scenario-11-credentials` is created successfully |
| Pod Logs | Lists whether common credential files exist |
| Runtime Security (optional) | Alerts for file enumeration activity |
| SOAR | Manual investigation and response demonstration |

## Manual investigation

```bash
kubectl logs -n security-lab scenario-11-credentials
```

```bash
kubectl exec -it -n security-lab scenario-11-credentials -- sh
```

```bash
kubectl describe pod -n security-lab scenario-11-credentials
```

## Capture

```bash
kubectl get pod -n security-lab scenario-11-credentials -o wide
```

```bash
kubectl logs -n security-lab scenario-11-credentials
```

```bash
kubectl describe pod -n security-lab scenario-11-credentials
```