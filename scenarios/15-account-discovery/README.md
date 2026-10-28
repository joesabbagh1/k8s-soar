# Scenario 15 — Account Discovery

**MITRE:** T1087 — Account Discovery

## Attack

After gaining access to a Kubernetes container, an attacker identifies which user account is running inside the container and what account information is available. This helps determine the privileges of the compromised workload and may influence later attack decisions.

This scenario demonstrates account discovery using standard Linux commands available inside the container.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | A pod named **`scenario-15-account-discovery`** is deployed in the **`security-lab`** namespace. |
| 2. **Discovery** | Container | The pod displays the current user, user ID, group membership, and basic account information from `/etc/passwd` and `/etc/group`. |
| 3. **Detection** | Runtime Security | Runtime security tools such as Falco or Tetragon can detect account enumeration commands. |
| 4. **Response (manual demo)** | Operator / SOAR | Review pod activity, investigate the workload, and isolate or terminate the container if the behavior is unexpected. |

This scenario demonstrates the discovery phase of a Kubernetes attack. Identifying available user accounts helps an attacker understand the execution context and available privileges.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kubernetes | Pod `scenario-15-account-discovery` is created successfully |
| Pod Logs | Displays the current user, user ID, group membership, and basic account information |
| Falco / Tetragon (optional) | Account discovery activity may be detected |
| SOAR | Manual investigation and containment demonstration |

## Manual investigation

```bash
kubectl logs -n security-lab scenario-15-account-discovery
```

```bash
kubectl exec -it -n security-lab scenario-15-account-discovery -- sh
```

```bash
kubectl describe pod -n security-lab scenario-15-account-discovery
```

## Capture

```bash
kubectl get pod -n security-lab scenario-15-account-discovery -o wide
```

```bash
kubectl logs -n security-lab scenario-15-account-discovery
```

```bash
kubectl describe pod -n security-lab scenario-15-account-discovery
```