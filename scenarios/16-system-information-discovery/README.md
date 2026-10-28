# Scenario 16 — System Information Discovery

**MITRE:** T1082 — System Information Discovery

## Attack

After compromising a Kubernetes container, an attacker may collect information about the operating system and runtime environment. This helps identify the platform, architecture, kernel version, and execution context before attempting further actions.

This scenario demonstrates system information discovery by collecting information available from within the container.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | A pod named **`scenario-16-system-information`** is deployed in the **`security-lab`** namespace. |
| 2. **Discovery** | Container | The pod collects the hostname, operating system information, kernel version, CPU architecture, current user, and uptime. |
| 3. **Detection** | Runtime Security | Runtime monitoring tools such as Falco or Tetragon can detect execution of system information commands. |
| 4. **Response (manual demo)** | Operator / SOAR | Review the pod logs, investigate the workload, and isolate or terminate the pod if the behavior is unexpected. |

This scenario demonstrates the reconnaissance phase of a Kubernetes attack. The collected information helps an attacker understand the execution environment before performing additional actions.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kubernetes | Pod `scenario-16-system-information` is created successfully |
| Pod Logs | Displays hostname, operating system, kernel version, CPU architecture, current user, and uptime |
| Falco / Tetragon (optional) | Alerts for execution of system information commands |
| SOAR | Manual investigation and response demonstration |

## Manual investigation

```bash
kubectl logs -n security-lab scenario-16-system-information
```

```bash
kubectl exec -it -n security-lab scenario-16-system-information -- sh
```

```bash
kubectl describe pod -n security-lab scenario-16-system-information
```

## Capture

```bash
kubectl get pod -n security-lab scenario-16-system-information -o wide
```

```bash
kubectl logs -n security-lab scenario-16-system-information
```

```bash
kubectl describe pod -n security-lab scenario-16-system-information
```