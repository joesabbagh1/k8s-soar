# Scenario 14 — Process Discovery

**MITRE:** T1057 — Process Discovery

## Attack

After gaining access to a Kubernetes container, an attacker may inspect the running processes to understand what applications and services are active. This reconnaissance helps identify potential targets and provides context for later stages of an attack.

This scenario demonstrates process discovery by listing the processes running inside the container.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | A pod named **`scenario-14-process-discovery`** is deployed in the **`security-lab`** namespace. |
| 2. **Discovery** | Container | The pod displays the current user and enumerates running processes using standard Linux commands. |
| 3. **Detection** | Runtime Security | Runtime monitoring tools such as Falco or Tetragon can detect process enumeration activity. |
| 4. **Response (manual demo)** | Operator / SOAR | Review pod logs, investigate the container, and isolate or terminate the workload if the activity is suspicious. |

This scenario demonstrates the discovery phase of a Kubernetes attack. Understanding the running processes helps an attacker identify services and plan subsequent actions.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kubernetes | Pod `scenario-14-process-discovery` is created successfully |
| Pod Logs | Displays the current user and running processes |
| Falco / Tetragon (optional) | Process enumeration activity may be detected |
| SOAR | Manual investigation and containment demonstration |

## Manual investigation

```bash
kubectl logs -n security-lab scenario-14-process-discovery
```

```bash
kubectl exec -it -n security-lab scenario-14-process-discovery -- sh
```

```bash
kubectl describe pod -n security-lab scenario-14-process-discovery
```

## Capture

```bash
kubectl get pod -n security-lab scenario-14-process-discovery -o wide
```

```bash
kubectl logs -n security-lab scenario-14-process-discovery
```

```bash
kubectl describe pod -n security-lab scenario-14-process-discovery
```