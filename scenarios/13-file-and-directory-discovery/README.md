# Scenario 13 — File and Directory Discovery

**MITRE:** T1083 — File and Directory Discovery

## Attack

After compromising a Kubernetes container, an attacker performs file and directory discovery to understand the container's file system. The attacker enumerates common directories such as the root directory, `/etc`, `/var`, and `/tmp` to identify configuration files, application data, logs, and other resources that may be useful in later stages of an attack.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | A pod named **`scenario-13-file-discovery`** is deployed in the **`security-lab`** namespace. |
| 2. **Discovery** | Container | The attacker lists common directories (`/`, `/etc`, `/var`, `/tmp`) to understand the container's file system. |
| 3. **Detection** | Runtime Security | Runtime security tools such as Falco can detect suspicious directory enumeration inside the container. |
| 4. **Response (manual demo)** | Operator / SOAR | Review pod activity, investigate the container, and isolate or terminate the suspicious workload if necessary. |

This scenario demonstrates the discovery phase of a Kubernetes attack. Understanding the file system helps an attacker locate configuration files, logs, application data, and other resources before attempting further actions.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kubernetes | Pod `scenario-13-file-discovery` is created successfully |
| Pod Logs | Displays the contents of `/`, `/etc`, `/var`, and `/tmp` |
| Runtime Security (optional) | Alerts for file and directory enumeration |
| SOAR | Manual investigation and response demonstration |

## Manual investigation

```bash
kubectl logs -n security-lab scenario-13-file-discovery
```

```bash
kubectl exec -it -n security-lab scenario-13-file-discovery -- sh
```

```bash
kubectl describe pod -n security-lab scenario-13-file-discovery
```

## Capture

```bash
kubectl get pod -n security-lab scenario-13-file-discovery -o wide
```

```bash
kubectl logs -n security-lab scenario-13-file-discovery
```

```bash
kubectl describe pod -n security-lab scenario-13-file-discovery
```