# Scenario 09 — Container and Resource Discovery

**MITRE:** T1613 — Container and Resource Discovery

## Attack

After compromising a Kubernetes container, an adversary performs **container and resource discovery** to understand the environment before launching further attacks. The attacker enumerates the pod hostname, namespace, service account files, environment variables, mounted file systems, network configuration, DNS settings, and Kubernetes API endpoint. This reconnaissance helps identify potential targets and available privileges within the cluster.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | A pod named **`scenario-09-discovery`** is deployed in the **`security-lab`** namespace and executes common discovery commands inside the container. |
| 2. **Discovery** | Container | The attacker gathers the hostname, namespace, ServiceAccount information, environment variables, mounted volumes, network interfaces, routing table, DNS configuration, and Kubernetes API endpoint. |
| 3. **Detection** | Runtime Security | Falco or other runtime monitoring solutions can detect execution of discovery commands and access to Kubernetes ServiceAccount files. |
| 4. **Response (manual demo)** | Operator / SOAR | Review pod logs, investigate the suspicious container, and delete or isolate the compromised pod to prevent additional reconnaissance. |

This scenario demonstrates the reconnaissance phase of a Kubernetes attack. The collected information may later be used for privilege escalation, credential theft, or lateral movement.

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Kubernetes | Pod `scenario-09-discovery` is created successfully |
| Pod Logs | Hostname, namespace, ServiceAccount files, environment variables, network information, and Kubernetes API endpoint are displayed |
| Falco (optional) | Alerts for discovery commands or ServiceAccount access |
| SOAR | Manual investigation and containment demonstration |

## Manual investigation

```bash
kubectl logs -n security-lab scenario-09-discovery
```

```bash
kubectl exec -it -n security-lab scenario-09-discovery -- sh
```

## Capture

```bash
kubectl get pod -n security-lab scenario-09-discovery -o wide
```

```bash
kubectl logs -n security-lab scenario-09-discovery
```

```bash
kubectl describe pod -n security-lab scenario-09-discovery
```