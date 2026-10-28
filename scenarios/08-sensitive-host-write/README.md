# Scenario 08 — Sensitive File Write (simulated)

**MITRE:** T1611 — Escape to Host

## Attack

From inside a container, an adversary attempts to **modify a sensitive credential file** (`/etc/shadow`). Even when the file is container-local, this behaviour matches credential tampering and host-escape reconnaissance.

## Scenario flow

| Step | Layer | What happens |
|------|-------|--------------|
| 1. **Attack** | Adversary | From a pod in the **`security-lab`** namespace, a process attempts to append data to `/etc/shadow` — a sensitive credential file. |
| 2. **Enforcement** | Tetragon | TracingPolicy `k8s-soar-block-sensitive-writes` matches the path and applies **Sigkill** — process terminated, write blocked. |
| 3. **Detection** | Falco | May emit file-access alerts depending on rule overlap (secondary signal). |
| 4. **Response** | Kernel / eBPF | Attack stopped at syscall layer — faster than pod quarantine; no SOAR webhook required for containment. |
| 5. **Governance** | Kyverno | `k8s-soar-disallow-host-path` prevents hostPath mounts at admission (complements runtime enforcement). |

This scenario highlights **preventive enforcement** (Tetragon) vs **detect-and-isolate** (Falco + SOAR in scenarios 01, 03–05).

## Run

```bash
./run.sh
```

## Expected evidence

| Tool | Expected |
|------|----------|
| Tetragon | Process killed on sensitive path open; exec returns error or `write denied (expected)` |
| Falco | Optional file-access alert |
| Kyverno | Audit on host-path policy for workloads with host mounts |
| SOAR | — (Tetragon contains before webhook path matters) |

## Capture

```bash
kubectl get tracingpolicy k8s-soar-block-sensitive-writes
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon --since=5m | grep -i shadow
```
