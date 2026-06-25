# k8s-soar

> **Kubernetes Security Orchestration, Automation & Response**
> Bare-metal bootstrap — kubeadm + Cilium + Falco + Tetragon + Kyverno

[![Publish Helm Chart](https://github.com/joesabbagh1/k8s-soar/actions/workflows/helm-publish.yml/badge.svg)](https://github.com/joesabbagh1/k8s-soar/actions/workflows/helm-publish.yml)

---

## Overview

`k8s-soar` provisions a complete security stack on **bare-metal Linux servers** from scratch:

1. **Ansible** — OS prep, kubeadm cluster, Helm install
2. **Cilium** — eBPF CNI, network policies, Hubble
3. **Falco** — runtime threat detection (modern eBPF) + custom rules
4. **Tetragon** — kernel-level enforcement policies
5. **Kyverno** — admission policies-as-code
6. **security-lab** — isolated namespace for attack scenarios
7. **SOAR responder** — Detect → Isolate via falcosidekick webhook (enabled by default)
8. **Observability** — Grafana + Prometheus + Loki for findings dashboards and alerts (enabled by default)

## Prerequisites

**For Bare-Metal (From Scratch):**
- Bare-metal or VM servers: Ubuntu 22.04+, kernel ≥ 5.10
- Ansible ≥ 2.14 on operator machine
- SSH + sudo access to all nodes

## Install: One-command (Bare-metal from scratch)

```bash
cd ansible
chmod +x setup.sh
./setup.sh
```

This automatically provisions the cluster and security stack. **Attack scenarios are not run** — execute those manually when you are ready (see below).

## Run attack scenarios (Separated Repository)

Attack scenarios are now housed in a separate repository to maintain `k8s-soar` as a clean, deployable security solution. 
Please refer to the `k8s-soar-scenarios` repository to run simulations and trigger the security stack.

## Post-Install: Shuffle SOAR

Shuffle is automatically installed and configured alongside the security stack! 

During installation, the script automatically:
1. Created an admin account (`admin` / `admin_password123!`).
2. Imported the default `playbooks/master-responder.json` workflow.
3. Hooked the workflow directly into Falco's webhook endpoint.

If you wish to view or modify your Playbooks, simply access the UI:
```bash
kubectl port-forward svc/shuffle-frontend -n shuffle 3001:3000
```
Open `http://localhost:3001` in your browser.

## Observability (Grafana + Prometheus + Loki)

The observability stack is **enabled by default** so you can visualize Falco findings, explore alert history, and configure Grafana alerts.

| Component | Role |
|-----------|------|
| **Prometheus** | Scrapes Falco / falcosidekick metrics (ServiceMonitors) |
| **Loki** | Stores Falco JSON alerts (via falcosidekick + Promtail pod logs) |
| **Grafana** | `k8s-soar — Falco Findings` dashboard + provisioned Loki alert |

```bash
./scripts/port-forward-grafana.sh
# http://127.0.0.1:3000 — user admin, password k8s-soar (change in values.yaml)
```

**Do you need Loki?** Prometheus gives you rates and counters; **Loki is what makes full finding text searchable** in Grafana (rule name, pod, namespace, output message). Promtail also captures responder/sidekick logs for SOAR correlation.

To disable observability:

```yaml
# values.yaml
observability:
  enabled: false
```

Or: `K8S_SOAR_ENABLE_OBSERVABILITY=0 ./ansible/setup.sh`

## Manual Helm install (kubeadm already done)

```bash
./ansible/setup.sh
```

## What is automated vs manual

| Step | Automated by |
|------|----------------|
| OS + kubeadm cluster | Ansible |
| Cilium / Falco / Tetragon / Kyverno | Split Helm releases (`ansible/setup.sh`) |
| Grafana / Prometheus / Loki | Split Helm releases (`monitoring` namespace) |
| Falco custom rules | `render-helm-values.sh` overlay |
| Kyverno + Tetragon + quarantine policies | `scripts/apply-policies-lab.sh` |
| security-lab namespace + victim app | `scripts/apply-policies-lab.sh` |
| SOAR responder + webhook | On by default; disable with `enable_soar: false` or `K8S_SOAR_ENABLE_SOAR=0` |
| Grafana dashboards + Loki alerts | On by default; `./scripts/port-forward-grafana.sh` |
| Observability stack | On by default; disable with `observability.enabled: false` or `K8S_SOAR_ENABLE_OBSERVABILITY=0` |
| Attack scenario execution | **k8s-soar-scenarios repository** |
| Kyverno Enforce mode | Optional — policies ship in Audit mode |
| Inventory / server IPs | One-time manual edit |

To update policies without a full reinstall: `kubectl apply -k policies/`

## Verify

```bash
./scripts/verify-stack.sh
kubectl get cpol -A
kubectl get ns security-lab
```

## Documentation

- [Ansible bootstrap](./ansible/README.md)
- [Architecture](./docs/thesis/ARCHITECTURE.md)
- [Observability](./docs/OBSERVABILITY.md)
- [Threat matrix](./scenarios/threat-matrix.md)
- [SOAR limitations](./docs/thesis/SOAR-LIMITATIONS.md)

## License

MIT
