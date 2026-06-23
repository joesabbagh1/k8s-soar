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

- Bare-metal or VM servers: Ubuntu 22.04+, kernel ≥ 5.10
- Ansible ≥ 2.14 on operator machine
- SSH + sudo access to all nodes

## One-command install (bare metal from scratch)

```bash
cd ansible
chmod +x setup.sh
./setup.sh
```

This automatically provisions the cluster and security stack. **Attack scenarios are not run** — execute those manually when you are ready (see below).

## Run attack scenarios (manual — one at a time)

After install, new terminals work automatically. In the same terminal where you ran `./setup.sh`, run once:

```bash
source ~/.bashrc
```

```bash
# Pick a scenario — do not run all at once unless you intend to
./scenarios/01-shell-in-container/run.sh
./scenarios/02-privileged-pod/run.sh
# ... see scenarios/threat-matrix.md
```

Each scenario folder has a `README.md` with expected alerts and evidence to capture.

## SOAR (Detect → Isolate)

SOAR (falcosidekick webhook + in-cluster responder) is **enabled by default** in `values.yaml` and via `./ansible/setup.sh` (`enable_soar: true`).

To disable:

```yaml
# ansible/group_vars/all.yml
enable_soar: false
```

Or for manual Helm only: `K8S_SOAR_ENABLE_SOAR=0 ./scripts/helm-install.sh`

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

Or: `K8S_SOAR_ENABLE_OBSERVABILITY=0 ./scripts/helm-install.sh`

## Manual Helm install (kubeadm already done)

```bash
./scripts/helm-install.sh
```

## What is automated vs manual

| Step | Automated by |
|------|----------------|
| OS + kubeadm cluster | Ansible |
| Cilium / Falco / Tetragon / Kyverno | Split Helm releases (`scripts/helm-install.sh`) |
| Grafana / Prometheus / Loki | Split Helm releases (`monitoring` namespace) |
| Falco custom rules | `render-helm-values.sh` overlay |
| Kyverno + Tetragon + quarantine policies | `scripts/apply-policies-lab.sh` |
| security-lab namespace + victim app | `scripts/apply-policies-lab.sh` |
| SOAR responder + webhook | On by default; disable with `enable_soar: false` or `K8S_SOAR_ENABLE_SOAR=0` |
| Grafana dashboards + Loki alerts | On by default; `./scripts/port-forward-grafana.sh` |
| Observability stack | On by default; disable with `observability.enabled: false` or `K8S_SOAR_ENABLE_OBSERVABILITY=0` |
| Attack scenario execution | **Manual only** — `./scenarios/NN-name/run.sh` when you choose |
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
