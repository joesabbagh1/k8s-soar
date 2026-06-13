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
7. **SOAR responder** (optional) — Detect → Isolate via falcosidekick webhook

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

After install, new terminals load cluster access automatically via `~/.bashrc`. In the same terminal where you ran `./setup.sh`, run once:

```bash
source ~/.kube/k8s-soar-client.env
```

```bash
# Pick a scenario — do not run all at once unless you intend to
./scenarios/01-shell-in-container/run.sh
./scenarios/02-privileged-pod/run.sh
# ... see scenarios/threat-matrix.md
```

Each scenario folder has a `README.md` with expected alerts and evidence to capture.

## Enable SOAR (Detect → Isolate)

SOAR is **enabled by default** when using `./ansible/setup.sh` (`enable_soar: true`).

To disable, set in `group_vars/all.yml`:

```yaml
enable_soar: false
```

Then re-run `./setup.sh`.

## Manual Helm install (kubeadm already done)

```bash
./scripts/helm-install.sh
```

## What is automated vs manual

| Step | Automated by |
|------|----------------|
| OS + kubeadm cluster | Ansible |
| Cilium / Falco / Tetragon / Kyverno | Helm |
| Falco custom rules | `render-helm-values.sh` overlay |
| Kyverno + Tetragon + quarantine policies | Helm (`templates/extras-manifests.yaml`) |
| security-lab namespace + victim app | Helm (`templates/extras-manifests.yaml`) |
| SOAR responder + webhook | `enable_soar: true` or `K8S_SOAR_ENABLE_SOAR=1` |
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
- [Threat matrix](./scenarios/threat-matrix.md)
- [SOAR limitations](./docs/thesis/SOAR-LIMITATIONS.md)

## License

MIT
