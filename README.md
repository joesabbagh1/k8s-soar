# k8s-soar

> **Kubernetes Security Orchestration, Automation & Response**
> Bare-metal bootstrap — kubeadm + Cilium + Falco + Tetragon + Kyverno

[![Publish Helm Chart](https://github.com/joesabbagh1/k8s-soar/actions/workflows/helm-publish.yml/badge.svg)](https://github.com/joesabbagh1/k8s-soar/actions/workflows/helm-publish.yml)

---

## Overview

`k8s-soar` provisions a complete security stack on **bare-metal Linux servers** from scratch:

1. **Ansible** — OS prep, kubeadm cluster, Helm install
2. **Cilium** — eBPF CNI, network policies, Hubble
3. **Falco** — runtime threat detection (modern eBPF)
4. **Tetragon** — kernel-level enforcement
5. **Kyverno** — admission policies-as-code
6. **SOAR responder** (optional) — Detect → Isolate via falcosidekick webhook

| Component | Role |
|-----------|------|
| **Ansible** | Bare-metal kubeadm bootstrap |
| **Cilium** | CNI + network security + Hubble |
| **Falco** | Syscall-level detection |
| **Tetragon** | eBPF TracingPolicies |
| **Kyverno** | Admission policy engine |

## Prerequisites

- Bare-metal or VM servers: Ubuntu 22.04+, kernel ≥ 5.10
- Ansible ≥ 2.14 on operator machine
- SSH + sudo access to all nodes
- Operator machine: Helm ≥ 3.14 (installed by Ansible if missing)

## Install (bare metal from scratch)

```bash
cp ansible/inventory.example.ini ansible/inventory.ini
cp ansible/group_vars/all.yml.example ansible/group_vars/all.yml
# Edit: master IP, node hosts, cluster_name, SSH key

./ansible/setup.sh
```

The playbook will:

1. Prepare nodes and install kubeadm (no CNI yet — nodes stay NotReady)
2. Initialize the cluster and join workers
3. Install k8s-soar via Helm (Cilium becomes the pod network)
4. Run `./scripts/verify-stack.sh`

Then apply policies and the attack lab:

```bash
export KUBECONFIG=~/.kube/config-<cluster_name>   # from setup.sh output
kubectl apply -k policies/
kubectl apply -k lab/
./scripts/load-falco-rules.sh
./scenarios/run-all.sh
```

## Manual Helm install (after kubeadm only)

If you already ran kubeadm separately and need only the security stack:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add cilium         https://helm.cilium.io/
helm repo add kyverno        https://kyverno.github.io/kyverno/
helm repo update
helm dependency build .

helm install k8s-soar . \
  --namespace k8s-soar --create-namespace \
  --wait --timeout 15m
```

## Enable SOAR (Detect → Isolate)

Set in `values.yaml` or pass `--set`:

```yaml
soar:
  responder:
    enabled: true
falco:
  falcosidekick:
    enabled: true
    config:
      webhook:
        address: "http://k8s-soar-responder.k8s-soar.svc.cluster.local:8080/webhook"
        minimumpriority: "warning"
```

Then `helm upgrade k8s-soar . -n k8s-soar --wait`. See [docs/thesis/SOAR-LIMITATIONS.md](./docs/thesis/SOAR-LIMITATIONS.md).

## Repository layout

```text
ansible/          Bare-metal kubeadm bootstrap + Helm install
values.yaml       Full stack defaults (Cilium + Falco + Tetragon + Kyverno)
policies/         Kyverno, Falco, Tetragon, quarantine YAML
lab/              security-lab namespace + victim workload
scenarios/        Threat matrix + attack simulation runbooks
scripts/          preflight, verify-stack, load-falco-rules
docs/             Thesis architecture, methodology, validation
```

## Verify

```bash
./scripts/verify-stack.sh
kubectl get pods -n kube-system -l k8s-app=cilium
kubectl get pods -n falco
kubectl get pods -n tetragon
kubectl get pods -n kyverno
```

## Documentation

- [Ansible bootstrap](./ansible/README.md)
- [Architecture](./docs/thesis/ARCHITECTURE.md)
- [Methodology](./docs/thesis/METHODOLOGY.md)
- [Reproducibility](./docs/thesis/REPRODUCIBILITY.md)
- [Threat matrix](./scenarios/threat-matrix.md)

## License

MIT
