# k8s-soar Ansible Bootstrap

Provisions a kubeadm cluster on bare-metal Linux servers, then installs the k8s-soar Helm stack (Cilium as CNI).

## Prerequisites

- Ansible ≥ 2.14 on the operator machine
- Target nodes: Ubuntu 22.04+ (Debian-based), kernel ≥ 5.10, SSH access with sudo
- Operator machine: `kubectl`, `helm` (installed automatically if missing during Helm phase)

## Quick start

```bash
cp inventory.example.ini inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
# Edit inventory.ini and group_vars/all.yml for your servers

./setup.sh
```

## What it does

1. Optional nuclear wipe of prior k3s/kubeadm installs
2. OS prep: swap off, kernel modules, containerd, kubeadm/kubelet/kubectl
3. `kubeadm init` on master (+ worker join when workers are defined)
4. Fetch kubeconfig to operator machine
5. Helm install k8s-soar from chart defaults (Cilium + Falco + Tetragon + Kyverno)
6. Run `scripts/verify-stack.sh`

## Single-node cluster

Leave the `[workers]` group empty in `inventory.ini` and set `allow_control_plane_scheduling: true` in `group_vars/all.yml`.

## Secrets

Store sensitive vars in `secrets.yml` encrypted with ansible-vault:

```bash
ansible-vault create secrets.yml
```

## Variables

See [group_vars/all.yml.example](./group_vars/all.yml.example) for all tunables.
