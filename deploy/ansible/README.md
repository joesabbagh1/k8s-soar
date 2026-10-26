# Ansible bootstrap

Provisions a kubeadm cluster on bare-metal/VM Linux hosts, then deploys the k8s-soar stack with
helmfile (Cilium is the CNI).

## Quick start (single node)

```bash
cd deploy/ansible
./setup.sh
```

`setup.sh` first runs a **pre-setup** on this machine:

1. apt-installs Ansible and node prerequisites
2. auto-detects the host IP (`ip route get 1.1.1.1`)
3. renders `inventory.ini` and `group_vars/all.yml` from the `*.example` files
4. installs the Ansible collections in `requirements.yml`

Options: `--force` (regenerate config), `--ip <addr>`, `--pre-setup-only`, plus any
`ansible-playbook` arguments (e.g. `--tags`, `-v`).

## Playbook stages (`site.yml`)

| Stage | Hosts | What |
|-------|-------|------|
| 1/5 Preflight | k8s | kernel ≥ `min_kernel_version`, `/sys/fs/bpf` |
| 2/5 Prepare nodes | k8s | swap off, kernel modules, sysctl, containerd (systemd cgroups), pinned kubeadm/kubelet/kubectl |
| 3/5 Control plane | master, workers | `kubeadm init`, worker join, single-node taint removal |
| 4/5 Operator | localhost | kubeconfig at `~/.kube/config-<cluster_name>`, env file sourced by bash/zsh |
| 5/5 Stack | localhost | pinned helm + helmfile, local-path StorageClass, `scripts/secrets.sh`, `helmfile apply`, `scripts/verify.sh` |

Every task is idempotent; re-running upgrades nothing implicitly (package versions are held).
`nuclear_wipe: true` wipes a previous k3s/kubeadm install first — **destructive**, off by default.

## Multi-node

```bash
cp inventory.example.ini inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
# edit hosts under [master] / [workers] and the variables, then:
./setup.sh
```

## Secrets

Integration secrets come from `deploy/secrets.env` (see `deploy/secrets.env.example`).
Ansible-specific secrets (become passwords) can go in an ansible-vault `secrets.yml`.

See [group_vars/all.yml.example](./group_vars/all.yml.example) for all variables.
