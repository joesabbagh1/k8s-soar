# k8s-soar Ansible Bootstrap

Provisions a kubeadm cluster on bare-metal Linux servers, then installs the k8s-soar Helm stack (Cilium as CNI).

## Quick start (single VM)

```bash
cd ansible
chmod +x setup.sh
./setup.sh    # packages + auto IP + config + kubeadm + full security stack (SOAR enabled)
```

## What setup.sh does first (pre-setup)

Before Ansible runs, `setup.sh` automatically:

1. Installs **ansible**, **conntrack**, **ethtool**, **socat**, **ipset**, and other apt dependencies
2. Auto-detects this host's IP (`ip route get 1.1.1.1` → source address)
3. Renders **`inventory.ini`** and **`group_vars/all.yml`** from the `*.example` templates, replacing `{{PRESETUP_HOST_IP}}` and `{{PRESETUP_ANSIBLE_USER}}`

Options:

```bash
./setup.sh --force          # regenerate config from *.example files
./setup.sh --ip 172.16.0.2  # only if auto-detect picks the wrong interface
./setup.sh --pre-setup-only # packages + config only (same as ./pre-setup.sh)
```

## Ansible bootstrap phase

1. Optional nuclear wipe of prior k3s/kubeadm installs
2. OS prep: swap off, kernel modules, containerd, kubeadm/kubelet/kubectl
3. `kubeadm init` on master (+ worker join when workers are defined)
4. Fetch kubeconfig to `~/.kube/config-<cluster_name>`, write `~/.kube/<cluster_name>.env`, and wire `~/.bashrc` / `~/.zshrc` to source it
5. Helm install k8s-soar (Cilium + Falco + Tetragon + Kyverno + policies + lab + SOAR)
6. Run `scripts/verify-stack.sh`

## Manual config (multi-node)

Skip auto-config and copy examples yourself:

```bash
cp inventory.example.ini inventory.ini
cp group_vars/all.yml.example group_vars/all.yml
# Edit for your servers, then ./setup.sh
```

## Secrets

Store sensitive vars in `secrets.yml` encrypted with ansible-vault:

```bash
ansible-vault create secrets.yml
```

## Variables

See [group_vars/all.yml.example](./group_vars/all.yml.example) for all tunables.
