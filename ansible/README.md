# k8s-soar Ansible Bootstrap

Provisions a kubeadm cluster on bare-metal Linux servers, then installs the k8s-soar Helm stack (Cilium as CNI).

## Quick start (single VM)

```bash
cd ansible
chmod +x pre-setup.sh setup.sh
./pre-setup.sh    # installs packages, detects IP, writes config (SOAR enabled)
./setup.sh        # kubeadm + full security stack
```

## What pre-setup.sh does

1. Installs **ansible**, **conntrack**, **ethtool**, **socat**, **ipset**, and other apt dependencies
2. Detects this host's IP (default route source address)
3. Writes **`inventory.ini`** — single-node, `ansible_connection=local`
4. Writes **`group_vars/all.yml`** — matching `apiserver_advertise_address`, **`enable_soar: true`**

Options:

```bash
./pre-setup.sh --force          # overwrite existing inventory and group_vars
./pre-setup.sh --ip 172.16.0.2  # set IP manually
K8S_SOAR_CLUSTER_NAME=my-cluster ./pre-setup.sh
```

## What setup.sh does

1. Optional nuclear wipe of prior k3s/kubeadm installs
2. OS prep: swap off, kernel modules, containerd, kubeadm/kubelet/kubectl
3. `kubeadm init` on master (+ worker join when workers are defined)
4. Fetch kubeconfig to operator machine
5. Helm install k8s-soar (Cilium + Falco + Tetragon + Kyverno + policies + lab + SOAR)
6. Run `scripts/verify-stack.sh`

## Manual config (multi-node)

Skip pre-setup and copy examples yourself:

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
