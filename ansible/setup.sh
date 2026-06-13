#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "ERROR: ansible-playbook not found. Run ./pre-setup.sh first."
  exit 1
fi

if [[ ! -f inventory.ini ]]; then
  echo "ERROR: inventory.ini not found. Run ./pre-setup.sh first."
  exit 1
fi

if [[ ! -f group_vars/all.yml ]]; then
  echo "ERROR: group_vars/all.yml not found. Run ./pre-setup.sh first."
  exit 1
fi

EXTRA_ARGS=()
if [[ -f secrets.yml ]]; then
  EXTRA_ARGS+=(-e "@secrets.yml")
  if [[ -z "${ANSIBLE_VAULT_PASSWORD_FILE:-}" && -z "${VAULT_PASS:-}" ]]; then
    EXTRA_ARGS+=(--ask-vault-pass)
  fi
fi

export OBJC_DISABLE_INITIALIZE_FORK_SAFETY="${OBJC_DISABLE_INITIALIZE_FORK_SAFETY:-YES}"

echo ">>> Bootstrapping kubeadm cluster and k8s-soar stack..."
ansible-playbook -i inventory.ini site.yml "${EXTRA_ARGS[@]}" "$@"

if [[ -f group_vars/all.yml ]]; then
  CLUSTER_NAME="$(grep '^cluster_name:' group_vars/all.yml | awk '{print $2}' | tr -d '"')"
  KUBECONFIG_PATH="${HOME}/.kube/config-${CLUSTER_NAME:-k8s-soar-client}"
  if [[ -f "$KUBECONFIG_PATH" ]]; then
    export KUBECONFIG="$KUBECONFIG_PATH"
    echo ""
    echo ">>> Cluster nodes:"
    kubectl get nodes
    echo ""
    echo ">>> export KUBECONFIG=$KUBECONFIG_PATH"
  fi
fi

echo ""
echo ">>> Bootstrap complete."
