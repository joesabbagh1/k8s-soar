#!/usr/bin/env bash
# One-command install: packages + config from *.example, then kubeadm + k8s-soar stack.
# Usage: ./setup.sh [--force] [--ip <address>] [--pre-setup-only] [ansible-playbook args...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PRE_SETUP_FORCE=false
PRE_SETUP_HOST_IP=""
PRE_SETUP_ONLY=false
ANSIBLE_ARGS=()

show_help() {
  cat <<EOF
Usage: $0 [--force] [--ip <address>] [--pre-setup-only] [ansible-playbook args...]

  Installs apt dependencies, auto-detects host IP, renders inventory.ini and
  group_vars/all.yml from *.example templates, then runs the Ansible bootstrap.

Options:
  --force           Regenerate config from *.example files
  --ip <address>    Override auto-detected host IP
  --pre-setup-only  Stop after package install and config render
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) PRE_SETUP_FORCE=true; shift ;;
    --ip)
      PRE_SETUP_HOST_IP="${2:?--ip requires an address}"
      shift 2
      ;;
    --pre-setup-only) PRE_SETUP_ONLY=true; shift ;;
    -h|--help) show_help; exit 0 ;;
    --)
      shift
      ANSIBLE_ARGS+=("$@")
      break
      ;;
    *) ANSIBLE_ARGS+=("$1"); shift ;;
  esac
done

PRE_SETUP_SCRIPT_DIR="$SCRIPT_DIR"
# shellcheck source=lib/pre-setup.sh
source "${SCRIPT_DIR}/lib/pre-setup.sh"
run_pre_setup

if [[ "$PRE_SETUP_ONLY" == true ]]; then
  echo ""
  echo ">>> Pre-setup complete (SOAR enabled by default: enable_soar: true)."
  exit 0
fi

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "ERROR: ansible-playbook not found after pre-setup." >&2
  exit 1
fi

if [[ ! -f inventory.ini || ! -f group_vars/all.yml ]]; then
  echo "ERROR: inventory.ini or group_vars/all.yml missing after pre-setup." >&2
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

echo ""
echo ">>> Bootstrapping kubeadm cluster and k8s-soar stack..."
ansible-playbook -i inventory.ini site.yml "${EXTRA_ARGS[@]}" "${ANSIBLE_ARGS[@]}"

if [[ -f group_vars/all.yml ]]; then
  CLUSTER_NAME="$(grep '^cluster_name:' group_vars/all.yml | awk '{print $2}' | tr -d '"')"
  KUBECONFIG_PATH="${HOME}/.kube/config-${CLUSTER_NAME:-k8s-soar-client}"
  if [[ -f "$KUBECONFIG_PATH" ]]; then
    export KUBECONFIG="$KUBECONFIG_PATH"
    if grep -qE '^enable_soar:[[:space:]]*true' group_vars/all.yml; then
      export K8S_SOAR_ENABLE_SOAR=1
    fi
    echo ""
    echo ">>> Cluster nodes:"
    kubectl get nodes
    echo ""
    echo ">>> KUBECONFIG is set for this session (~/.bashrc updated for new shells)"
    if [[ "${K8S_SOAR_ENABLE_SOAR:-0}" == "1" ]]; then
      echo ">>> K8S_SOAR_ENABLE_SOAR=1 is set for this session"
    fi
    echo ">>> Other terminals: source ~/.bashrc"
  fi
fi

echo ""
echo ">>> Bootstrap complete."
