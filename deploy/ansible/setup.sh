#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
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
  echo ">>> Pre-setup complete. Review inventory.ini and group_vars/all.yml, then run ./setup.sh"
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

echo ">>> Installing Ansible collections..."
ansible-galaxy collection install -r requirements.yml >/dev/null

echo ""
echo ">>> Bootstrapping kubeadm cluster and k8s-soar stack..."
ansible-playbook -i inventory.ini site.yml "${EXTRA_ARGS[@]}" "${ANSIBLE_ARGS[@]}"

CLUSTER_NAME="$(awk '/^cluster_name:/ {gsub(/"/, "", $2); print $2}' group_vars/all.yml)"
ENV_FILE="${HOME}/.kube/${CLUSTER_NAME:-k8s-soar}.env"

echo ""
echo ">>> Bootstrap complete."
echo ">>> New terminals load the cluster automatically. In this one run:"
echo "      source ${ENV_FILE}"
echo ">>> Then: make status    (from the repository root)"
