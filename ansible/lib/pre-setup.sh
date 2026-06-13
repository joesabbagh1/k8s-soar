# shellcheck shell=bash
# Sourced by setup.sh — installs packages and renders inventory/group_vars from *.example.

pre_setup_detect_host_ip() {
  local ip=""
  ip="$($PRE_SETUP_SUDO ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") print $(i + 1)}' | head -1)"
  if [[ -z "$ip" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  if [[ -z "$ip" ]]; then
    echo "ERROR: could not detect host IP. Pass --ip manually." >&2
    exit 1
  fi
  echo "$ip"
}

pre_setup_render_template() {
  local src=$1
  sed \
    -e "s/{{PRESETUP_HOST_IP}}/${PRE_SETUP_HOST_IP}/g" \
    -e "s/{{PRESETUP_ANSIBLE_USER}}/${PRE_SETUP_ANSIBLE_USER}/g" \
    < "$src"
}

pre_setup_write_from_example() {
  local example=$1
  local dest=$2

  if [[ ! -f "$example" ]]; then
    echo "ERROR: missing template ${example}" >&2
    exit 1
  fi

  if [[ -f "$dest" && "$PRE_SETUP_FORCE" != true ]]; then
    if grep -q '{{PRESETUP_' "$dest" 2>/dev/null; then
      echo ">>> Updating placeholders in ${dest}"
      pre_setup_render_template "$dest" > "${dest}.tmp"
      mv "${dest}.tmp" "$dest"
      echo ">>> Updated ${dest}"
      return
    fi
    echo ">>> Skipping ${dest} (exists; use --force to regenerate from ${example})"
    return
  fi

  if [[ -f "$dest" && "$PRE_SETUP_FORCE" == true ]]; then
    cp "$dest" "${dest}.bak.$(date +%Y%m%d%H%M%S)"
    echo ">>> Backed up existing ${dest}"
  fi

  pre_setup_render_template "$example" > "$dest"
  echo ">>> Wrote ${dest} from ${example}"
}

run_pre_setup() {
  if [[ "$(id -u)" -eq 0 ]]; then
    PRE_SETUP_SUDO=""
  else
    PRE_SETUP_SUDO="sudo"
  fi

  PRE_SETUP_HOST_IP="${PRE_SETUP_HOST_IP:-$(pre_setup_detect_host_ip)}"
  PRE_SETUP_ANSIBLE_USER="${SUDO_USER:-${USER:-ubuntu}}"

  echo ">>> k8s-soar pre-setup"
  echo ">>> Host IP:        ${PRE_SETUP_HOST_IP} (auto-detected; override with --ip)"
  echo ">>> Ansible user:   ${PRE_SETUP_ANSIBLE_USER}"
  echo ""

  echo ">>> Installing required packages..."
  $PRE_SETUP_SUDO apt-get update -qq
  $PRE_SETUP_SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    ansible \
    git \
    curl \
    gpg \
    apt-transport-https \
    ca-certificates \
    conntrack \
    ethtool \
    socat \
    ipset

  mkdir -p group_vars
  pre_setup_write_from_example inventory.example.ini inventory.ini
  pre_setup_write_from_example group_vars/all.yml.example group_vars/all.yml

  chmod +x "${PRE_SETUP_SCRIPT_DIR}/setup.sh" "${PRE_SETUP_SCRIPT_DIR}/../scripts/"*.sh 2>/dev/null || true
}
