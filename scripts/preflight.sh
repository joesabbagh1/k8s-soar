#!/usr/bin/env bash
# Pre-install checks for k8s-soar on any Kubernetes cluster.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass=0
warn=0
fail=0

ok()   { echo -e "${GREEN}PASS${NC} $*"; pass=$((pass + 1)); }
warn() { echo -e "${YELLOW}WARN${NC} $*"; warn=$((warn + 1)); }
bad()  { echo -e "${RED}FAIL${NC} $*"; fail=$((fail + 1)); }

MIN_K8S_MINOR=28
MIN_KERNEL="5.10"

echo "=== k8s-soar preflight ==="
echo ""

# --- kubectl / helm ---
if command -v kubectl >/dev/null 2>&1; then
  ok "kubectl found"
else
  bad "kubectl not found"
fi

if command -v helm >/dev/null 2>&1; then
  ok "helm found"
else
  bad "helm not found (required for install)"
fi

# --- cluster access ---
if kubectl cluster-info >/dev/null 2>&1; then
  ok "cluster reachable"
else
  bad "cannot reach cluster — set KUBECONFIG"
fi

# --- kubernetes version ---
# (--short was removed from kubectl; parse the JSON instead)
if ver=$(kubectl version -o json 2>/dev/null | sed -n 's/.*"gitVersion": *"v\([0-9.]*\).*/\1/p' | tail -1) && [[ -n "$ver" ]]; then
  minor=$(echo "$ver" | cut -d. -f2)
  if [[ "$minor" -ge "$MIN_K8S_MINOR" ]]; then
    ok "Kubernetes v${ver} (>= 1.${MIN_K8S_MINOR})"
  else
    bad "Kubernetes v${ver} — require >= 1.${MIN_K8S_MINOR}"
  fi
else
  warn "could not determine Kubernetes version"
fi

# --- nodes ready ---
if kubectl get nodes >/dev/null 2>&1; then
  total=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
  ready=$(kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready ' || true)
  if [[ "$total" -gt 0 && "$ready" -eq "$total" ]]; then
    ok "all ${total} node(s) Ready"
  elif [[ "$total" -gt 0 ]]; then
    warn "${ready}/${total} nodes Ready — expected before Cilium install"
  else
    bad "no nodes found"
  fi
fi

# --- kernel version on nodes (best effort via kubectl) ---
# (process substitution, not a pipe, so ok/warn counters survive the loop)
while read -r kv; do
  [[ -n "$kv" ]] || continue
  kver=${kv%%-*}
  if [[ "$(printf '%s\n' "$kver" "$MIN_KERNEL" | sort -V | head -1)" == "$MIN_KERNEL" ]]; then
    ok "node kernel ${kv}"
  else
    warn "node kernel ${kv} — recommend >= ${MIN_KERNEL} for Falco/Tetragon eBPF"
  fi
done < <(kubectl get nodes -o jsonpath='{range .items[*]}{.status.nodeInfo.kernelVersion}{"\n"}{end}' 2>/dev/null || true)

# --- expect fresh kubeadm cluster (no CNI until k8s-soar installs Cilium) ---
if kubectl get daemonset -n kube-system cilium 2>/dev/null | grep cilium >/dev/null; then
  ok "Cilium already installed"
elif kubectl get daemonset -n kube-system 2>/dev/null | grep -E 'calico|flannel|weave|canal' >/dev/null; then
  warn "existing CNI detected — k8s-soar expects a fresh kubeadm cluster without CNI"
else
  ok "no CNI yet — ready for k8s-soar Helm install (Cilium)"
fi

# --- operator tooling ---
if command -v helmfile >/dev/null 2>&1; then
  ok "helmfile found"
else
  bad "helmfile not found (https://github.com/helmfile/helmfile/releases)"
fi
if helm plugin list 2>/dev/null | grep '^diff' >/dev/null; then
  ok "helm-diff plugin installed"
else
  warn "helm-diff plugin missing — run: helmfile init"
fi

echo ""
echo "=== summary: ${pass} passed, ${warn} warnings, ${fail} failed ==="
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
