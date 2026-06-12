#!/usr/bin/env bash
# Post-install verification for k8s-soar stack.
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

wait_for_pods() {
  local ns=$1
  local selector=$2
  local timeout=${3:-300}
  if kubectl wait --for=condition=ready pod -n "$ns" -l "$selector" --timeout="${timeout}s" >/dev/null 2>&1; then
    ok "pods ready in ${ns} (${selector})"
  else
    bad "pods not ready in ${ns} (${selector})"
    kubectl get pods -n "$ns" -l "$selector" 2>/dev/null || true
  fi
}

echo "=== k8s-soar verify-stack ==="
echo ""

if ! kubectl cluster-info >/dev/null 2>&1; then
  bad "cluster not reachable"
  exit 1
fi
ok "cluster reachable"

# --- Cilium (optional) ---
if kubectl get daemonset -n kube-system cilium >/dev/null 2>&1; then
  wait_for_pods kube-system k8s-app=cilium 600
  if kubectl get pods -n kube-system -l k8s-app=cilium --no-headers 2>/dev/null | grep -qv Running; then
    bad "some Cilium pods not Running"
  else
    ok "Cilium daemonset healthy"
  fi
else
  bad "Cilium not installed — run k8s-soar Helm install"
fi

# --- Falco ---
if kubectl get ns falco >/dev/null 2>&1; then
  wait_for_pods falco app.kubernetes.io/name=falco 300
  if kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 2>/dev/null | grep -q .; then
    ok "Falco producing logs"
  else
    warn "Falco logs empty (may still be starting)"
  fi
else
  warn "falco namespace missing"
fi

# --- Tetragon ---
if kubectl get ns tetragon >/dev/null 2>&1; then
  wait_for_pods kube-system app.kubernetes.io/name=tetragon 300 2>/dev/null || \
  wait_for_pods tetragon app.kubernetes.io/name=tetragon 300 2>/dev/null || \
  warn "Tetragon pod selector may differ — check manually"
  if kubectl get pods -A -l app.kubernetes.io/name=tetragon --no-headers 2>/dev/null | grep -q Running; then
    ok "Tetragon running"
  else
    warn "Tetragon pods not confirmed Running"
  fi
else
  warn "tetragon namespace missing — check helm release"
fi

# --- Kyverno ---
if kubectl get ns kyverno >/dev/null 2>&1; then
  wait_for_pods kyverno app.kubernetes.io/component=admission-controller 300 2>/dev/null || \
  wait_for_pods kyverno app.kubernetes.io/name=kyverno 300 2>/dev/null || \
  warn "Kyverno pod selector may differ"
  if kubectl get validatingwebhookconfigurations 2>/dev/null | grep -qi kyverno; then
    ok "Kyverno admission webhook registered"
  else
    warn "Kyverno webhook not found"
  fi
else
  warn "kyverno namespace missing"
fi

# --- SOAR responder (optional) ---
if kubectl get deploy -n k8s-soar k8s-soar-responder >/dev/null 2>&1; then
  wait_for_pods k8s-soar app.kubernetes.io/component=soar-responder 120
  ok "SOAR responder deployed"
fi

# --- nodes ready ---
ready=$(kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready ' || true)
total=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [[ "$ready" -eq "$total" && "$total" -gt 0 ]]; then
  ok "all ${total} node(s) Ready"
else
  bad "${ready}/${total} nodes Ready"
fi

echo ""
echo "=== summary: ${pass} passed, ${warn} warnings, ${fail} failed ==="
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
