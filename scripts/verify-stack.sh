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

RELEASE_NS="${K8S_SOAR_NAMESPACE:-k8s-soar}"

ok()   { echo -e "${GREEN}PASS${NC} $*"; pass=$((pass + 1)); }
warn() { echo -e "${YELLOW}WARN${NC} $*"; warn=$((warn + 1)); }
bad()  { echo -e "${RED}FAIL${NC} $*"; fail=$((fail + 1)); }

wait_for_pods() {
  local ns=$1
  local selector=$2
  local timeout=${3:-300}
  if kubectl wait --for=condition=ready pod -n "$ns" -l "$selector" --timeout="${timeout}s" >/dev/null 2>&1; then
    ok "pods ready in ${ns} (${selector})"
    return 0
  fi
  bad "pods not ready in ${ns} (${selector})"
  kubectl get pods -n "$ns" -l "$selector" 2>/dev/null || true
  return 1
}

pods_running() {
  local selector=$1
  shift
  local ns
  for ns in "$@"; do
    [[ -n "$ns" ]] || continue
    if kubectl get pods -n "$ns" -l "$selector" --no-headers 2>/dev/null | grep -q .; then
      if ! kubectl get pods -n "$ns" -l "$selector" --no-headers 2>/dev/null | grep -qv Running; then
        echo "${ns}"
        return 0
      fi
    fi
  done
  return 1
}

echo "=== k8s-soar verify-stack ==="
echo ""

if ! kubectl cluster-info >/dev/null 2>&1; then
  bad "cluster not reachable"
  exit 1
fi
ok "cluster reachable"

# --- Cilium ---
cilium_ns=""
for ns in kube-system "$RELEASE_NS"; do
  if kubectl get daemonset -n "$ns" -l k8s-app=cilium >/dev/null 2>&1 \
    || kubectl get daemonset -n "$ns" cilium >/dev/null 2>&1; then
    cilium_ns="$ns"
    break
  fi
done
if [[ -n "$cilium_ns" ]]; then
  wait_for_pods "$cilium_ns" "k8s-app=cilium" 600 || true
  if kubectl get pods -n "$cilium_ns" -l k8s-app=cilium --no-headers 2>/dev/null | grep -qv Running; then
    bad "some Cilium pods not Running"
  else
    ok "Cilium daemonset healthy"
  fi
elif kubectl get pods -A -l app.kubernetes.io/name=cilium-agent --no-headers 2>/dev/null | grep -q Running; then
  ok "Cilium agent pods running"
else
  bad "Cilium not found (checked kube-system and ${RELEASE_NS})"
fi

# --- Falco ---
falco_ns=""
if ns="$(pods_running app.kubernetes.io/name=falco falco "$RELEASE_NS")"; then
  falco_ns="$ns"
  wait_for_pods "$falco_ns" "app.kubernetes.io/name=falco" 300 || true
  if kubectl logs -n "$falco_ns" -l app.kubernetes.io/name=falco --tail=50 2>/dev/null | grep -q .; then
    ok "Falco producing logs"
  else
    warn "Falco logs empty (may still be starting)"
  fi
  if kubectl logs -n "$falco_ns" -l app.kubernetes.io/name=falco --tail=200 2>/dev/null \
    | grep -q 'please make sure to install them'; then
    bad "Falco plugins not installed (k8s-soar rules will not match) — run ./scripts/repair-falco.sh"
  fi
  if kubectl get deploy -n "$falco_ns" -l app.kubernetes.io/name=k8s-metacollector >/dev/null 2>&1 \
    || kubectl get deploy -n "$falco_ns" 2>/dev/null | grep -qi metacollector; then
    ok "k8s-metacollector deployed"
  else
    warn "k8s-metacollector not found (collectors.kubernetes.enabled should be true)"
  fi
  if kubectl get deploy -n "$falco_ns" -l app.kubernetes.io/name=falcosidekick >/dev/null 2>&1; then
    wait_for_pods "$falco_ns" "app.kubernetes.io/name=falcosidekick" 120 || true
    ok "falcosidekick deployed"
  else
    warn "falcosidekick not deployed (SOAR webhook disabled?)"
  fi
elif kubectl get ns falco >/dev/null 2>&1 || kubectl get ns "$RELEASE_NS" >/dev/null 2>&1; then
  bad "Falco not running (checked falco and ${RELEASE_NS})"
else
  warn "Falco namespace missing"
fi

# --- Tetragon ---
if ns="$(pods_running app.kubernetes.io/name=tetragon kube-system tetragon "$RELEASE_NS")"; then
  wait_for_pods "$ns" "app.kubernetes.io/name=tetragon" 300 || true
  ok "Tetragon running"
else
  bad "Tetragon not running (checked kube-system, tetragon, ${RELEASE_NS})"
fi

# --- Kyverno ---
if ns="$(pods_running app.kubernetes.io/name=kyverno-admission-controller kyverno "$RELEASE_NS")"; then
  wait_for_pods "$ns" "app.kubernetes.io/name=kyverno-admission-controller" 300 || true
  ok "Kyverno admission controller ready"
elif ns="$(pods_running app.kubernetes.io/component=admission-controller kyverno "$RELEASE_NS")"; then
  wait_for_pods "$ns" "app.kubernetes.io/component=admission-controller" 300 || true
  ok "Kyverno admission controller ready"
else
  bad "Kyverno admission controller not running (checked kyverno and ${RELEASE_NS})"
fi
if kubectl get validatingwebhookconfigurations 2>/dev/null | grep -qi kyverno; then
  ok "Kyverno admission webhook registered"
else
  warn "Kyverno webhook not found"
fi

# --- security-lab ---
if kubectl get ns security-lab >/dev/null 2>&1; then
  if kubectl get pods -n security-lab --no-headers 2>/dev/null | grep -q .; then
    wait_for_pods security-lab app=victim 180 || warn "victim workload not ready yet"
  else
    warn "security-lab has no pods (run ./scripts/apply-policies-lab.sh)"
  fi
else
  warn "security-lab namespace missing"
fi

# --- SOAR responder (optional) ---
if kubectl get deploy -n "$RELEASE_NS" k8s-soar-responder >/dev/null 2>&1; then
  wait_for_pods "$RELEASE_NS" app.kubernetes.io/component=soar-responder 120 || true
  ok "SOAR responder deployed"
  if kubectl get configmap -n "$RELEASE_NS" k8s-soar-responder -o yaml 2>/dev/null | grep -q 'output_fields'; then
    ok "SOAR responder webhook parser up to date"
  else
    bad "SOAR responder ConfigMap stale — run ./scripts/upgrade-soar.sh"
  fi
fi

# --- Observability (Grafana + Prometheus + Loki) ---
MONITORING_NS="${K8S_SOAR_MONITORING_NS:-monitoring}"
KPS_RELEASE="${K8S_SOAR_KPS_RELEASE:-kube-prometheus-stack}"
if kubectl get ns "$MONITORING_NS" >/dev/null 2>&1; then
  if kubectl get statefulset,deployment -n "$MONITORING_NS" -l app.kubernetes.io/name=loki --no-headers 2>/dev/null | grep -q .; then
    wait_for_pods "$MONITORING_NS" app.kubernetes.io/name=loki 300 || true
    ok "Loki running in ${MONITORING_NS}"
  else
    warn "Loki not found in ${MONITORING_NS} (observability disabled?)"
  fi
  if kubectl get daemonset -n "$MONITORING_NS" -l app.kubernetes.io/name=promtail >/dev/null 2>&1; then
    wait_for_pods "$MONITORING_NS" app.kubernetes.io/name=promtail 180 || true
    ok "Promtail running"
  fi
  if kubectl get deploy -n "$MONITORING_NS" "${KPS_RELEASE}-grafana" >/dev/null 2>&1; then
    wait_for_pods "$MONITORING_NS" app.kubernetes.io/name=grafana 300 || true
    ok "Grafana running (${KPS_RELEASE}-grafana)"
  else
    warn "Grafana not deployed in ${MONITORING_NS}"
  fi
  if kubectl get prometheus -n "$MONITORING_NS" "${KPS_RELEASE}-kube-prometheus-prometheus" >/dev/null 2>&1 \
    || kubectl get deploy -n "$MONITORING_NS" -l app.kubernetes.io/name=prometheus >/dev/null 2>&1; then
    ok "Prometheus operator stack present"
  fi
  if [[ -n "$falco_ns" ]] && kubectl get servicemonitor -n "$falco_ns" -l app.kubernetes.io/name=falco >/dev/null 2>&1; then
    ok "Falco ServiceMonitor configured"
  elif [[ -n "$falco_ns" ]]; then
    warn "Falco ServiceMonitor missing (observability.metrics disabled?)"
  fi
else
  warn "monitoring namespace missing (observability disabled?)"
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
