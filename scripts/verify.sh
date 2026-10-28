#!/usr/bin/env bash
# Health check of a deployed k8s-soar stack. Exit 1 if anything essential is broken.
set -uo pipefail

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BOLD=''; NC=''
fi
pass=0; warn=0; fail=0
ok()      { echo -e "  ${GREEN}✓${NC} $*"; pass=$((pass + 1)); }
warning() { echo -e "  ${YELLOW}!${NC} $*"; warn=$((warn + 1)); }
bad()     { echo -e "  ${RED}✗${NC} $*"; fail=$((fail + 1)); }
section() { echo -e "\n${BOLD}$*${NC}"; }

SOAR_NS="${K8S_SOAR_NAMESPACE:-k8s-soar}"

# rollout <kind/name> <namespace> <label>
rollout() {
  if kubectl rollout status "$1" -n "$2" --timeout="${TIMEOUT:-120s}" >/dev/null 2>&1; then
    ok "$3"
  else
    bad "$3 — kubectl rollout status $1 -n $2"
  fi
}

crd() { kubectl get crd "$1" >/dev/null 2>&1; }

section "Cluster"
if ! kubectl cluster-info >/dev/null 2>&1; then
  bad "cluster not reachable (KUBECONFIG=${KUBECONFIG:-unset})"; exit 1
fi
ok "API server reachable"
not_ready=$(kubectl get nodes --no-headers 2>/dev/null | awk '$2 != "Ready"' | wc -l | tr -d ' ')
if [[ "$not_ready" == 0 ]]; then ok "all nodes Ready"; else bad "${not_ready} node(s) not Ready"; fi

section "Network — Cilium"
rollout ds/cilium kube-system "cilium agent"
if kubectl get ciliumclusterwidenetworkpolicy k8s-soar-quarantine >/dev/null 2>&1; then
  ok "quarantine policy k8s-soar-quarantine present"
else
  bad "quarantine policy missing — quarantined pods would NOT be isolated"
fi

section "Detection — Falco, Tetragon, Kyverno"
rollout ds/falco falco "falco daemonset"
rollout deploy/falco-falcosidekick falco "falcosidekick"
if kubectl get configmap -n falco k8s-soar-falco-rules >/dev/null 2>&1; then
  n=$(kubectl get configmap -n falco k8s-soar-falco-rules -o go-template='{{len .data}}')
  ok "k8s-soar Falco rules ConfigMap (${n} files)"
else
  bad "k8s-soar Falco rules ConfigMap missing"
fi
falco_logs=$(kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --tail=-1 2>/dev/null || true)
if grep -qiE 'k8s-soar.d|K8sSoar' <<<"$falco_logs"; then
  ok "Falco loaded /etc/falco/k8s-soar.d"
elif grep -qiE 'error|LOAD_ERR' <<<"$falco_logs"; then
  bad "Falco reports rule errors — kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco"
else
  warning "could not confirm k8s-soar rules in Falco logs"
fi
if grep -q 'please make sure to install them' <<<"$falco_logs"; then
  bad "Falco plugins missing (container/k8smeta) — check falcoctl-artifact-install init container"
fi
rollout ds/tetragon kube-system "tetragon daemonset"
tp=$(kubectl get tracingpolicies -o name 2>/dev/null | grep -c k8s-soar || true)
if [[ "$tp" -gt 0 ]]; then ok "${tp} Tetragon TracingPolicies"; else warning "no k8s-soar TracingPolicies"; fi
rollout deploy/kyverno-admission-controller kyverno "kyverno admission controller"
cp=$(kubectl get clusterpolicies -o name 2>/dev/null | grep -c k8s-soar || true)
if [[ "$cp" -gt 0 ]]; then ok "${cp} Kyverno ClusterPolicies"; else bad "no k8s-soar Kyverno policies"; fi

section "Response — Argo Events + Workflows"
for c in eventbus.argoproj.io eventsources.argoproj.io sensors.argoproj.io workflows.argoproj.io; do
  crd "$c" || bad "CRD ${c} missing"
done
rollout deploy/argo-events-controller-manager argo-events "argo-events controller"
rollout deploy/argo-workflows-workflow-controller argo "argo workflow controller"
rollout deploy/argo-workflows-server argo "argo server (UI)"
for obj in eventbus/soar eventsource/soar-webhook sensor/soar-router workflowtemplate/falco-response; do
  if kubectl get -n "$SOAR_NS" "$obj" >/dev/null 2>&1; then ok "$obj"; else bad "$obj missing"; fi
done
if kubectl get svc -n "$SOAR_NS" soar-webhook-eventsource-svc >/dev/null 2>&1; then
  ok "webhook service soar-webhook-eventsource-svc:12000"
else
  bad "webhook service missing — Falco alerts cannot reach the response pipeline"
fi
sensor_pods=$(kubectl get pods -n "$SOAR_NS" -l sensor-name=soar-router --no-headers 2>/dev/null | grep -c Running || true)
if [[ "$sensor_pods" -gt 0 ]]; then
  ok "sensor running"
else
  bad "sensor soar-router not running"
  reason=$(kubectl logs -n "$SOAR_NS" -l sensor-name=soar-router --tail=20 2>/dev/null | grep -iE 'error|fatal' | tail -1 || true)
  [[ -n "$reason" ]] && echo "      last error: ${reason:0:200}"
  if grep -qi inotify <<<"$reason"; then
    echo "      fix: raise fs.inotify.max_user_instances on the nodes (see docs/operations.md)"
  fi
fi
if kubectl get deploy -n "$SOAR_NS" soar-console -o jsonpath='{.spec.template.spec.containers[0].env[*].name}' 2>/dev/null | grep -w PYTHONPATH >/dev/null; then
  warning "dev mode is on: pods run the source checkout (./k8s-soar dev off)"
fi
if kubectl get deploy -n "$SOAR_NS" soar-console >/dev/null 2>&1; then
  rollout deploy/soar-console "$SOAR_NS" "analyst console (make console)"
else
  warning "analyst console disabled (k8sSoar.console.enabled=false)"
fi
mode=$(kubectl get configmap -n "$SOAR_NS" soar-config -o jsonpath='{.data.SOAR_MODE}' 2>/dev/null)
ok "response mode: ${mode:-unknown}"

section "AI triage"
if kubectl get deploy -n "$SOAR_NS" soar-agent >/dev/null 2>&1; then
  rollout deploy/soar-agent "$SOAR_NS" "soar-agent"
  if kubectl get secret -n "$SOAR_NS" soar-ai >/dev/null 2>&1; then
    ok "provider key secret soar-ai present"
  else
    warning "secret soar-ai missing — run: make ai-key KEY=... (not needed for Ollama)"
  fi
else
  warning "AI agent disabled (k8sSoar.ai.enabled=false in deploy/profiles)"
fi

section "Observability"
if kubectl get ns monitoring >/dev/null 2>&1; then
  rollout deploy/kube-prometheus-stack-grafana monitoring "grafana"
  rollout statefulset/loki monitoring "loki"
  rollout ds/promtail monitoring "promtail"
else
  warning "observability disabled"
fi

echo
echo -e "${BOLD}Summary:${NC} ${pass} ok, ${warn} warnings, ${fail} failed"
[[ "$fail" -eq 0 ]]
