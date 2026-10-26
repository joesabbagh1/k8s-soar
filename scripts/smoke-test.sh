#!/usr/bin/env bash
# End-to-end test: detection -> response pipeline -> containment.
#
# Creates a throwaway namespace with a small Deployment, triggers k8s-soar
# rules from inside the pod and checks that:
#   1. Falco raised the alert,
#   2. a case Workflow ran,
#   3. the pod was labelled quarantined and detached from its ReplicaSet,
#   4. its egress is blocked while it stays Running (probes still pass),
#   5. a clean replacement pod was scheduled.
#
# Usage: scripts/smoke-test.sh [--keep]
set -euo pipefail

NS="k8s-soar-smoke-$(date +%s)"
SOAR_NS="${K8S_SOAR_NAMESPACE:-k8s-soar}"
KEEP=false; [[ "${1:-}" == "--keep" ]] && KEEP=true
RULE="K8sSoar Service Account Token Read By Shell Tool"
# Same slug the Sensor writes into the k8s-soar.io/rule label.
RULE_LABEL=$(tr '[:upper:]' '[:lower:]' <<<"$RULE" | sed -E 's/[^a-z0-9]+/-/g')

step() { echo -e "\n\033[1m==> $*\033[0m"; }
fail() { echo -e "\033[0;31mFAIL\033[0m $*"; exit 1; }
pass() { echo -e "\033[0;32mPASS\033[0m $*"; }

cleanup() {
  if [[ "$KEEP" == true ]]; then
    echo "Kept namespace ${NS} (delete with: kubectl delete ns ${NS})"
  else
    kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Printed when a step times out: where the case got stuck.
diagnose() {
  [[ -n "${WF:-}" ]] || return 0
  echo "    case ${WF}: $(kubectl get workflow -n "$SOAR_NS" "$WF" -o jsonpath='{.status.phase} {.status.message}' 2>/dev/null)"
  kubectl get pods -n "$SOAR_NS" -l "workflows.argoproj.io/workflow=${WF}" \
    -o custom-columns='STEP:.metadata.annotations.workflows\.argoproj\.io/node-name,STATUS:.status.containerStatuses[*].state.*.reason,IMAGE:.spec.containers[*].image' \
    2>/dev/null | sed 's/^/    /'
}

wait_for() { # wait_for <seconds> <description> <command...>
  local timeout=$1 what=$2; shift 2
  for _ in $(seq "$timeout"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  diagnose
  fail "timed out after ${timeout}s waiting for: ${what}"
}

step "Creating test workload in ${NS}"
kubectl create namespace "$NS" >/dev/null
kubectl apply -n "$NS" -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: victim
spec:
  replicas: 1
  selector:
    matchLabels: {app: victim}
  template:
    metadata:
      labels: {app: victim}
    spec:
      containers:
        - name: web
          image: nginx:1.27-alpine
          readinessProbe:
            httpGet: {path: /, port: 80}
            periodSeconds: 5
          livenessProbe:
            httpGet: {path: /, port: 80}
            periodSeconds: 5
          resources:
            requests: {cpu: 10m, memory: 16Mi}
            limits: {memory: 64Mi}
YAML
kubectl rollout status -n "$NS" deploy/victim --timeout=120s >/dev/null
POD=$(kubectl get pod -n "$NS" -l app=victim -o jsonpath='{.items[0].metadata.name}')
pass "pod ${POD} running"

step "Triggering '${RULE}'"
kubectl exec -n "$NS" "$POD" -- sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null' || true

step "1. Falco alert"
wait_for 60 "Falco alert for ${POD}" \
  sh -c "kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --since=2m | grep -q '${POD}'"
pass "Falco reported the event"

step "2. Case workflow"
# Other rules may open their own cases for the same pod; follow the one we triggered.
CASE_SELECTOR="k8s-soar.io/pod=${POD:0:63},k8s-soar.io/rule=${RULE_LABEL:0:63}"
wait_for 90 "case for '${RULE}' on ${POD}" \
  sh -c "kubectl get workflows -n ${SOAR_NS} -l '${CASE_SELECTOR}' -o name | grep . >/dev/null"
WF=$(kubectl get workflows -n "$SOAR_NS" -l "$CASE_SELECTOR" -o jsonpath='{.items[0].metadata.name}')
pass "case ${WF} created"

step "3. Quarantine + orphaning"
wait_for 90 "quarantine label on ${POD}" \
  sh -c "kubectl get pod -n ${NS} ${POD} -o jsonpath='{.metadata.labels.security\.quarantine}' | grep -q true"
pass "pod labelled security.quarantine=true"
owner=$(kubectl get pod -n "$NS" "$POD" -o jsonpath='{.metadata.ownerReferences[0].kind}')
[[ -z "$owner" ]] && pass "pod detached from its ReplicaSet" || echo "WARN pod still owned by ${owner}"

step "4. Network isolation"
sleep 5
if kubectl exec -n "$NS" "$POD" -- wget -q -T 3 -O /dev/null http://kubernetes.default.svc 2>/dev/null; then
  fail "quarantined pod can still reach the network"
fi
pass "egress blocked"
sleep 15
restarts=$(kubectl get pod -n "$NS" "$POD" -o jsonpath='{.status.containerStatuses[0].restartCount}')
[[ "$restarts" == 0 ]] && pass "pod kept running (probes still pass, evidence preserved)" \
  || echo "WARN container restarted ${restarts}x — probes blocked by quarantine policy?"

step "5. Replacement pod"
wait_for 60 "replacement pod" \
  sh -c "kubectl get pods -n ${NS} -l app=victim --field-selector=status.phase=Running -o name | grep -v ${POD} | grep -q ."
pass "a clean replacement pod is running"

echo
phase=$(kubectl get workflow -n "$SOAR_NS" "$WF" -o jsonpath='{.status.phase}')
echo "Case ${WF} is ${phase} (Running = waiting at the approval gate)."
echo "Inspect: make argo-ui, then open /workflows/${SOAR_NS}/${WF}  (use --keep to keep the test pod for the approval step)"
echo -e "\033[0;32mSmoke test passed.\033[0m"
