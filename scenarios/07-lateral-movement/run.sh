#!/usr/bin/env bash
# Pod-to-pod pivot: a shell in the attacker pod fetches the peer over its pod IP.
# That connect matches "K8sSoar Lateral Movement To Pod" (soar_contain), which
# opens a case and quarantines the attacker the same way smoke-test does.
# The peer must accept TCP; Falco's connect rules ignore "connection refused".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../scripts/lab/scenario-lib.sh
source "${ROOT}/scripts/lab/scenario-lib.sh"

SCENARIO_ID="07"
ATTACKER="scenario-07-attacker"
PEER="scenario-07-peer"
SOAR_NS="${K8S_SOAR_NAMESPACE:-k8s-soar}"
KEEP=false
[[ "${1:-}" == "--keep" ]] && KEEP=true
PASSED=false
RULE="K8sSoar Lateral Movement To Pod"
RULE_LABEL=$(tr '[:upper:]' '[:lower:]' <<<"$RULE" | sed -E 's/[^a-z0-9]+/-/g')
CASE_SELECTOR="k8s-soar.io/pod=${ATTACKER},k8s-soar.io/rule=${RULE_LABEL}"

step() { echo -e "\n\033[1m==> $*\033[0m"; }
fail() { echo -e "\033[0;31mFAIL\033[0m $*"; exit 1; }
pass() { echo -e "\033[0;32mPASS\033[0m $*"; }

# A passing run leaves the quarantined attacker up. The case is waiting at the
# approval gate; deleting the pod would remove the evidence the reviewer decides on.
cleanup() {
  if [[ "$PASSED" == true || "$KEEP" == true ]]; then
    return
  fi
  scenario_cleanup "$SCENARIO_ID"
  kubectl delete pod "$ATTACKER" "$PEER" -n "$SCENARIO_NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

has_new_case() { [[ -n "$(scenario_latest_case "$CASE_SELECTOR" "$SOAR_NS")" ]]; }
trap cleanup EXIT

diagnose_falco() {
  echo "---- why Falco did not report ${ATTACKER} ----"
  if kubectl get configmap -n falco k8s-soar-falco-rules -o jsonpath='{.data}' 2>/dev/null | grep -q 'Lateral Movement To Pod'; then
    echo "The rule is in the Falco ConfigMap."
  else
    echo "The rule is not loaded. From this repo run: make deploy-soar"
  fi
  echo "Recent Falco log lines that mention rules or errors:"
  kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --since=5m --tail=80 2>/dev/null \
    | grep -iE 'error|invalid|Lateral Movement|scenario-07' | tail -20 \
    || echo "    (no matching Falco log lines)"
}

wait_for() {
  local timeout=$1 what=$2
  shift 2
  for _ in $(seq "$timeout"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  if [[ "$what" == Falco* ]]; then
    diagnose_falco
  fi
  fail "timed out after ${timeout}s waiting for: ${what}"
}

if ! kubectl get namespace "$SCENARIO_NS" >/dev/null 2>&1; then
  fail "namespace ${SCENARIO_NS} does not exist. Create it with: make deploy"
fi

scenario_cleanup "$SCENARIO_ID"
kubectl delete pod "$ATTACKER" "$PEER" -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true

step "Creating attacker and peer in ${SCENARIO_NS}"
# nginx accepts the TCP connection. A sleeping pod returns "connection refused",
# and Falco does not treat a refused connect as a completed outbound connection.
kubectl run "$PEER" -n "$SCENARIO_NS" --restart=Never \
  --labels="${SCENARIO_LABEL_KEY}=${SCENARIO_ID},scenario-role=peer" \
  --image=nginx:1.27-alpine >/dev/null
kubectl run "$ATTACKER" -n "$SCENARIO_NS" --restart=Never \
  --labels="${SCENARIO_LABEL_KEY}=${SCENARIO_ID},scenario-role=attacker" \
  --image=busybox:1.36 --command -- sleep 3600 >/dev/null
kubectl wait -n "$SCENARIO_NS" --for=condition=Ready "pod/${PEER}" "pod/${ATTACKER}" --timeout=120s >/dev/null
PEER_IP=$(kubectl get pod -n "$SCENARIO_NS" "$PEER" -o jsonpath='{.status.podIP}')
pass "peer ${PEER} is listening at ${PEER_IP}"

step "Triggering '${RULE}'"
echo "Pod-to-pod probe from ${ATTACKER} to ${PEER} (${PEER_IP})"
reached=false
for _ in $(seq 15); do
  if kubectl exec -n "$SCENARIO_NS" "$ATTACKER" -- sh -c "wget -T 3 -qO- http://${PEER_IP}/ >/dev/null"; then
    reached=true
  fi
  if has_new_case; then
    break
  fi
  sleep 2
done
[[ "$reached" == true ]] && pass "the peer accepted the connection" \
  || echo "WARN the probe never reached the peer (connection refused does not open this case)"

step "1. Falco alert"
wait_for 60 "Falco alert for ${ATTACKER}" \
  sh -c "kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --since=3m | grep -q '${ATTACKER}'"
pass "Falco reported the event"
if ! kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --since=3m 2>/dev/null | grep -q 'Lateral Movement To Pod'; then
  echo "WARN Falco saw the pod but not '${RULE}'. Load the rule with: make deploy-soar"
fi

step "2. Case workflow"
wait_for 90 "case for '${RULE}' on ${ATTACKER}" has_new_case
WF=$(scenario_latest_case "$CASE_SELECTOR" "$SOAR_NS")
SCENARIO_CASE=$WF
pass "case ${WF} created"

step "3. Quarantine"
wait_for 90 "quarantine label on ${ATTACKER}" \
  sh -c "kubectl get pod -n ${SCENARIO_NS} ${ATTACKER} -o jsonpath='{.metadata.labels.security\.quarantine}' | grep -q true"
pass "pod labelled security.quarantine=true"

step "4. Network isolation"
# Cilium programs the new identity a few seconds after the label lands.
blocked=false
for _ in $(seq 12); do
  if ! kubectl exec -n "$SCENARIO_NS" "$ATTACKER" -- wget -q -T 3 -O /dev/null "http://${PEER_IP}/" 2>/dev/null; then
    blocked=true
    break
  fi
  sleep 2
done
[[ "$blocked" == true ]] && pass "egress blocked (${PEER_IP} unreachable from the quarantined pod)" \
  || fail "quarantined pod can still reach ${PEER_IP} (reload the policy with: make deploy-soar)"

PASSED=true
echo -e "\033[0;32mLateral movement scenario passed.\033[0m"
scenario_review "$ATTACKER"
