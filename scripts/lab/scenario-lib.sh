#!/usr/bin/env bash
# Shared helpers — each scenario uses labeled pods and cleans up its own resources.
set -euo pipefail

SCENARIO_NS="${SCENARIO_NS:-default}"
SCENARIO_LABEL_KEY="${SCENARIO_LABEL_KEY:-scenario}"
# Cases created before this process are leftovers from an earlier run of the same pod name.
SCENARIO_STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SCENARIO_CASE=""

# Target: the demo application (make demo-app) or the scenario's own pod.
#
#   make <attack>               auto: use the demo app when it is installed, else the scenario's own pod
#   make <attack> TARGET=demo   require the demo app (fail if it is not installed)
#   make <attack> TARGET=own    never use the demo app
#
# A scenario asks the library for a target before creating its own pod:
#
#   if scenario_pick_target web; then
#     pod="$SCENARIO_TARGET_POD"        # a running demo pod; SCENARIO_NS is now the demo namespace
#   else
#     pod=$(scenario_ensure_pod ...)    # the scenario's own pod, as before
#   fi
#
# It must be called directly, not as $(scenario_pick_target ...): a subshell would
# lose the SCENARIO_NS switch that the case and quarantine helpers below rely on.
DEMO_NS="${DEMO_NS:-shop}"
SCENARIO_TARGET_POD=""
scenario_pick_target() {
  local tier="$1" mode="${SCENARIO_TARGET:-auto}" pod=""
  SCENARIO_TARGET_POD=""
  [[ -n "$mode" ]] || mode=auto
  case "$mode" in
    own) return 1 ;;
    auto | demo) ;;
    *) echo "Unknown TARGET='${mode}' (use demo, own, or leave it unset)" >&2; exit 1 ;;
  esac
  pod=$(kubectl get pod -n "$DEMO_NS" -l "app=${tier}" --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [[ -z "$pod" ]]; then
    if [[ "$mode" == "demo" ]]; then
      echo "TARGET=demo needs the demo app with a running '${tier}' pod. Install it with: make demo-app" >&2
      exit 1
    fi
    return 1
  fi
  SCENARIO_NS="$DEMO_NS"
  # shellcheck disable=SC2034  # read by the scenario scripts that source this library
  SCENARIO_TARGET_POD="$pod"
  echo ">>> Target: demo app, ${DEMO_NS}/${pod} (TARGET=own to use the scenario's own pod)"
}

# Remove pods for one scenario id (e.g. "01") and legacy fixed names.
scenario_cleanup() {
  local id="${1:-}"
  if [[ -n "$id" ]]; then
    kubectl delete pod -n "$SCENARIO_NS" -l "${SCENARIO_LABEL_KEY}=${id}" \
      --ignore-not-found --wait=true --timeout=90s 2>/dev/null || true
  fi
}

# Drop quarantine on the baseline victim workload (SOAR may have labeled it).
scenario_reset_victim() {
  kubectl label pod -n "$SCENARIO_NS" -l app=victim security.quarantine- 2>/dev/null || true
}

# Delete all scenario pods and reset victim between demos.
scenario_cleanup_all() {
  kubectl delete pod -n "$SCENARIO_NS" -l "${SCENARIO_LABEL_KEY}" \
    --ignore-not-found --wait=true --timeout=120s 2>/dev/null || true
  for legacy in scenario-02-privileged scenario-06-insecure scenario-07-peer; do
    kubectl delete pod "$legacy" -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s 2>/dev/null || true
  done
  scenario_reset_victim
}

# Ensure a long-lived pod exists for exec-based scenarios (returns pod name).
scenario_ensure_pod() {
  local id="$1"
  local name="$2"
  local image="$3"
  shift 3

  scenario_cleanup "$id"
  kubectl delete pod "$name" -n "$SCENARIO_NS" --ignore-not-found --wait=true --timeout=60s 2>/dev/null || true
  kubectl run "$name" -n "$SCENARIO_NS" --restart=Never \
    --labels="${SCENARIO_LABEL_KEY}=${id},scenario-target=true" \
    --image="$image" \
    "$@"
  kubectl wait -n "$SCENARIO_NS" --for=condition=Ready "pod/${name}" --timeout=90s
  echo "$name"
}

# Slug the Sensor writes into the k8s-soar.io/rule label.
scenario_rule_label() {
  local label
  label=$(tr '[:upper:]' '[:lower:]' <<<"$1" | sed -E 's/[^a-z0-9]+/-/g')
  label=${label:0:63}
  label=${label%-}
  printf '%s' "$label"
}

scenario_require_namespace() {
  if ! kubectl get namespace "$SCENARIO_NS" >/dev/null 2>&1; then
    echo "Namespace ${SCENARIO_NS} does not exist. Create it with: make deploy" >&2
    exit 1
  fi
}

# Newest case for this selector that was opened by the current run.
scenario_latest_case() {
  local selector="$1"
  local soar_ns="${2:-${K8S_SOAR_NAMESPACE:-k8s-soar}}"
  kubectl get workflows -n "$soar_ns" -l "$selector" \
    --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{range .items[*]}{.metadata.creationTimestamp}{" "}{.metadata.name}{"\n"}{end}' 2>/dev/null \
    | awk -v start="${SCENARIO_STARTED}" '$1 >= start { name = $2 } END { if (name != "") print name }' \
    || true
}

# Block until the response pipeline has opened a case for this pod and rule.
scenario_expect_case() {
  local pod="$1" rule="$2" label soar_ns selector wf
  scenario_require_namespace
  label=$(scenario_rule_label "$rule")
  soar_ns="${K8S_SOAR_NAMESPACE:-k8s-soar}"
  selector="k8s-soar.io/pod=${pod:0:63},k8s-soar.io/rule=${label}"
  for _ in $(seq 90); do
    wf=$(scenario_latest_case "$selector" "$soar_ns")
    if [[ -n "$wf" ]]; then
      SCENARIO_CASE=$wf
      echo "PASS case ${wf} for ${rule} on ${pod}"
      return 0
    fi
    sleep 1
  done
  echo "FAIL no case for '${rule}' on ${pod}. Load rules with: make deploy-soar" >&2
  return 1
}

# The script does not decide the case. The pod stays so the console still has it.
scenario_review() {
  local pod="${1:-}"
  echo
  if [[ -n "${SCENARIO_CASE}" ]]; then
    echo "Case ${SCENARIO_CASE} stays at the approval gate until you decide in the console."
    echo "Review it: make cases, or make console and open /cases/${SCENARIO_CASE}"
  else
    echo "Review it: make cases"
  fi
  if [[ -n "$pod" ]]; then
    echo "Left ${pod} in ${SCENARIO_NS} until that decision."
  else
    echo "Left the scenario pods in ${SCENARIO_NS} until that decision."
  fi
  echo "Delete them later with: make scenario-reset"
}

# Block until the contain step has labelled the pod.
scenario_expect_quarantine() {
  local pod="$1"
  for _ in $(seq 90); do
    if kubectl get pod -n "$SCENARIO_NS" "$pod" -o jsonpath='{.metadata.labels.security\.quarantine}' 2>/dev/null | grep -q true; then
      echo "PASS ${pod} quarantined"
      return 0
    fi
    sleep 1
  done
  echo "FAIL ${pod} was not quarantined" >&2
  return 1
}
