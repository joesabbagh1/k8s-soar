#!/usr/bin/env bash
# Shared helpers — each scenario uses labeled pods and cleans up its own resources.
set -euo pipefail

SCENARIO_NS="${SCENARIO_NS:-default}"
SCENARIO_LABEL_KEY="${SCENARIO_LABEL_KEY:-scenario}"

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

# Block until the response pipeline has opened a case for this pod and rule.
scenario_expect_case() {
  local pod="$1" rule="$2" label soar_ns selector wf
  scenario_require_namespace
  label=$(scenario_rule_label "$rule")
  soar_ns="${K8S_SOAR_NAMESPACE:-k8s-soar}"
  selector="k8s-soar.io/pod=${pod:0:63},k8s-soar.io/rule=${label}"
  for _ in $(seq 90); do
    if kubectl get workflows -n "$soar_ns" -l "$selector" -o name 2>/dev/null | grep -q .; then
      wf=$(kubectl get workflows -n "$soar_ns" -l "$selector" -o jsonpath='{.items[0].metadata.name}')
      echo "PASS case ${wf} for ${rule} on ${pod}"
      return 0
    fi
    sleep 1
  done
  echo "FAIL no case for '${rule}' on ${pod}. Load rules with: make deploy-soar" >&2
  return 1
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
