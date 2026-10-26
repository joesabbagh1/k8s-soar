#!/usr/bin/env bash
# Shared helpers — each scenario uses labeled pods and cleans up its own resources.
set -euo pipefail

SCENARIO_NS="${SCENARIO_NS:-security-lab}"
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
