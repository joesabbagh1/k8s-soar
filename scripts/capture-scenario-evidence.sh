#!/usr/bin/env bash
# Print Falco / Sidekick evidence after running a scenario.
set -euo pipefail

SINCE="${1:-3m}"
PATTERN="${2:-k8s-soar|Shell spawned|scenario-01}"

echo ">>> Falco (stdout, last ${SINCE}):"
kubectl logs -n falco -l app.kubernetes.io/name=falco --since="$SINCE" 2>/dev/null \
  | grep -iE "$PATTERN" || echo "    (no matches)"

if kubectl get deploy -n falco -l app.kubernetes.io/name=falcosidekick >/dev/null 2>&1; then
  echo ">>> Falcosidekick (last ${SINCE}):"
  kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick --since="$SINCE" 2>/dev/null \
    | grep -iE "$PATTERN" || echo "    (no matches)"
fi
