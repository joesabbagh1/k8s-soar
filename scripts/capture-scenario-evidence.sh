#!/usr/bin/env bash
# Print Falco / Sidekick evidence after running a scenario.
set -euo pipefail

SINCE="${1:-3m}"
PATTERN="${2:-k8s-soar|Shell spawned|scenario-01}"

echo ">>> Falco (stdout, last ${SINCE}):"
falco_logs="$(kubectl logs -n falco -l app.kubernetes.io/name=falco --since="$SINCE" 2>/dev/null || true)"
if [[ -z "$falco_logs" ]]; then
  echo "    (no logs — is Falco running?)"
elif echo "$falco_logs" | grep -qiE 'please make sure to install them|error.*plugin'; then
  echo "    (Falco plugins missing — run ./scripts/repair-falco.sh first)"
  echo "$falco_logs" | grep -iE 'please make sure|plugin' | tail -3 | sed 's/^/    /'
else
  echo "$falco_logs" | grep -iE "$PATTERN" || echo "    (no matches)"
fi

if kubectl get deploy -n falco -l app.kubernetes.io/name=falcosidekick >/dev/null 2>&1; then
  echo ">>> Falcosidekick (last ${SINCE}):"
  sidekick_logs="$(kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick --since="$SINCE" 2>/dev/null || true)"
  if [[ -z "$sidekick_logs" ]]; then
    echo "    (no logs)"
  else
    echo "$sidekick_logs" | grep -iE "${PATTERN}|webhook|Shell spawned|K8sSoar" || echo "    (no matches)"
  fi
fi
