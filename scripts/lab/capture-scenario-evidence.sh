#!/usr/bin/env bash
# Print Falco / Sidekick evidence after running a scenario.
set -euo pipefail

SINCE="${1:-3m}"
PATTERN="${2:-k8s-soar|Shell spawned|scenario-01}"

echo ">>> Falco (stdout, last ${SINCE}):"
falco_logs="$(kubectl logs -n falco -l app.kubernetes.io/name=falco --since="$SINCE" 2>/dev/null || true)"
if [[ -z "$falco_logs" ]]; then
  echo "    (no logs — is Falco running?)"
elif echo "$falco_logs" | grep -iE 'please make sure to install them|error.*plugin' >/dev/null; then
  echo "    (Falco plugins missing — check falcoctl-artifact-install logs: kubectl logs -n falco -l app.kubernetes.io/name=falco -c falcoctl-artifact-install)"
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
    echo "$sidekick_logs" | grep -iE "${PATTERN}|webhook|Shell spawned|K8sSoar|quarantined|status:ok" || echo "    (no matches)"
  fi
fi

echo ">>> k8s-soar cases (most recent last):"
kubectl get workflows -n k8s-soar --sort-by=.metadata.creationTimestamp \
  -o custom-columns='CASE:.metadata.name,RULE:.metadata.labels.k8s-soar\.io/rule,POD:.metadata.labels.k8s-soar\.io/pod,STATUS:.status.phase,STARTED:.status.startedAt' \
  2>/dev/null | tail -15 || echo "    (none)"

echo ">>> Quarantined pods:"
kubectl get pods -A -l security.quarantine=true 2>/dev/null || echo "    (none)"
