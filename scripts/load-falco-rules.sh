#!/usr/bin/env bash
# Load custom Falco rules into the falco namespace.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
kubectl create configmap k8s-soar-falco-rules -n falco \
  --from-file=k8s-soar_rules.yaml="${SCRIPT_DIR}/../policies/falco/k8s-soar_rules.yaml" \
  --dry-run=client -o yaml | kubectl apply -f -
echo "ConfigMap k8s-soar-falco-rules applied."
echo "Mount or reference this ConfigMap via Falco Helm values (falco.customRules) and restart Falco pods."
