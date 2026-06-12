#!/usr/bin/env bash
# Render Helm values overlay: Falco custom rules + optional SOAR toggles.
# Usage: render-helm-values.sh [output-file]
# Env:
#   K8S_SOAR_ENABLE_SOAR=1  — enable SOAR responder and falcosidekick webhook
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="${1:-${ROOT_DIR}/.generated/helm-values.yaml}"
RULES_FILE="${ROOT_DIR}/policies/falco/k8s-soar_rules.yaml"

if [[ ! -f "$RULES_FILE" ]]; then
  echo "ERROR: rules file not found: $RULES_FILE" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

{
  echo "falco:"
  echo "  customRules:"
  echo "    k8s-soar_rules.yaml: |"
  sed 's/^/      /' "$RULES_FILE"
  if [[ "${K8S_SOAR_ENABLE_SOAR:-0}" == "1" ]]; then
    echo "  falcosidekick:"
    echo "    enabled: true"
  fi

  if [[ "${K8S_SOAR_ENABLE_SOAR:-0}" == "1" ]]; then
    cat <<'EOF'

soar:
  responder:
    enabled: true
EOF
  fi
} > "$OUTPUT"
