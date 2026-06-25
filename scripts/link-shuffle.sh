#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <SHUFFLE_WEBHOOK_URL>"
  echo "Example: $0 http://10.10.10.10:3001/api/v1/hooks/webhook_12345"
  exit 1
fi

WEBHOOK_URL="$1"

echo ">>> Updating falcosidekick webhook in values.yaml..."
cd "$ROOT_DIR"

# Safely replace the falcosidekick webhook address using awk
awk -v url="$WEBHOOK_URL" '
  /falcosidekick:/{in_falco=1}
  in_falco && /webhook:/{in_webhook=1}
  in_webhook && /address:/{
    sub(/address: ".+"/, "address: \"" url "\"")
    in_webhook=0
    in_falco=0
  }
  1
' values.yaml > values.yaml.tmp && mv values.yaml.tmp values.yaml

echo ">>> Regenerating Helm values..."
"${SCRIPT_DIR}/render-helm-values.sh"

FALCO_VER="$(grep -A2 "name: falco" "${ROOT_DIR}/Chart.lock" | grep 'version:' | awk '{print $2}')"
GENERATED_DIR="${ROOT_DIR}/.generated"

echo ">>> Upgrading Falco to apply the new webhook..."
helm upgrade falco "${ROOT_DIR}/charts/falco-${FALCO_VER}.tgz" \
  --namespace falco \
  -f "${GENERATED_DIR}/falco-values.yaml"

echo ">>> Success! Falco alerts will now be routed to: $WEBHOOK_URL"
