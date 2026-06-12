#!/usr/bin/env bash
# Deprecated wrapper — use render-helm-values.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/render-helm-values.sh" "$@"
