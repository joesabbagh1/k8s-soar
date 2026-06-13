#!/usr/bin/env bash
# Render per-component Helm values (split install avoids 1MB release Secret limit).
# Usage: render-helm-values.sh [ignored-output-path]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

python3 "${SCRIPT_DIR}/render_stack_values.py" "$ROOT_DIR"
