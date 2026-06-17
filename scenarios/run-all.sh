#!/usr/bin/env bash
# Optional: run ALL scenarios in sequence (for batch testing only).
# Each scenario uses its own labeled pods; cleanup runs between scenarios.
# For demos and thesis evidence, run scenarios individually instead:
#   ./scenarios/01-shell-in-container/run.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/scenario-lib.sh
source "${ROOT}/../scripts/scenario-lib.sh"

scenario_cleanup_all

for dir in "$ROOT"/[0-9][0-9]-*/; do
  name=$(basename "$dir")
  echo "=== Running scenario: ${name} ==="
  if [[ -x "${dir}/run.sh" ]]; then
    "${dir}/run.sh"
  fi
  scenario_cleanup_all
  sleep 3
done
echo "=== All scenarios triggered — collect Falco/Kyverno evidence ==="
