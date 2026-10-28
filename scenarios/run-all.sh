#!/usr/bin/env bash
# Optional: run ALL scenarios in sequence (for batch testing only).
# Clears previous scenario pods first, then leaves each new pod up for review.
# make scenario-reset clears them all.
# For demos and thesis evidence, run scenarios individually instead:
#   ./scenarios/01-shell-in-container/run.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../scripts/lab/scenario-lib.sh
source "${ROOT}/../scripts/lab/scenario-lib.sh"

scenario_cleanup_all

for dir in "$ROOT"/[0-9][0-9]-*/; do
  name=$(basename "$dir")
  echo "=== Running scenario: ${name} ==="
  if [[ -x "${dir}/run.sh" ]]; then
    "${dir}/run.sh"
  fi
  sleep 3
done
echo "=== All scenarios triggered — collect Falco/Kyverno evidence ==="
