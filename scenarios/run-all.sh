#!/usr/bin/env bash
# Run all k8s-soar scenarios sequentially (requires lab + policies applied).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for dir in "$ROOT"/[0-9][0-9]-*/; do
  name=$(basename "$dir")
  echo "=== Running scenario: ${name} ==="
  if [[ -x "${dir}/run.sh" ]]; then
    "${dir}/run.sh"
  fi
  sleep 3
done
echo "=== All scenarios triggered — collect Falco/Kyverno evidence ==="
