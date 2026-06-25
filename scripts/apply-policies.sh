#!/usr/bin/env bash
# Apply policy manifests after Helm CRDs are ready.
# Kept out of the Helm release to avoid the 1MB release Secret size limit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo ">>> Applying Kyverno, Tetragon, and quarantine policies..."
kubectl apply -k "${ROOT_DIR}/policies"

echo ">>> Policies applied."
