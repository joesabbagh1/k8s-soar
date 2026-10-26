#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Reset scenario pods and victim quarantine labels between demos.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scenario-lib.sh
source "${SCRIPT_DIR}/scenario-lib.sh"

echo ">>> Cleaning scenario workloads in ${SCENARIO_NS}..."
scenario_cleanup_all
echo ">>> Lab reset complete (victim deployment unchanged)."
