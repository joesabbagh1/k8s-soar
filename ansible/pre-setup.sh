#!/usr/bin/env bash
# Optional: run only the pre-setup phase (packages + config). setup.sh does this automatically.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/setup.sh" --pre-setup-only "$@"
