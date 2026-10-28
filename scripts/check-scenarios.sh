#!/usr/bin/env bash
# Keeps scenarios/ honest: every scenario has a README and an executable run.sh,
# and every `K8sSoar ...` rule its README names in backticks exists in the Falco rule files.
# (Rules get renamed; READMEs used to keep pointing at the old names.)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${ROOT}/charts/k8s-soar/files/falco-rules"
fail=0

for dir in "${ROOT}"/scenarios/[0-9][0-9]-*/; do
  name=$(basename "$dir")
  [[ -f "${dir}README.md" ]] || { echo "FAIL ${name}: README.md missing"; fail=1; }
  [[ -x "${dir}run.sh" ]] || { echo "FAIL ${name}: run.sh missing or not executable"; fail=1; }
  [[ -f "${dir}README.md" ]] || continue
  while IFS= read -r rule; do
    if ! grep -rqF -- "- rule: ${rule}" "$RULES"; then
      echo "FAIL ${name}: README names '${rule}', which is not a Falco rule"
      fail=1
    fi
  done < <(grep -hoE '`K8sSoar [^`]+`' "${dir}README.md" | tr -d '`' | sort -u)
done

[[ $fail -eq 0 ]] && echo "scenarios OK"
exit "$fail"
