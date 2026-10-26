# Validation guide

## Install path

| Step | Command |
|------|---------|
| Prerequisites | `make preflight` |
| Bootstrap cluster + stack | `cd deploy/ansible && ./setup.sh` (or `make deploy` on an existing cluster) |
| Verify components | `make status` |
| End-to-end check | `make smoke-test` |
| Run scenarios (manual) | k8s-soar-scenarios repository, with `make deploy ENV=lab` |

## Checklist

1. `make preflight`
2. Install (see above), starting with `k8sSoar.response.mode: dry-run` on a real cluster
3. `make status` — every hop of detection → response must be green
4. `make smoke-test` — confirms alert → case → quarantine → isolation → replacement
5. Run scenarios **one at a time**; collect evidence with `scripts/lab/capture-scenario-evidence.sh`
6. Record baseline noise in `evidence/baseline/` using the template, tune, then switch to `contain`

## Baseline noise collection

Run the cluster under normal load for 24h in `dry-run` mode before tuning Falco rules.
`make cases` and the k8s-soar — Response dashboard show what would have been contained.
Document alerts in `evidence/baseline/` using [baseline-noise-template.md](./baseline-noise-template.md).
