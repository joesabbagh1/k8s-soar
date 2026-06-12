# Validation Guide

Procedures for validating k8s-soar after bare-metal bootstrap.

## Install path

| Step | Command |
|------|---------|
| Bootstrap cluster + stack | `./ansible/setup.sh` |
| Verify components | `./scripts/verify-stack.sh` |
| Run scenarios (manual) | `./scenarios/01-shell-in-container/run.sh` etc. |

## Checklist

1. `./scripts/preflight.sh` — optional, before manual Helm install on existing kubeadm cluster
2. `./ansible/setup.sh` — full bare-metal path
3. `./scripts/verify-stack.sh` — post-install
4. When ready, run scenarios **one at a time** (see `scenarios/threat-matrix.md`)
7. Record baseline noise in `evidence/baseline/` using the template

## Baseline noise collection

Run the cluster under normal load for 24h before tuning Falco rules. Document alerts in `evidence/baseline/` using [baseline-noise-template.md](./baseline-noise-template.md).
