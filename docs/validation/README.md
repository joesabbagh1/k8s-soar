# Validation Guide

Procedures for validating k8s-soar after bare-metal bootstrap.

## Install path

| Step | Command |
|------|---------|
| Bootstrap cluster + stack | `./ansible/setup.sh` |
| Verify components | `./scripts/verify-stack.sh` |
| Apply policies | `kubectl apply -k policies/` |
| Deploy lab | `kubectl apply -k lab/` |
| Run scenarios | `./scenarios/run-all.sh` |

## Checklist

1. `./scripts/preflight.sh` — optional, before manual Helm install on existing kubeadm cluster
2. `./ansible/setup.sh` — full bare-metal path
3. `./scripts/verify-stack.sh` — post-install
4. `kubectl apply -k policies/ && kubectl apply -k lab/`
5. `./scripts/load-falco-rules.sh`
6. `./scenarios/run-all.sh`
7. Record baseline noise in `evidence/baseline/` using the template

## Baseline noise collection

Run the cluster under normal load for 24h before tuning Falco rules. Document alerts in `evidence/baseline/` using [baseline-noise-template.md](./baseline-noise-template.md).
