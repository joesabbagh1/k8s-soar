# Policies-as-Code

Apply after k8s-soar Helm install:

```bash
kubectl apply -k policies/
```

## Contents

| Path | Tool | Mode |
|------|------|------|
| `kyverno/` | Admission policies | Audit (flip to Enforce when ready) |
| `falco/k8s-soar_rules.yaml` | Custom runtime rules | Load via `./scripts/load-falco-rules.sh` |
| `tetragon/` | TracingPolicies | Apply when Tetragon enabled |
| `cilium/quarantine-cnp.yaml` | Quarantine network deny | Requires Cilium |
| `network/quarantine-networkpolicy.yaml` | Fallback quarantine | Standard NetworkPolicy |

## Enforce mode

Edit Kyverno policies: `validationFailureAction: Enforce`

## CI validation

Kyverno CLI and falcoctl validation can be added to GitHub Actions when CLIs are available in runner.
