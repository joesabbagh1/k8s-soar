# Policies-as-Code

Kyverno, Tetragon, and quarantine policies are **applied automatically** when you install via `./ansible/setup.sh` or `./scripts/helm-install.sh` (`scripts/apply-policies-lab.sh` runs after Helm).

Falco rules in `falco/` are loaded via the Helm values overlay (not `kubectl apply`).

## Manual update (optional)

To push policy changes without reinstalling the chart:

```bash
kubectl apply -k policies/
```

## Enforce mode

Kyverno policies ship in **Audit** mode. To block violations, edit policies:

```yaml
validationFailureAction: Enforce
```

Then re-apply or upgrade the Helm release.
