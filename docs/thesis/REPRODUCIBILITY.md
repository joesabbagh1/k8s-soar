# Reproducibility appendix

## Full bare-metal path

```bash
git clone https://github.com/joesabbagh1/k8s-soar.git
cd k8s-soar/deploy/ansible
./setup.sh --pre-setup-only           # renders inventory.ini and group_vars/all.yml
./setup.sh
cd ../.. && make status && make smoke-test
```

## Existing cluster

```bash
make preflight
make deploy
make status
```

## Evidence collection

Store exports under `evidence/` (gitignored):

```text
evidence/
  baseline/YYYY-MM-DD.md
  scenario-01/falco.log
  scenario-01/case.yaml          # kubectl get workflow -n k8s-soar <case> -o yaml
  scenario-01/kyverno-report.yaml
```

## Version pinning

Every component version is pinned in `deploy/helmfile.yaml.gotmpl`; record:

- k8s-soar git SHA and chart `appVersion`
- Kubernetes version (`kubectl version`)
- `k8s_version` / `k8s_package_version` from `deploy/ansible/group_vars/all.yml`
- AI provider and model if triage was enabled (`GET /config` on soar-agent)
