# Reproducibility Appendix

## Full bare-metal path

```bash
git clone https://github.com/joesabbagh1/k8s-soar.git
cd k8s-soar

cp ansible/inventory.example.ini ansible/inventory.ini
cp ansible/group_vars/all.yml.example ansible/group_vars/all.yml
# Edit inventory and vars for client hardware

./ansible/setup.sh
./scripts/verify-stack.sh
kubectl apply -k policies/
kubectl apply -k lab/
./scripts/load-falco-rules.sh
./scenarios/run-all.sh
```

## Helm-only (kubeadm already done, no CNI)

Use when kubeadm is initialized but Cilium is not yet installed:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo add cilium https://helm.cilium.io/
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update

helm dependency build .

helm install k8s-soar . \
  --namespace k8s-soar --create-namespace \
  --wait --timeout 15m

./scripts/verify-stack.sh
kubectl apply -k policies/
kubectl apply -k lab/
```

## Evidence collection

Store exports under `evidence/` (gitignored):

```text
evidence/
  baseline/YYYY-MM-DD.md
  scenario-01/falco.log
  scenario-01/kyverno-report.yaml
  ...
```

## Version pinning

Record in thesis:

- `k8s-soar` chart version / git SHA
- Kubernetes version (`kubectl version`)
- Ansible `k8s_version` var from `group_vars/all.yml`
