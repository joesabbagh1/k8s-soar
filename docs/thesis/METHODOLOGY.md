# Methodology

## Threat modeling

1. Map 8 scenarios to MITRE ATT&CK (Containers) — see [scenarios/threat-matrix.md](../../scenarios/threat-matrix.md).
2. Assign each scenario to Kyverno (prevent), Falco (detect), Tetragon/Cilium (enforce/isolate).
3. Define expected evidence per tool before running simulations.

## Lab design

- Namespace: `security-lab`
- Victim workload: nginx Deployment with minimal privileges
- Network: default-deny + explicit DNS egress
- Scenarios never run cluster-wide

## Simulation procedure

1. Install stack via `./ansible/setup.sh` (policies, lab, and Falco rules included)
2. Run scenarios
3. Run `./scenarios/NN-name/run.sh`
4. Capture logs within 2 minutes:
   - `kubectl logs -n falco ...`
   - `kubectl get policyreport -A`
   - `kubectl exec -n tetragon ds/tetragon -- tetra getevents -o compact`
5. Record PASS/FAIL in evidence folder

## Policy rollout

1. Kyverno: Audit → validate scenarios → Enforce
2. Falco: load k8s-soar rules scoped to security-lab
3. Tetragon: apply TracingPolicies incrementally
4. SOAR: set `enable_soar: true` in `ansible/group_vars/all.yml` and re-run setup, or `K8S_SOAR_ENABLE_SOAR=1 ./ansible/setup.sh`

## Reproducibility

Document exact versions: Helm chart tag, git commit, inventory vars.
