# Methodology

## Threat modeling

1. Map 8 scenarios to MITRE ATT&CK (Containers) — see [detection-catalog.md](../detection-catalog.md) and [scenarios/threat-matrix.md](../../scenarios/threat-matrix.md).
2. Assign each scenario to Kyverno (prevent), Falco (detect), Tetragon/Cilium (enforce/isolate).
3. Define expected evidence per tool before running simulations.

## Lab design

- Namespace: `security-lab`
- Victim workload: nginx Deployment with minimal privileges
- Network: default-deny + explicit DNS egress
- Scenarios never run cluster-wide

## Simulation procedure

1. Install the stack: `cd deploy/ansible && ./setup.sh` with `k8s_soar_env: lab`, or `make deploy ENV=lab`
2. Run one attack: `make <attack>` (for example `make shell-in-container`; `make help` lists them)
3. Capture logs within 2 minutes:
   - `kubectl logs -n falco ...`
   - `kubectl get policyreport -A`
   - `kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact`
   - `scripts/lab/capture-scenario-evidence.sh` and `make cases`
4. Record PASS/FAIL in evidence folder

## Policy rollout

1. Kyverno: Audit → validate scenarios → Enforce
2. Falco: k8s-soar rules apply to every non-trusted namespace
3. Tetragon: apply TracingPolicies incrementally
4. SOAR: start in `dry-run` mode (`k8sSoar.response.mode`), then `contain`

## Reproducibility

Document exact versions: Helm chart tag, git commit, inventory vars.
