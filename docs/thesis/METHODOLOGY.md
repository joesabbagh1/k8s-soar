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

1. Install stack and apply policies/lab
2. Load Falco custom rules
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
4. SOAR: set `soar.responder.enabled=true` and `falco.falcosidekick.enabled=true` in values.yaml, then `helm upgrade`

## Reproducibility

Document exact versions: Helm chart tag, git commit, inventory vars.
