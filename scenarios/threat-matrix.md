# k8s-soar Threat Matrix

Maps core thesis scenarios to MITRE ATT&CK (Containers), tooling, and evidence.

| ID | Scenario | MITRE ATT&CK | Kyverno (prevent) | Falco (detect) | Tetragon / Cilium (enforce) |
|----|----------|--------------|-------------------|----------------|-----------------------------|
| 01 | Shell in victim container | T1059 Execution | — | K8sSoar Shell In Victim Container | — |
| 02 | Privileged pod / hostPath | T1611 Escape to Host | disallow-privileged, disallow-host-path | Default Falco rules | — |
| 03 | SA token / credential read | T1552 Credential Access | restrict-sa-automount | K8sSoar Sensitive Credential Access | — |
| 04 | Reverse shell outbound | T1059 Execution | — | K8sSoar Reverse Shell Outbound | detect-reverse-shell |
| 05 | Crypto miner process | T1496 Resource Hijacking | disallow-latest-tag | K8sSoar Crypto Miner Process | quarantine isolate |
| 06 | Missing security context / :latest | Best practice | require-non-root, disallow-latest-tag | — | — |
| 07 | Lateral movement pod-to-pod | T1021 Lateral Movement | default-deny NetworkPolicy | Connection rules / Hubble | quarantine CNP |
| 08 | Sensitive host path write | T1611 Escape to Host | disallow-host-path | Write rules | block-sensitive-writes |

## Policy modes

- Kyverno policies ship in **Audit** mode. Flip to `Enforce` after baseline validation.
- Falco custom rules target `security-lab` namespace only to limit noise.
- **Tetragon enforce policies** use pod label `scenario: "NN"` so scenarios do not affect each other (e.g. scenario 08 blocks writes only on `scenario=08` pods).
- Quarantine label `security.quarantine=true` triggers network isolation (SOAR Phase 5).
- Run `./scripts/reset-scenario-lab.sh` to delete scenario pods and clear victim quarantine between demos.

## Scenario runbooks

Each scenario directory contains `README.md` (steps + expected evidence) and `run.sh` (manual trigger — run one scenario at a time for demos).

## References

- [MITRE ATT&CK — Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Kyverno Policy Library](https://kyverno.io/policies/)
- [Tetragon TracingPolicy examples](https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy)
- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) (optional extended scenarios)
