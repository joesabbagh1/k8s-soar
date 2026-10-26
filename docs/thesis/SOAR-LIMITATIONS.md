# SOAR limitations and extensions

## Implemented scope

Detect (Falco, Tetragon) → automated network containment (Cilium) → evidence collection →
optional AI triage → notification (Slack, Jira, Grafana) → human-approved follow-up actions
(delete pod, scale workload to zero, release quarantine). See [response.md](../response.md).

## Limitations

| Limitation | Impact | Mitigation in k8s-soar |
|------------|--------|------------------------|
| Latency | Seconds between syscall and isolation; an attacker can act in that window | Event bus + small step image; time-to-contain is measured on the Response dashboard |
| False positives | Benign activity can quarantine a pod | Rules tuned to tools, not shells in general; trusted namespaces; `dry-run` mode; AI verdict + `release-quarantine` |
| Node-level compromise | Pod quarantine does not isolate a compromised node | Kyverno Pod Security baseline reduces escape paths; Tetragon observes namespace-escape syscalls |
| Data already exfiltrated | Network deny cannot retract data | Tetragon egress events in the case evidence |
| Non-Cilium CNI | Pods are labelled but not isolated | Documented; verify script fails if the policy is missing |
| Admission vs runtime | Kyverno cannot stop already-running pods | Falco/Tetragon cover runtime |
| Pipeline availability | If the EventSource/Sensor is down, no case is opened | JetStream EventBus buffers events; falcosidekick retries; `make status` checks every hop |
| LLM risks | Hallucinated or manipulated verdicts | AI is advisory only, read-only tools, schema-validated output, human approval |
| StatefulSet pods | Cannot be detached from their controller | Quarantined in place; `scale-to-zero` is available |

## Possible extensions

- CRIU checkpoint (`kubectl checkpoint`) of the quarantined container before deletion
- Image digest re-verification (Sigstore/Cosign) before allowing the replacement pod
- Slack interactive approvals (buttons calling the Argo API) in addition to the Argo UI
- Case-level Q&A with the agent (`POST /chat`) from Slack
- Migrate Promtail to Grafana Alloy
