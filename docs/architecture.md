# Architecture

## Layers

| Layer | Component | Namespace | What it does in k8s-soar |
|-------|-----------|-----------|--------------------------|
| Bootstrap | Ansible + kubeadm | — | Bare-metal cluster (optional; any cluster works) |
| Install | helmfile | — | All releases, pinned, ordered (`deploy/helmfile.yaml.gotmpl`) |
| Network | Cilium | kube-system | CNI; enforces the quarantine `CiliumClusterwideNetworkPolicy` |
| Prevent | Kyverno | kyverno | Pod Security baseline/restricted, image pinning, limits; protects the quarantine label |
| Detect | Falco | falco | Syscall rules (`charts/k8s-soar/files/falco-rules/`), routed by tags |
| Detect / enforce | Tetragon | kube-system | Kernel observe policies (events → Loki); opt-in SIGKILL enforcement |
| Respond | Argo Events | argo-events (controller), k8s-soar (resources) | Webhook → EventBus → Sensor |
| Respond | Argo Workflows | argo (controller + UI), k8s-soar (cases) | One Workflow per case; UI = case management |
| Respond | soar-actions | k8s-soar | Python steps: guard, contain, enrich, triage, notify, act |
| Triage | soar-agent | k8s-soar | Optional LLM agent, read-only tools, structured verdict |
| Observe | Prometheus, Loki, Promtail, Grafana | monitoring | Findings + Response dashboards, alerts |

## Event flow

```text
Falco ─► falcosidekick ─┬─► Loki                         (every finding ≥ notice: search, dashboards)
                        └─► soar-webhook EventSource     (≥ warning)
Alertmanager ──────────────► soar-webhook EventSource    (severity=critical)
                                 │
                                 ▼
                         EventBus "soar" (NATS JetStream — survives restarts, absorbs bursts)
                                 │
                                 ▼
                         Sensor "soar-router"
                           keeps: tags contain soar_contain|soar_notify, or priority ≥ Critical
                           rate limit: response.rateLimitPerSecond
                                 │
                                 ▼
                         Workflow from WorkflowTemplate "falco-response"  (= one case)
```

## Why these choices

- **Argo instead of Shuffle.** Playbooks are YAML in git (reviewed, versioned, diffable), run as
  native Kubernetes pods with their own ServiceAccount, and the Argo UI gives per-step logs,
  inputs/outputs and a resume button for approvals. No GUI-only state, no bootstrap API calls,
  no port-forwards in the data path.
- **Deterministic containment, AI after.** Quarantine depends only on the Falco rule's tag, so it
  happens in seconds and works with AI disabled or the provider down. The AI only advises; humans
  approve anything destructive.
- **Quarantine keeps the evidence.** The Cilium policy allows ingress from the node so probes
  pass and the container is not restarted, and the pod is detached from its controller so the
  service self-heals with a clean replica while the compromised pod stays for forensics.
- **Single source of truth.** Trusted namespaces, quarantine label and response mode are chart
  values; the Falco list, Kyverno exclusions and step config are generated from them.
- **Least privilege.** Sensor can only create Workflows; responder can patch/delete pods and
  scale workloads but is blocked from trusted namespaces by Kyverno; the agent is read-only and
  its tools are bound to the case's namespace.

## Namespaces

| Namespace | Contents |
|-----------|----------|
| `k8s-soar` | EventBus, EventSource, Sensor, WorkflowTemplate, cases (Workflows), soar-agent |
| `argo`, `argo-events` | Controllers and Argo UI |
| `falco` | Falco DaemonSet, falcosidekick, `k8s-soar-falco-rules` ConfigMap |
| `kyverno` | Kyverno controllers |
| `monitoring` | Prometheus, Alertmanager, Grafana, Loki, Promtail, k8s-soar dashboards |
| `security-lab` | Lab profile only: target for k8s-soar-scenarios |
