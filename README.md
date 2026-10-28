# k8s-soar

> Kubernetes runtime **detection → automated containment → AI-assisted triage → analyst-approved or automatic response**.
> Falco + Tetragon + Kyverno + Cilium, orchestrated by Argo Events/Workflows, with an optional LLM triage agent (bring your own provider).

[![CI](https://github.com/joesabbagh1/k8s-soar/actions/workflows/ci.yml/badge.svg)](https://github.com/joesabbagh1/k8s-soar/actions/workflows/ci.yml)

---

## What happens when an attack is detected

```mermaid
flowchart LR
  subgraph Detect
    F[Falco<br/>syscall rules] --> SK[falcosidekick]
    T[Tetragon<br/>kernel events] --> PT[Promtail]
    K[Kyverno<br/>admission] -.PolicyReports.-> G
  end
  SK -->|all findings| L[(Loki)]
  PT --> L
  SK -->|soar_* tagged + Critical| ES[Argo EventSource<br/>webhook]
  AM[Alertmanager] -->|critical| ES
  ES --> EB[(EventBus<br/>JetStream)] --> S[Sensor<br/>filter + rate limit]
  S --> W

  subgraph W[Case = one Argo Workflow]
    direction TB
    g[1 guard<br/>route + dedup] --> c[2 contain<br/>quarantine label<br/>+ detach pod] --> e[3 enrich<br/>pod, logs, events,<br/>Falco + Tetragon history]
    e --> a[4 triage<br/>AI verdict] --> n[5 notify<br/>Slack, Jira, Grafana] --> ap[6 approve<br/>analyst picks action] --> x[7 act<br/>delete / scale 0 / release]
  end
  UI[soar-console<br/>case page + decision] -->|read + resume<br/>Argo Server API| W

  c -->|label| CNP[Cilium quarantine<br/>policy]
  a <-->|read-only tools| AG[soar-agent<br/>LiteLLM: Anthropic, OpenAI,<br/>Gemini, Bedrock, Ollama...]
  L --> G[Grafana]
```

Concretely, for `kubectl exec` into a pod followed by `cat /var/run/secrets/.../token`:

1. **Falco** matches `K8sSoar Service Account Token Read By Shell Tool` (tags `soar_contain`, `T1552.007`).
2. **falcosidekick** posts the JSON event to the in-cluster webhook; the **Sensor** opens a case: a Workflow named `k8ssoar-service-account-token-read-by-shell-tool-xxxxx`, labelled with the namespace and pod.
3. **guard** checks the namespace isn't a platform namespace, the pod isn't already quarantined, and the same alert wasn't handled in the last 10 minutes (atomic claim on the pod).
4. **contain** labels the pod `security.quarantine=true` → the Cilium policy cuts all its traffic (kubelet probes still pass, so the process stays alive for forensics), and removes its ReplicaSet selector labels → the Deployment schedules a clean replacement and Services stop routing to it. Typical time-to-contain: a few seconds.
5. **enrich** collects pod spec, owner chain, events, recent logs, other Falco alerts and Tetragon events for that pod.
6. **triage** (optional) asks the AI agent for a verdict: `true_positive | benign | needs_review`, confidence, evidence and recommended next action.
7. **notify** posts to Slack, opens a Jira issue (MITRE mapping, evidence, AI summary, links) and annotates Grafana — each only if configured.
8. **decide** applies the per-severity setting. **Automatic** levels run the configured action (or the AI's pick, above a confidence threshold) right away. **Analyst** levels pause the case. In the **console** (`make console`), an analyst sees what happened, what k8s-soar already did, the evidence and the AI verdict, then picks **Delete pod**, **Scale to zero**, **False positive — release** or **Close**. By default every level waits for an analyst; automatic actions happen only where you enabled them.

The console is the analyst view ([docs](docs/console.md)). Argo's UI (`make argo-ui`) still shows each step's raw inputs, outputs and logs for debugging, and `make cases` lists cases in the terminal.

## Quick start

**Guided setup** (Ubuntu 22.04+, kernel ≥ 5.10, or any cluster in your kubeconfig):

```bash
./k8s-soar setup      # asks: cluster, response mode, AI, analyst vs automatic per severity,
                      # notification channels (Slack, Teams, Google Chat, webhook, email,
                      # PagerDuty, Jira) with test messages; then installs
./k8s-soar configure  # change any of it later
```

**Bare metal, non-interactive:** `cd deploy/ansible && ./setup.sh` (kubeadm cluster + full stack).

**Existing cluster** (no CNI yet, or already Cilium — see [operations](docs/operations.md)):

```bash
make preflight                         # tools + cluster checks
cp deploy/secrets.env.example deploy/secrets.env   # optional: Slack, Jira, AI key
make deploy                            # helmfile apply
make status                            # health check
make smoke-test                        # trigger a rule, verify containment end to end
make console                           # review and decide cases
```

**Turn on AI triage:**

```yaml
# deploy/profiles/default.yaml
k8sSoar:
  ai:
    enabled: true
    provider: anthropic        # anthropic | openai | gemini | azure | bedrock | ollama | ...
    model: claude-sonnet-5-5
```

```bash
make ai-key KEY=<your provider key> && make deploy
```

## Repository layout

```text
deploy/
  ansible/              kubeadm bootstrap (cluster only) → then runs helmfile
  helmfile.yaml.gotmpl  every Helm release, pinned versions, install order
  profiles/             the settings you change (default.yaml, lab.yaml)
  values/               per-component Helm values (Cilium, Falco, Argo, ...)
charts/k8s-soar/        k8s-soar's own resources
  files/falco-rules/    detection rules by MITRE tactic
  templates/detection/  Kyverno + Tetragon policies, Falco rules ConfigMap
  templates/response/   quarantine policy, Argo EventSource/Sensor/WorkflowTemplate, RBAC
  templates/console/    analyst console
  templates/agent/      AI triage agent
services/soar/          Python: workflow steps (soar-actions), console (soar-console), AI agent (soar-agent)
scenarios/              attack simulations (`make <attack>` after `make deploy`)
scripts/                verify, smoke test, secrets, preflight, lab helpers
docs/                   architecture, detection catalog, response, AI agent, operations
```

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | components, data flow, design decisions |
| [Detection catalog](docs/detection-catalog.md) | every rule/policy, MITRE mapping, response, known false positives |
| [Response playbook](docs/response.md) | the case workflow, modes, approvals, integrations |
| [Analyst console](docs/console.md) | case list, case page, decisions, identity |
| [AI agent](docs/ai-agent.md) | providers, configuration, safety model |
| [Operations](docs/operations.md) | install paths, upgrades, tuning, troubleshooting |
| [Thesis](docs/thesis/) | methodology, reproducibility, limitations |

Attack scenarios live in `scenarios/` ([how to run and verify them](docs/scenarios.md): `make verify-attack`, and an optional demo customer app, `make demo-app`). They run in the `default` namespace. `make <attack>` runs one (for example `make shell-in-container`). `make help` lists them.

## License

MIT
