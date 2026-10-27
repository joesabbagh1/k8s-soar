# AI triage agent

`soar-agent` is a small FastAPI service (`services/soar/src/k8s_soar/agent/`) deployed in the
`k8s-soar` namespace when `k8sSoar.ai.enabled: true`. The case workflow's **triage** step sends
it the alert and collected evidence; it investigates with read-only tools and returns a
structured verdict that is shown in Slack, Jira and at the approval gate.

## Choosing a provider and model

Provider calls go through [LiteLLM](https://docs.litellm.ai/docs/providers), so any provider it
supports works. Configure in `deploy/profiles/default.yaml`:

```yaml
k8sSoar:
  ai:
    enabled: true
    provider: anthropic            # see table
    model: claude-sonnet-5-5
    baseUrl: ""                    # only for self-hosted / proxies
    extraEnv: []                   # provider-specific settings
```

| Provider | `provider` | `model` example | Key | Notes |
|----------|-----------|-----------------|-----|-------|
| Anthropic | `anthropic` | `claude-sonnet-5-5`, `claude-opus-5-5`, `claude-haiku-4-5-20251001` | `make ai-key KEY=sk-ant-...` | |
| OpenAI | `openai` | `gpt-...` | `make ai-key KEY=sk-...` | |
| Google Gemini | `gemini` | `gemini-...` | API key | |
| Azure OpenAI | `azure` | `<deployment name>` | API key | `baseUrl: https://<res>.openai.azure.com`, `extraEnv: [{name: AZURE_API_VERSION, value: ...}]` |
| AWS Bedrock | `bedrock` | `anthropic.claude-...` | — | IAM via IRSA/instance role + `AWS_REGION_NAME` in `extraEnv` |
| Ollama (local) | `ollama` | `llama3.1`, `qwen2.5` | none | `baseUrl: http://ollama.<ns>:11434`; model must support tool calling |
| OpenRouter / Mistral / Vertex | `openrouter` / `mistral` / `vertex_ai` | | | |

Then:

```bash
make ai-key KEY=<key>      # stores Secret k8s-soar/soar-ai, restarts the agent
make deploy-soar           # applies ai.* changes
kubectl -n k8s-soar port-forward svc/soar-agent 8080 & curl -s localhost:8080/config
```

`GET /config` shows the provider/model in use and whether a key is configured (never the key).

## What the agent can do

Tools (all read-only, all bound to **the case's namespace** — the model cannot choose another):

| Tool | Data |
|------|------|
| `get_pod`, `list_pods` | spec summary: images, security context, host access, owners |
| `get_pod_logs` | last N lines (disable with `ai.sendLogs: false`) |
| `get_pod_events` | Kubernetes events |
| `falco_history` | other Falco alerts for the pod (Loki) |
| `tetragon_events` | kernel exec/connect/file events (Loki) |
| `list_network_policies` | NetworkPolicies in the namespace |
| `mitre_lookup` | technique name/tactic |
| `submit_verdict` | final answer (schema-validated) |

Verdict schema (`services/soar/src/k8s_soar/verdict.py`):
`verdict` (`true_positive | benign | needs_review | unavailable`), `confidence` 0–1, `severity`,
`summary`, `evidence[]`, `recommended_actions[]` from
`none | delete-pod | scale-to-zero | release-quarantine | investigate`.

## Safety model

- **Advisory by default.** The agent has no write RBAC, and containment never depends on it.
  At the approval gate its recommendation is only marked: the analyst chooses, and the default
  is `none`. The exception is a severity level set to `approval: auto` with `strategy: ai`.
  There, the workflow (not the agent) runs the recommended `delete-pod` or `scale-to-zero` when
  the verdict is *true positive* above `aiMinConfidence`. Anything else goes to an analyst, and
  `release-quarantine` is never automatic. See [Decisions](response.md#decisions).
- **Prompt injection.** Alert fields, logs and tool results are attacker-controlled. They are
  fenced as `<untrusted_data>`, the system prompt instructs the model never to follow
  instructions found in data, tools are namespace-bound, and the output is a fixed schema
  with an enum of actions.
- **Data leaving the cluster.** Alert payloads, pod metadata and (unless `sendLogs: false`) log
  lines are sent to the provider. Use a self-hosted model (Ollama, vLLM behind `baseUrl`) when
  that is not acceptable.
- **Cost and latency bounds.** `maxToolCalls` (default 8), `maxTokens` per call, `timeoutSeconds`.
  On the last allowed call the model is forced to submit a verdict.
- **Failure is harmless.** Provider errors, timeouts or invalid output yield
  `verdict: unavailable`; the case continues.
- **Audit.** Every triage is logged as one JSON line (`k8s_soar.audit`) → Loki, and the AI
  verdict panel on the k8s-soar — Response dashboard summarises them.

## Developing

```bash
cd services/soar && python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[agent,dev]" && pytest
AI_PROVIDER=anthropic AI_MODEL=claude-sonnet-5-5 AI_API_KEY=... soar-agent   # uses your kubeconfig
```
