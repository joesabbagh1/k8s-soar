# k8s-soar service

Python package behind the response layer. One source tree, two images:

| Image | Entrypoint | Runs as | Purpose |
|-------|-----------|---------|---------|
| `k8s-soar-actions` | `soar-actions <step>` | Argo Workflow step pods, SA `soar-responder` | guard → contain → enrich → triage → notify → act |
| `k8s-soar-agent` | `soar-agent` | Deployment `soar-agent`, SA `soar-agent` (read-only) | AI triage over HTTP (`POST /triage`) |

```
src/k8s_soar/
  alert.py      Falco / Alertmanager payload -> Alert
  mitre.py      ATT&CK technique lookup from rule tags
  config.py     env -> Settings (set by the Helm chart)
  context.py    read-only evidence (pod spec, logs, events, Loki, Tetragon)
  verdict.py    AI verdict schema (shared)
  actions/      one module per workflow step + cli.py
  agent/        FastAPI server, triage loop, read-only tools
```

Develop:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[agent,dev]"
pytest && ruff check src tests
```

Run a step against your current kubeconfig (dry-run, nothing is modified):

```bash
SOAR_MODE=dry-run soar-actions --out /tmp/out guard --alert "$(cat tests/fixtures/falco_reverse_shell.json)"
```
