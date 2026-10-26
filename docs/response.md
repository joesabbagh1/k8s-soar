# Response playbook

A **case** is one Argo Workflow created from the `falco-response` WorkflowTemplate in the
`k8s-soar` namespace. Watch them with `make argo-ui` (UI) or `make cases` (terminal).

```text
guard ──► case[ contain ─► enrich ─► triage ─► notify ─► review[ approve ─► act ] ]
```

| Step | What it does | Fails the case? |
|------|--------------|-----------------|
| guard | Routes the alert (`contain`, `notify`, `skip`) and atomically claims the pod (annotation `k8s-soar.io/seen-rules`, resourceVersion precondition) | yes |
| contain | Only when guard said `contain`: adds `security.quarantine=true` + `k8s-soar.io/case=<case>`, removes the controller's selector labels (originals saved in `k8s-soar.io/original-labels`), records owner in `k8s-soar.io/owner` | shown red, case continues |
| enrich | Pod spec, owners, events, last logs, NetworkPolicies, Falco history and Tetragon events from Loki | no (best effort) |
| triage | Calls the AI agent; `unavailable` when disabled or failing | no |
| notify | Slack, Jira, Grafana annotation — each only when configured | shown red, case continues |
| approve | Suspends. Resume in the UI and pick an action (default `none`) | — |
| act | `delete-pod`, `scale-to-zero` (owner recorded at containment), `release-quarantine` (restores labels) | yes |

## Guard decisions

| Situation | Decision |
|-----------|----------|
| Rule not tagged `soar_*` and priority below Critical | skip |
| Namespace is trusted | notify (never contained) |
| Event without a pod (host/cluster-level) | notify |
| Pod already quarantined | skip (case already open) |
| Same pod already contained, or same notify rule on same pod, within `dedupMinutes` | skip |
| `soar_contain` rule and mode `contain` or `dry-run` | contain |
| otherwise | notify |

## Modes (`k8sSoar.response.mode`)

| Mode | Behaviour |
|------|-----------|
| `contain` | default; quarantines pods for `soar_contain` rules |
| `notify` | never modifies workloads; everything becomes notify |
| `dry-run` | full pipeline, contain/act only log what they would do — use when onboarding a new cluster |

## Approvals

In the Argo UI open the case → node **approve** → **RESUME** → choose the action. The
description shows the AI recommendation. CLI equivalent:

```bash
argo node set <case> -n k8s-soar --node-field-selector displayName=approve \
  --output-parameter action=delete-pod
argo resume <case> -n k8s-soar --node-field-selector displayName=approve
```

Unanswered approvals expire after `response.activeDeadlineSeconds` (7 days) with no action.
Disable the gate entirely with `k8sSoar.response.approvalGate: false`.

## Lifting a quarantine manually

Only the responder or members of `quarantine.adminGroups` may remove the label (Kyverno
`k8s-soar-protect-quarantine`). Prefer resuming the case with `release-quarantine`, which also
restores the controller labels. Manual equivalent as cluster admin:

```bash
kubectl label pod -n <ns> <pod> security.quarantine- k8s-soar.io/case-
```

## Integrations

Set in `deploy/secrets.env`, then `make secrets` (no redeploy needed — steps read the Secret
at start):

| Variable | Used for |
|----------|----------|
| `SLACK_WEBHOOK_URL` | Slack message with rule, workload, MITRE, response, AI summary, links |
| `JIRA_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` | Jira Cloud issue (ADF description, labels `k8s-soar`, priority, technique IDs) |
| `GRAFANA_API_TOKEN` | Annotations on the k8s-soar dashboards |

Set `k8sSoar.integrations.grafanaExternalUrl` / `argoExternalUrl` in your profile so messages
link back to Grafana and the case.

## Adding a playbook

The pipeline is generic: new behaviour usually means a new Falco rule with the right tag. For
a new kind of action, add a subcommand to `services/soar/src/k8s_soar/actions/`, a template to
`charts/k8s-soar/templates/response/workflowtemplate.yaml`, and the needed verbs to
`templates/response/rbac.yaml`.
