# Response playbook

A **case** is one Argo Workflow created from the `falco-response` WorkflowTemplate in the
`k8s-soar` namespace. Analysts work them in the [console](console.md) (`make console`); the Argo
UI (`make argo-ui`) shows raw step inputs/outputs/logs, and `make cases` lists them in the terminal.

```text
guard ──► case[ contain ─► enrich ─► triage ─► decide ─► notify ─► auto-act | review[ approve ─► act ] ]
```

| Step | What it does | Fails the case? |
|------|--------------|-----------------|
| guard | Routes the alert (`contain`, `notify`, `skip`) and atomically claims the pod (annotation `k8s-soar.io/seen-rules`, resourceVersion precondition) | yes |
| contain | Only when guard said `contain`: adds `security.quarantine=true` + `k8s-soar.io/case=<case>`, removes the controller's selector labels (originals saved in `k8s-soar.io/original-labels`), records owner in `k8s-soar.io/owner` | shown red, case continues |
| enrich | Pod spec, owners, events, last logs, NetworkPolicies, Falco history and Tetragon events from Loki | no (best effort) |
| triage | Calls the AI agent; `unavailable` when disabled or failing | no |
| decide | Per severity: automatic action or analyst approval (see [Decisions](#decisions)). Outputs `route` = `auto`, `human` or `none` | yes |
| notify | Every configured channel (see [Notifications](#notifications)); messages say what happens next | shown red, case continues |
| auto-act | Only when `route=auto` and the action isn't `none`: runs the action without waiting | yes |
| approve | Only when `route=human`: suspends until an analyst decides in the console (default `none`) | — |
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

## Decisions

Per severity level, the admin chooses who decides the follow-up action. Use `./k8s-soar
configure`, or set `k8sSoar.response.decisions` directly. Falco priorities map to levels:
critical/alert/emergency → **critical**, error → **high**, warning → **medium**, notice and
below → **low**.

| Setting | Behaviour |
|---------|-----------|
| `approval: human` | The case waits for an analyst in the console (default for every level) |
| `approval: auto` + `strategy: policy` | Runs the level's `action` right away: `none` (keep quarantined), `delete-pod` or `scale-to-zero` |
| `approval: auto` + `strategy: ai` | Runs the AI's recommended action when its verdict is *true positive* with confidence ≥ `aiMinConfidence`. A benign or unsure verdict, an unavailable AI, or a `release-quarantine` recommendation goes to an analyst |

```yaml
k8sSoar:
  response:
    decisions:
      strategy: policy            # policy | ai
      aiMinConfidence: 0.85       # strategy ai only
      levels:
        critical: { approval: auto,  action: delete-pod }
        high:     { approval: human, action: none }
        medium:   { approval: human, action: none }
        low:      { approval: human, action: none }
```

The `ai` strategy needs AI triage with a key. Without one, `./k8s-soar setup` selects `policy`.
A few safeguards always apply:

- `notify` mode never acts automatically.
- Trusted namespaces are never acted on.
- `release-quarantine` is never automatic.

Automatic cases appear in the console as "Closed — pod deleted (auto)", with the reason in the
timeline.

## Approvals

In the [console](console.md): open the case → **Decision required** → pick an action →
confirm. The page shows the context, and the AI's pick is marked.

Argo UI fallback: open the case → click the **approve** node → **RESUME in the node panel** (not
the toolbar one) → pick the action. CLI equivalent:

```bash
argo node set <case> -n k8s-soar --node-field-selector displayName=approve \
  --output-parameter action=delete-pod
argo resume <case> -n k8s-soar --node-field-selector displayName=approve
```

Unanswered approvals expire after `response.activeDeadlineSeconds` (7 days) with no action.
To skip the gate for a level, set `approval: auto` with `action: none`.

## Lifting a quarantine manually

Only the responder or members of `quarantine.adminGroups` may remove the label (Kyverno
`k8s-soar-protect-quarantine`). Prefer resuming the case with `release-quarantine`, which also
restores the controller labels. Manual equivalent as cluster admin:

```bash
kubectl label pod -n <ns> <pod> security.quarantine- k8s-soar.io/case-
```

## Notifications

Configure with `./k8s-soar configure`, which asks for each value, offers a test message, and
applies the changes. `./k8s-soar test-notify` re-tests all channels. You can also set the
variables in `deploy/secrets.env` and run `make secrets`. No redeploy is needed, because steps
read the Secret when they start.

Every message carries the rule, severity, workload, image, MITRE technique, the automatic
response, the **next step** ("Automatic: delete-pod (…)" or "Waiting for an analyst
decision"), the AI summary, and links to the case and to Grafana.

| Channel | Variables | Format |
|---------|-----------|--------|
| Slack | `SLACK_WEBHOOK_URL` | Block Kit message |
| Microsoft Teams | `TEAMS_WEBHOOK_URL` (Workflows: "Post to a channel when a webhook request is received") | Adaptive Card with link buttons |
| Google Chat | `GOOGLE_CHAT_WEBHOOK_URL` | Card |
| Generic webhook | `WEBHOOK_URL`, optional `WEBHOOK_SECRET` | `POST` JSON `{"event": "case.opened", "case", "alert", "decision", "containment", "route", "verdict", "links"}`; signed with `X-K8s-Soar-Signature: sha256=<HMAC of body>` when a secret is set |
| Email | `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS` (`starttls`/`ssl`/`none`), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO` (comma-separated) | Plain text |
| PagerDuty | `PAGERDUTY_ROUTING_KEY` | Events API v2, one incident per case. Pages from `integrations.pagerdutyMinSeverity` up (default critical) |
| Jira | `JIRA_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` | Jira Cloud issue (labels `k8s-soar`, priority, technique IDs) |
| Grafana | `GRAFANA_API_TOKEN` | Annotation on the k8s-soar dashboards |

Set `k8sSoar.integrations.grafanaExternalUrl` / `argoExternalUrl` in your profile so messages
link back to Grafana and the case.

## Adding a playbook

The pipeline is generic: new behaviour usually means a new Falco rule with the right tag. For
a new kind of action, add a subcommand to `services/soar/src/k8s_soar/actions/`, a template to
`charts/k8s-soar/templates/response/workflowtemplate.yaml`, and the needed verbs to
`templates/response/rbac.yaml`.
