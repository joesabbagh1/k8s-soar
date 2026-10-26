# Analyst console

The console is where analysts work cases. Argo Workflows still runs every case. The console
reads each case Workflow and shows it as an incident, so nobody has to interpret a step graph.

```bash
make console            # http://<host>:8081  (port-forward on all interfaces;
                        #  CONSOLE_ADDRESS=127.0.0.1 keeps it local)
```

## Case list

Open cases come first, ordered by status: **Awaiting decision**, then **In progress** and
**Failed**. Each row shows the severity, the detection in plain words, the workload, whether
it was quarantined, the AI verdict, and the case's age. The page refreshes every 20 seconds.
The **Closed** and **All** tabs show the cases that are finished.

## Case page

| Section | Content |
|---------|---------|
| Header | Rule, severity, status, and Falco's one-line description of what happened, on which pod and image |
| What happened | Process, command line, parent, file or connection, user, workload and owner, node, MITRE techniques (linked) |
| What k8s-soar did | Timeline: detection → routing decision → quarantine (time to contain, replacement scheduled) → evidence collected → AI verdict → notifications → waiting for decision → decision (who, note) → action result |
| Evidence | Pod as it was at alert time (owner, node, service account, host access, container security flags), Kubernetes events, related Falco alerts, Tetragon kernel events, container logs, all Falco fields, raw alert |
| Your decision | Shown while the case waits. Actions are described in plain words, and the AI recommendation is marked |
| AI triage | Verdict, confidence, summary, evidence, recommended actions, reasoning, model |
| Links | Grafana logs and dashboard (when `integrations.grafanaExternalUrl` is set), Argo case |

## Decisions

| Option | Effect |
|--------|--------|
| Close, keep quarantined / Close — no action | Nothing changes; a quarantined pod stays isolated for investigation |
| Delete pod | Deletes the pod (its controller already runs a clean replacement when it was quarantined) |
| Scale workload to zero | Scales the pod's Deployment / StatefulSet / ReplicaSet to 0 |
| False positive — release | Only for quarantined pods: removes the quarantine and returns the pod to its controller |

Before running a destructive action, the console asks for confirmation. A decision does
three things:

1. It records the analyst and the optional note on the case's `approve` step. They show in the
   timeline and in the Argo UI.
2. It resumes the approval gate through the Argo Server API. These are the same calls
   `argo node set` and `argo resume` make.
3. It logs one audit line: `k8s_soar.audit` `{"event": "decision", ...}` → Loki.

The case's `act` step then runs as `soar-responder`. The console itself never modifies
workloads.

## Identity

- **Default:** the analyst types a name with the first decision. It's kept in a cookie.
  Use this behind `make console` (port-forward), where only people with cluster access can
  reach the UI.
- **Behind an authenticating proxy:** put the console behind oauth2-proxy or your SSO ingress
  and set the header the proxy sends:

  ```yaml
  k8sSoar:
    console:
      userHeader: X-Auth-Request-Email
      externalUrl: https://soar.example.com   # Slack/Jira link to the case page
  ```

  The console then attributes decisions to the authenticated user. Make sure only the proxy
  can reach the Service.

Form posts from other sites are refused, because the `Origin` header must match the host.

## Configuration (`k8sSoar.console`)

| Key | Default | |
|-----|---------|---|
| `enabled` | `true` | |
| `argoServerUrl` | `http://argo-workflows-server.argo.svc.cluster.local:2746` | In-cluster Argo Server |
| `externalUrl` | `""` | Browser URL; enables "Case" links in Slack/Jira |
| `userHeader` | `""` | Identity header from an authenticating proxy |

If Argo Server runs with `authMode: client`, the console sends its own ServiceAccount token.
That account can read and resume Workflows in the `k8s-soar` namespace only.
