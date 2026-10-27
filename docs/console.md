# Analyst console

The console is where analysts work cases. Argo Workflows still runs every case. The console
reads each case Workflow and shows it as an incident, so nobody has to interpret a step graph.

```bash
make console            # http://<host>:8081  (port-forward on all interfaces;
                        #  CONSOLE_ADDRESS=127.0.0.1 keeps it local)
```

## Case list

Open cases come first, ordered by status: **Awaiting decision**, then **In progress** and
**Failed**. Cases decided automatically (see [Decisions](response.md#decisions)) close on their
own, for example "Closed — pod deleted (auto)", and the reason is in the timeline. Each row shows the severity, the detection in plain words, the workload, whether
it was quarantined, the AI verdict, and the case's age. The page refreshes every 20 seconds.
The **Closed** and **All** tabs show the cases that are finished.

## Case page

| Section | Content |
|---------|---------|
| Header | Severity, rule, status, Falco's one-line description, then workload, owner, image, detection time, time to contain and ATT&CK technique |
| Activity | The command line (copyable code block), process, parent, file or connection, user, syscall, container, node, rule and technique |
| Response | Timeline with offsets from detection: detection → routing decision → quarantine (time to contain, replacement scheduled) → evidence collected → AI verdict → notifications → waiting for decision → decision (who, note) → action result |
| Investigate in Grafana | Loki queries (shown as code) that open Grafana Explore on the case's time window, from 15 minutes before to 30 minutes after detection: Falco alerts on the pod, container logs, Tetragon kernel activity, and the response steps' logs. There's also a link to the Response dashboard |
| Workload at detection time | Owner chain, service account, node/IP, host access, NetworkPolicies, container security context, Kubernetes events |
| Commands | Ready-to-copy `kubectl` commands for the pod and the case workflow, all Falco fields, and the raw alert |
| Decision required | Shown while the case waits. The confirm button names the action and turns red for destructive ones. Actions are described in plain words, and the AI recommendation is marked |
| AI assessment | Verdict, confidence, summary, evidence, reasoning, model |
| Case | Workflow ID and Grafana base URL |

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

## Grafana links

Logs are not copied into the console. Each case links to Grafana with the query and time range
already filled in. The Grafana URL comes from `k8sSoar.integrations.grafanaExternalUrl`. When
that is empty, the console uses the host you opened it on with port 3000, which matches
`make grafana`: that command also listens on all interfaces.

## Configuration (`k8sSoar.console`)

| Key | Default | |
|-----|---------|---|
| `enabled` | `true` | |
| `argoServerUrl` | `http://argo-workflows-server.argo.svc.cluster.local:2746` | In-cluster Argo Server |
| `externalUrl` | `""` | Browser URL; enables "Case" links in Slack/Jira |
| `userHeader` | `""` | Identity header from an authenticating proxy |

If Argo Server runs with `authMode: client`, the console sends its own ServiceAccount token.
That account can read and resume Workflows in the `k8s-soar` namespace only.
