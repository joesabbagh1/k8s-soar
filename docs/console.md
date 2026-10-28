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

The top of the page always answers "where is this case right now":

| State | What you see |
|-------|--------------|
| Awaiting decision | **Your decision**: the AI's verdict and recommendation, the actions as cards (the AI's pick marked), a note and your name. The button names the action and turns red for destructive ones |
| In progress | The step running now, what it is doing, a live timer, and the steps still to come |
| Closed | The outcome: who decided ("Decided by Joe · 12m ago — note", "Decided automatically", or "Argo UI" when resumed there) and the action's result |
| Failed | What failed |

Below it, three tabs:

- **Overview**: what happened (command line as a copyable code block, process, file, user…), the
  AI assessment, and **Response**, every step in order with done / running / waiting / pending /
  skipped states, details and timings.
- **Investigate**: Grafana links (Loki queries on the case's time window), the workload at
  detection time (owner chain, service account, host access, container security context, events).
- **Technical**: kubectl commands, all Falco fields, the raw alert, the case ID.

The console behaves like an app. Links and decisions don't reload the page. Open cases update
in place, every 2.5 s while the response runs and 8 s while a decision is pending, without losing
your scroll position or what you are typing. The theme switch in the menu bar (light / dark,
following the OS until you choose) is remembered per browser.

## One case per pod

A pod under attack usually trips several rules at once (ours and Falco's own). Cases on the same
pod and container within 15 minutes are one group, shown as one row with "+N more alerts":

- The case that quarantined the pod does the work (approval, action). The group is **titled after
  its most specific rule** (rules tagged `soar_specific`), so a miner reads as "Crypto Miner
  Execution" even when a generic rule quarantined the pod first.
- The others are listed under **Also detected on this pod**. A duplicate containment case that was
  skipped shows as "Merged into this case".
- One decision per pod: deciding on any case in the group closes the waiting ones, and a case that
  reaches its approval gate after the decision is closed automatically.
- A pod re-created under the same name (a re-run, a restart) has a new container id and is a new case.

The **Technical** tab has **Where the time went**: detection to containment split into the event
pipeline, the workflow starting, and each step (every workflow step runs as its own pod).

## Decisions

| Option | Effect |
|--------|--------|
| Close, keep quarantined / Close — no action | Nothing changes; a quarantined pod stays isolated for investigation |
| Delete pod | Deletes the pod (its controller already runs a clean replacement when it was quarantined) |
| Scale workload to zero | Scales the pod's Deployment / StatefulSet / ReplicaSet to 0 |
| False positive — release | Only for quarantined pods: removes the quarantine and returns the pod to its controller |

Before running a destructive action, the console asks for confirmation. A decision does
three things:

1. It records the analyst, the time and the optional note as annotations on the case Workflow
   (`k8s-soar.io/decided-by`, `decided-at`, `decision-note`).
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
