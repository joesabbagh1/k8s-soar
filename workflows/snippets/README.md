# Jira ticket body — Shuffle wiring

## Root cause

**Query_Loki is the subflow start node** (`startnode` in Master Responder points at it). In Shuffle, a subflow entry node's result is **not exposed** to downstream nodes — so `$Query_Loki` is never available in `Build_Jira_Body` or `Jira`, even when wired correctly.

Execution variables (`$loki_logs`) also do not reach the remote **Jira app**.

Only **`$exec`** is reliably available everywhere in Observability-Responder.

---

## Recommended setup

```
Query_Loki → Build_Jira_Body → Jira → Grafana_Annotations → Slack_Alert
```

| Node | Configuration |
|---|---|
| **Build_Jira_Body** | Shuffle Tools → Repeat back to me → paste **`build-jira-body.liquid`** into **Call** |
| **Jira Body** | `$Build_Jira_Body` (or `$Build_Jira_Body.call`) — no Liquid, no `$Query_Loki` |

`build-jira-body.liquid` fetches Loki **inline via HTTP** using only `$exec` (pod name). It does not reference `$Query_Loki`.

Query_Loki can stay in the flow for observability; Jira no longer depends on it.

---

## Option without bridge node

Paste **`jira-adf-body.liquid`** directly into **Jira → Body**. Uses `$exec` only; forensics from `$exec.output` (no Loki block).

---

## Optional: fix start-node scoping (advanced)

Add a no-op **Pass_Exec** node (Shuffle Tools → Repeat back to me, call = `$exec`) **before** Query_Loki and change Master Responder **Log to Jira** `startnode` to Pass_Exec's ID. Then Query_Loki is no longer the entry node and `$Query_Loki` may become visible downstream. The inline Loki fetch in `build-jira-body.liquid` avoids needing this.

---

## If `$Build_Jira_Body` does not resolve in Jira

Replace the Jira app with an **HTTP POST** node:

- URL: `https://k8s-soar.atlassian.net/rest/api/3/issue`
- Body: `$Build_Jira_Body`
- Auth: same as current Jira node

Slack link variable becomes `$HTTP.body.key` (match your node label).

---

## Grafana annotations (red markers on dashboard)

Annotations fail to show when **both** of these are missing:

1. **Dashboard** has no annotation layer querying tags `soar` / `security` / `incident`  
   → fixed in `observability/grafana/dashboard-k8s-soar-findings.json` (re-provision dashboard after upgrade)

2. **Grafana_Annotations** POST body lacks `dashboardUID` and `time`  
   → use `workflows/snippets/grafana-annotation-body.json` in the node **Body**

**Grafana_Annotations node** also needs header (already in workflow):

```
Content-Type: application/json
Authorization: Basic YWRtaW46azhzLXNvYXI=
```

(`admin:k8s-soar` base64)

**Verify:** Shuffle execution → Grafana_Annotations → status `200`. Then open **k8s-soar — Falco Findings** — red vertical markers on the timeline.

If `$times` Liquid filter fails, set `"time"` manually via a Build node or use epoch ms from the Jira step timestamp.
