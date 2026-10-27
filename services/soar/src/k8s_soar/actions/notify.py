"""Step 5 — tell humans: Slack, Jira, Grafana annotation. Each channel is optional.

Alert content is attacker-controlled. It is only ever placed in JSON string
fields (Slack mrkdwn is escaped), never evaluated.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from k8s_soar import grafana
from k8s_soar.alert import Alert
from k8s_soar.config import Settings
from k8s_soar.verdict import Verdict

log = logging.getLogger(__name__)

ACTION_TEXT = {
    "contain": "Pod network-quarantined automatically",
    "notify": "Notification only (no automatic action)",
    "skip": "Skipped",
}


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def links(alert: Alert, settings: Settings, workflow: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if settings.console_external_url and workflow:
        out["Case"] = f"{settings.console_external_url.rstrip('/')}/cases/{workflow}"
    if settings.argo_external_url and workflow:
        out["Argo case"] = f"{settings.argo_external_url.rstrip('/')}/workflows/k8s-soar/{workflow}"
    if settings.grafana_external_url:
        base = settings.grafana_external_url
        expr = f'{{namespace="falco"}} |= {grafana.logql_string(alert.pod or "K8sSoar")}'
        out["Grafana logs"] = grafana.explore_url(base, expr, alert.time)
        out["Dashboard"] = grafana.dashboard_url(base, "k8s-soar-findings", alert.time)
    return out


def _summary_lines(
    alert: Alert, decision: dict[str, Any], contained: dict[str, Any], verdict: Verdict
) -> list[tuple[str, str]]:
    mitre = ", ".join(f"{t['id']} {t['name']}" for t in alert.mitre) or "—"
    rows = [
        ("Rule", alert.rule),
        ("Priority", alert.priority.upper()),
        ("Workload", f"{alert.namespace}/{alert.pod}" if alert.pod else (alert.hostname or "host")),
        ("Image", alert.image or "—"),
        ("MITRE ATT&CK", mitre),
        ("Response", ACTION_TEXT.get(decision.get("action", ""), decision.get("action", "?"))),
        ("Why", decision.get("reason", "")),
    ]
    if contained:
        rows.append(("Time to contain", f"{contained.get('latency_seconds', '?')}s"))
        if contained.get("orphaned"):
            rows.append(("Controller", "pod detached from controller; a clean replacement was scheduled"))
    if verdict.verdict != "unavailable":
        rows.append(("AI verdict", f"{verdict.verdict} ({verdict.confidence:.0%}, {verdict.severity})"))
        rows.append(("AI recommends", ", ".join(verdict.recommended_actions) or "none"))
    return rows


def slack(
    alert: Alert,
    decision: dict[str, Any],
    contained: dict[str, Any],
    verdict: Verdict,
    settings: Settings,
    workflow: str,
    jira_key: str = "",
) -> bool:
    if not settings.slack_webhook_url:
        return False
    rows = _summary_lines(alert, decision, contained, verdict)
    fields = [{"type": "mrkdwn", "text": f"*{k}*\n{_slack_escape(str(v))[:500]}"} for k, v in rows]
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"🚨 {alert.rule}"[:150]}},
        {"type": "section", "fields": fields[:10]},
        {"type": "section", "text": {"type": "mrkdwn", "text": "```" + _slack_escape(alert.output[:2500]) + "```"}},
    ]
    if verdict.verdict != "unavailable":
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": "*AI summary*\n" + _slack_escape(verdict.summary)}}
        )
    link_items = links(alert, settings, workflow)
    if jira_key and settings.jira_url:
        link_items["Jira " + jira_key] = f"{settings.jira_url}/browse/{jira_key}"
    if link_items:
        text = "  •  ".join(f"<{url}|{name}>" for name, url in link_items.items())
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": text}]})
    resp = httpx.post(
        settings.slack_webhook_url,
        json={"text": alert.short(), "blocks": blocks},
        timeout=settings.http_timeout,
    )
    resp.raise_for_status()
    return True


def _adf_text(text: str, bold: bool = False) -> dict[str, Any]:
    node: dict[str, Any] = {"type": "text", "text": text}
    if bold:
        node["marks"] = [{"type": "strong"}]
    return node


def _adf_link(text: str, href: str) -> dict[str, Any]:
    return {"type": "text", "text": text, "marks": [{"type": "link", "attrs": {"href": href}}]}


def jira_body(
    alert: Alert,
    decision: dict[str, Any],
    contained: dict[str, Any],
    verdict: Verdict,
    settings: Settings,
    workflow: str,
) -> dict[str, Any]:
    rows = _summary_lines(alert, decision, contained, verdict)
    table = {
        "type": "table",
        "content": [
            {
                "type": "tableRow",
                "content": [
                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [_adf_text(k)]}]},
                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [_adf_text(str(v) or "—")]}]},
                ],
            }
            for k, v in rows
        ],
    }
    content: list[dict[str, Any]] = [
        {"type": "heading", "attrs": {"level": 2}, "content": [_adf_text("Detection")]},
        table,
        {"type": "heading", "attrs": {"level": 3}, "content": [_adf_text("Falco output")]},
        {"type": "codeBlock", "content": [_adf_text(alert.output[:5000] or "—")]},
    ]
    if alert.mitre:
        content.append({"type": "heading", "attrs": {"level": 3}, "content": [_adf_text("MITRE ATT&CK")]})
        content.append(
            {
                "type": "bulletList",
                "content": [
                    {
                        "type": "listItem",
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    _adf_link(f"{t['id']} {t['name']}", t["url"]),
                                    _adf_text(f" — {t['tactic']}"),
                                ],
                            }
                        ],
                    }
                    for t in alert.mitre
                ],
            }
        )
    if verdict.verdict != "unavailable":
        content.append({"type": "heading", "attrs": {"level": 3}, "content": [_adf_text("AI triage")]})
        content.append({"type": "paragraph", "content": [_adf_text(verdict.summary)]})
        if verdict.evidence:
            content.append(
                {
                    "type": "bulletList",
                    "content": [
                        {"type": "listItem", "content": [{"type": "paragraph", "content": [_adf_text(e)]}]}
                        for e in verdict.evidence
                    ],
                }
            )
    link_items = links(alert, settings, workflow)
    if link_items:
        content.append({"type": "heading", "attrs": {"level": 3}, "content": [_adf_text("Links")]})
        content.append(
            {
                "type": "paragraph",
                "content": [
                    node
                    for i, (name, url) in enumerate(link_items.items())
                    for node in ([_adf_text("  |  ")] if i else []) + [_adf_link(name, url)]
                ],
            }
        )
    labels = ["k8s-soar", f"priority-{alert.priority}", decision.get("action", "notify")]
    labels += [t["id"].replace(".", "_") for t in alert.mitre]
    return {
        "fields": {
            "project": {"key": settings.jira_project_key},
            "issuetype": {"name": settings.jira_issue_type},
            "summary": alert.short()[:250],
            "labels": labels,
            "description": {"type": "doc", "version": 1, "content": content},
        }
    }


def jira(
    alert: Alert,
    decision: dict[str, Any],
    contained: dict[str, Any],
    verdict: Verdict,
    settings: Settings,
    workflow: str,
) -> str:
    if not (settings.jira_url and settings.jira_api_token and settings.jira_project_key):
        return ""
    resp = httpx.post(
        f"{settings.jira_url}/rest/api/3/issue",
        json=jira_body(alert, decision, contained, verdict, settings, workflow),
        auth=(settings.jira_email, settings.jira_api_token),
        headers={"Accept": "application/json"},
        timeout=settings.http_timeout,
    )
    resp.raise_for_status()
    return resp.json().get("key", "")


def grafana_annotation(alert: Alert, decision: dict[str, Any], settings: Settings) -> bool:
    if not (settings.grafana_url and settings.grafana_api_token):
        return False
    resp = httpx.post(
        f"{settings.grafana_url.rstrip('/')}/api/annotations",
        json={
            "time": int(alert.time.timestamp() * 1000),
            "tags": ["k8s-soar", decision.get("action", "notify"), alert.slug],
            "text": f"{alert.short()} — {ACTION_TEXT.get(decision.get('action', ''), '')}",
        },
        headers={"Authorization": f"Bearer {settings.grafana_api_token}"},
        timeout=settings.http_timeout,
    )
    resp.raise_for_status()
    return True


def notify_all(
    alert: Alert,
    decision: dict[str, Any],
    contained: dict[str, Any],
    verdict: Verdict,
    settings: Settings,
    workflow: str,
) -> dict[str, Any]:
    """Send to every configured channel; one failing channel does not stop the others."""
    result: dict[str, Any] = {}
    jira_key = ""
    try:
        jira_key = jira(alert, decision, contained, verdict, settings, workflow)
        result["jira"] = jira_key or "not configured"
    except httpx.HTTPError as exc:
        result["jira"] = f"error: {exc}"
    for name, send in (
        ("slack", lambda: slack(alert, decision, contained, verdict, settings, workflow, jira_key)),
        ("grafana", lambda: grafana_annotation(alert, decision, settings)),
    ):
        try:
            result[name] = "sent" if send() else "not configured"
        except httpx.HTTPError as exc:
            result[name] = f"error: {exc}"
    log.info("notifications: %s", result)
    return result
