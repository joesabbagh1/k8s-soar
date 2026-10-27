"""Deep links into Grafana (Explore on Loki, k8s-soar dashboards), scoped to a case's time window.

Used by the console and by Slack/Jira notifications, so an analyst lands on
exactly the logs of the attacked pod around the time of the alert.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta

LOKI_UID = "loki"  # datasource uid set in deploy/values/kube-prometheus-stack.yaml.gotmpl
BEFORE = timedelta(minutes=15)
AFTER = timedelta(minutes=30)


def logql_string(value: str) -> str:
    return json.dumps(value)  # JSON string escaping is valid LogQL string escaping


def window(at: datetime) -> tuple[int, int]:
    """Epoch milliseconds from 15 minutes before to 30 minutes after `at`."""
    return int((at - BEFORE).timestamp() * 1000), int((at + AFTER).timestamp() * 1000)


def explore_url(base: str, expr: str, at: datetime) -> str:
    start, end = window(at)
    panes = {
        "k8s-soar": {
            "datasource": LOKI_UID,
            "queries": [
                {
                    "refId": "A",
                    "expr": expr,
                    "queryType": "range",
                    "editorMode": "code",
                    "datasource": {"type": "loki", "uid": LOKI_UID},
                }
            ],
            "range": {"from": str(start), "to": str(end)},
        }
    }
    query = urllib.parse.urlencode({"schemaVersion": "1", "orgId": "1", "panes": json.dumps(panes)})
    return f"{base.rstrip('/')}/explore?{query}"


def dashboard_url(base: str, uid: str, at: datetime) -> str:
    start, end = window(at)
    return f"{base.rstrip('/')}/d/{uid}?orgId=1&from={start}&to={end}"


@dataclass(frozen=True)
class LogLink:
    title: str
    description: str
    expr: str
    url: str


def case_log_links(base: str, at: datetime, namespace: str | None, pod: str | None, case: str = "") -> list[LogLink]:
    """The Loki queries an analyst needs for a case, each opening Explore on the case's time window."""
    queries: list[tuple[str, str, str]] = []
    if pod:
        queries.append(
            (
                "Falco alerts on this pod",
                "Every Falco finding for the pod, not only the one that opened this case.",
                f'{{namespace="falco"}} |= {logql_string(pod)}',
            )
        )
        queries.append(
            (
                "Container logs",
                "What the application printed before and after the alert.",
                f"{{namespace={logql_string(namespace or '')}, pod={logql_string(pod)}}}",
            )
        )
        queries.append(
            (
                "Kernel activity (Tetragon)",
                "Process executions, network connections and sensitive file access.",
                f'{{container="export-stdout"}} |= {logql_string(pod)}',
            )
        )
    if case:
        queries.append(
            (
                "Response steps",
                "Logs of every k8s-soar step that ran for this case.",
                f'{{namespace="k8s-soar", pod=~{logql_string(case + "-.*")}}}',
            )
        )
    return [LogLink(title, desc, expr, explore_url(base, expr, at)) for title, desc, expr in queries]
