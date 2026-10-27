"""Normalised alert model.

Every field in here comes from the monitored workload (command lines, file
names, pod names) and must be treated as attacker-controlled data: never
interpolate it into code, shell commands or LLM instructions.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from k8s_soar.mitre import techniques_from_tags

CONTAIN_TAG = "soar_contain"
NOTIFY_TAG = "soar_notify"

PRIORITY_ORDER = [
    "debug",
    "informational",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
]


# The four levels decisions are configured on (see actions/decide.py).
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]


def severity_level(priority: str) -> str:
    """critical/alert/emergency -> critical, error -> high, warning -> medium, the rest -> low."""
    try:
        rank = PRIORITY_ORDER.index(priority.lower())
    except ValueError:
        rank = PRIORITY_ORDER.index("warning")
    if rank >= PRIORITY_ORDER.index("critical"):
        return "critical"
    if rank == PRIORITY_ORDER.index("error"):
        return "high"
    if rank == PRIORITY_ORDER.index("warning"):
        return "medium"
    return "low"


class Alert(BaseModel):
    source: str = "falco"
    rule: str
    priority: str = "warning"
    output: str = ""
    time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tags: list[str] = Field(default_factory=list)
    namespace: str | None = None
    pod: str | None = None
    container: str | None = None
    image: str | None = None
    hostname: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)

    @property
    def wants_containment(self) -> bool:
        return CONTAIN_TAG in self.tags

    @property
    def wants_notification(self) -> bool:
        return NOTIFY_TAG in self.tags or self.wants_containment

    @property
    def priority_rank(self) -> int:
        try:
            return PRIORITY_ORDER.index(self.priority.lower())
        except ValueError:
            return PRIORITY_ORDER.index("warning")

    @property
    def severity(self) -> str:
        return severity_level(self.priority)

    @property
    def mitre(self) -> list[dict[str, str]]:
        return techniques_from_tags(self.tags)

    @property
    def slug(self) -> str:
        return re.sub(r"[^a-z0-9]+", "-", self.rule.lower()).strip("-")[:50]

    def short(self) -> str:
        where = f"{self.namespace}/{self.pod}" if self.pod else (self.hostname or "host")
        return f"[{self.priority.upper()}] {self.rule} on {where}"


def _parse_time(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            # Falco emits nanosecond precision; fromisoformat accepts at most microseconds.
            trimmed = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
            return datetime.fromisoformat(trimmed)
        except ValueError:
            pass
    return datetime.now(UTC)


def from_falco(payload: dict[str, Any]) -> Alert:
    fields = payload.get("output_fields") or {}
    image = fields.get("container.image.repository")
    if image and fields.get("container.image.tag"):
        image = f"{image}:{fields['container.image.tag']}"
    return Alert(
        source="falco",
        rule=payload.get("rule", "unknown"),
        priority=str(payload.get("priority", "warning")).lower(),
        output=payload.get("output", ""),
        time=_parse_time(payload.get("time")),
        tags=list(payload.get("tags") or []),
        namespace=fields.get("k8s.ns.name") or None,
        pod=fields.get("k8s.pod.name") or None,
        container=fields.get("container.name") or None,
        image=image,
        hostname=payload.get("hostname"),
        fields=fields,
    )


def from_alertmanager(payload: dict[str, Any]) -> list[Alert]:
    alerts = []
    for item in payload.get("alerts", []):
        labels = item.get("labels") or {}
        annotations = item.get("annotations") or {}
        alerts.append(
            Alert(
                source="alertmanager",
                rule=labels.get("alertname", "unknown"),
                priority=labels.get("severity", "warning").lower(),
                output=annotations.get("description") or annotations.get("summary", ""),
                time=_parse_time(item.get("startsAt")),
                tags=[NOTIFY_TAG, f"status_{item.get('status', 'firing')}"],
                namespace=labels.get("namespace"),
                pod=labels.get("pod"),
                fields=labels,
            )
        )
    return alerts


def parse(raw: str | dict[str, Any]) -> Alert:
    """Parse a Falco event or the first alert of an Alertmanager notification."""
    payload = json.loads(raw) if isinstance(raw, str) else raw
    if "alerts" in payload and "rule" not in payload:
        parsed = from_alertmanager(payload)
        if not parsed:
            raise ValueError("alertmanager payload contains no alerts")
        return parsed[0]
    return from_falco(payload)
