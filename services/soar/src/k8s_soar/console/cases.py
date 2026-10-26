"""Turn a falco-response Workflow into a case an analyst can read.

Pure functions over the Workflow JSON returned by the Argo Server API, so the
mapping is testable without a cluster. Everything taken from the alert or the
evidence is attacker-controlled; the templates render it auto-escaped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from k8s_soar.alert import Alert, parse
from k8s_soar.verdict import Verdict

# Statuses shown in the console, in list order.
AWAITING = "awaiting"
IN_PROGRESS = "in_progress"
CLOSED = "closed"
FAILED = "failed"
SKIPPED = "skipped"

STATUS_LABELS = {
    AWAITING: "Awaiting decision",
    IN_PROGRESS: "In progress",
    CLOSED: "Closed",
    FAILED: "Failed",
    SKIPPED: "Skipped",
}

# Falco output fields worth showing first, with readable names.
FIELD_LABELS = {
    "proc.cmdline": "Command line",
    "proc.name": "Process",
    "proc.exepath": "Executable",
    "proc.pname": "Parent process",
    "proc.pcmdline": "Parent command line",
    "fd.name": "File / connection",
    "user.name": "User",
    "user.uid": "UID",
    "evt.type": "System call",
    "container.name": "Container",
    "container.id": "Container ID",
}

ACTION_LABELS = {
    "none": "Close — no further action",
    "delete-pod": "Delete pod",
    "scale-to-zero": "Scale workload to zero",
    "release-quarantine": "False positive — release",
}

CLOSED_LABELS = {
    "none": "Closed — no action",
    "delete-pod": "Closed — pod deleted",
    "scale-to-zero": "Closed — scaled to zero",
    "release-quarantine": "Closed — false positive",
}

VERDICT_LABELS = {
    "true_positive": "True positive",
    "benign": "Benign",
    "needs_review": "Needs review",
    "unavailable": "Unavailable",
}

_FALCO_PREFIX = re.compile(r"^\S+:\s+(Emergency|Alert|Critical|Error|Warning|Notice|Informational|Debug)\s+", re.I)


def _json(value: str | None) -> Any:
    if not value:
        return None
    try:
        return json.loads(value)
    except ValueError:
        return value


def _time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def ago(when: datetime | None, now: datetime | None = None) -> str:
    if when is None:
        return "—"
    seconds = int(((now or datetime.now(UTC)) - when).total_seconds())
    if seconds < 60:
        return f"{max(seconds, 0)}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


@dataclass
class Step:
    name: str
    phase: str
    started: datetime | None
    finished: datetime | None
    message: str
    outputs: dict[str, str]

    def output(self, name: str) -> Any:
        return _json(self.outputs.get(name))


@dataclass
class Event:
    """One line of the case timeline."""

    when: datetime | None
    title: str
    detail: str = ""
    tone: str = "info"  # info | good | warn | bad


@dataclass
class Choice:
    action: str
    label: str
    description: str
    recommended: bool = False


@dataclass
class Case:
    name: str
    created: datetime | None
    phase: str
    message: str
    alert: Alert | None
    steps: dict[str, Step] = field(default_factory=dict)

    # --- step outputs ---------------------------------------------------
    @property
    def decision(self) -> dict[str, Any]:
        step = self.steps.get("guard")
        value = step.output("decision") if step else None
        return value if isinstance(value, dict) else {}

    @property
    def containment(self) -> dict[str, Any]:
        step = self.steps.get("contain")
        value = step.output("result") if step else None
        return value if isinstance(value, dict) else {}

    @property
    def contained(self) -> bool:
        c = self.containment
        return bool(c) and "latency_seconds" in c and not c.get("dry_run")

    @property
    def pod_state(self) -> str:
        """Short state of the pod for the case list: quarantined / deleted / released / scaled to zero."""
        if not self.contained:
            return ""
        done = self.action_result and self.steps.get("act") and self.steps["act"].phase == "Succeeded"
        return {
            "delete-pod": "deleted",
            "release-quarantine": "released",
            "scale-to-zero": "scaled to zero",
        }.get(self.chosen_action if done else "", "quarantined")

    @property
    def evidence(self) -> dict[str, Any]:
        step = self.steps.get("enrich")
        value = step.output("context") if step else None
        return value if isinstance(value, dict) else {}

    @property
    def verdict(self) -> Verdict | None:
        step = self.steps.get("triage")
        value = step.output("verdict") if step else None
        if not isinstance(value, dict):
            return None
        try:
            return Verdict.model_validate(value)
        except ValueError:
            return None

    @property
    def recommended(self) -> str:
        verdict = self.verdict
        if verdict is None or verdict.verdict == "unavailable":
            return ""
        return verdict.approval_default

    @property
    def notifications(self) -> dict[str, str]:
        step = self.steps.get("notify")
        value = step.output("result") if step else None
        return value if isinstance(value, dict) else {}

    @property
    def chosen_action(self) -> str:
        step = self.steps.get("approve")
        return (step.outputs.get("action") or "") if step and step.phase == "Succeeded" else ""

    @property
    def action_result(self) -> dict[str, Any]:
        step = self.steps.get("act")
        value = step.output("result") if step else None
        return value if isinstance(value, dict) else {}

    # --- what the analyst sees -----------------------------------------
    @property
    def status(self) -> str:
        approve = self.steps.get("approve")
        if self.phase in ("Failed", "Error"):
            return FAILED
        if approve and approve.phase == "Running":
            return AWAITING
        if self.phase in ("Running", "Pending", ""):
            return IN_PROGRESS
        if self.decision.get("action") == "skip":
            return SKIPPED
        return CLOSED

    @property
    def status_label(self) -> str:
        if self.status == CLOSED and self.chosen_action:
            return CLOSED_LABELS.get(self.chosen_action, f"Closed — {self.chosen_action}")
        return STATUS_LABELS[self.status]

    @property
    def awaiting(self) -> bool:
        return self.status == AWAITING

    @property
    def title(self) -> str:
        if not self.alert:
            return self.name
        return re.sub(r"^K8sSoar\s+", "", self.alert.rule)

    @property
    def headline(self) -> str:
        """Falco's one-sentence description, without timestamp, priority and field dump."""
        if not self.alert or not self.alert.output:
            return ""
        text = _FALCO_PREFIX.sub("", self.alert.output.strip())
        return text.split(" (", 1)[0].strip()

    @property
    def severity(self) -> str:
        return self.alert.priority.lower() if self.alert else "warning"

    @property
    def workload(self) -> str:
        if not self.alert:
            return "—"
        if self.alert.pod:
            return f"{self.alert.namespace}/{self.alert.pod}"
        return self.alert.hostname or "host"

    @property
    def owner(self) -> str:
        owners = self.containment.get("owners") or (self.evidence.get("pod") or {}).get("owners") or []
        return owners[-1] if owners else ""

    @property
    def key_fields(self) -> list[tuple[str, str]]:
        if not self.alert:
            return []
        fields = self.alert.fields
        rows = [(label, str(fields[key])) for key, label in FIELD_LABELS.items() if fields.get(key) not in (None, "")]
        return rows

    @property
    def other_fields(self) -> list[tuple[str, str]]:
        if not self.alert:
            return []
        skip = set(FIELD_LABELS) | {"k8s.ns.name", "k8s.pod.name", "container.image.repository", "container.image.tag"}
        return sorted((k, str(v)) for k, v in self.alert.fields.items() if k not in skip and v not in (None, ""))

    @property
    def choices(self) -> list[Choice]:
        owner = self.owner or "its controller"
        options = [
            Choice(
                "none",
                "Close, keep quarantined" if self.contained else "Close — no action",
                "The pod stays network-isolated for investigation until someone deletes it."
                if self.contained
                else "Acknowledge the alert. Nothing changes in the cluster.",
            ),
            Choice(
                "delete-pod",
                "Delete pod",
                "Remove this pod. Anything not yet collected from it is lost"
                + ("; a clean replacement is already running." if self.containment.get("orphaned") else "."),
            ),
            Choice(
                "scale-to-zero",
                "Scale workload to zero",
                f"Stop every replica of {owner}. Use when the image or deployment itself is compromised.",
            ),
        ]
        if self.contained:
            options.append(
                Choice(
                    "release-quarantine",
                    "False positive — release",
                    f"Lift the network quarantine and hand the pod back to {owner}.",
                )
            )
        for choice in options:
            choice.recommended = choice.action == self.recommended
        return options

    @property
    def timeline(self) -> list[Event]:
        events: list[Event] = []
        alert = self.alert
        if alert:
            events.append(Event(alert.time, "Falco detected the activity", self.headline, "bad"))

        guard = self.steps.get("guard")
        if guard and guard.phase == "Succeeded":
            action = self.decision.get("action", "")
            title = {
                "contain": "Routed to automatic containment",
                "notify": "Routed to notification only",
                "skip": "Not handled",
            }.get(action, f"Routed: {action}")
            events.append(Event(guard.finished, title, self.decision.get("reason", "")))
        elif guard and guard.phase in ("Failed", "Error"):
            events.append(Event(guard.finished, "Routing failed", guard.message, "bad"))

        contain = self.steps.get("contain")
        c = self.containment
        if contain and "latency_seconds" in c:
            detail = f"{c['latency_seconds']}s after detection."
            if c.get("orphaned"):
                owners = ", ".join(c.get("owners") or ["its controller"])
                detail += f" Detached from {owners}; a clean replacement is scheduled."
            title = "Would quarantine the pod (dry-run)" if c.get("dry_run") else "Pod quarantined and network-isolated"
            events.append(Event(contain.finished, title, detail, "warn" if c.get("dry_run") else "good"))
        elif contain and "error" in c:
            events.append(Event(contain.finished, "Containment failed", str(c["error"]), "bad"))

        enrich = self.steps.get("enrich")
        if enrich and enrich.phase == "Succeeded":
            ev = self.evidence
            parts = []
            if ev.get("events"):
                parts.append(f"{len(ev['events'])} Kubernetes events")
            if ev.get("logs"):
                parts.append("container logs")
            if ev.get("falco_history"):
                parts.append(f"{len(ev['falco_history'])} related Falco alerts")
            if ev.get("tetragon_events"):
                parts.append(f"{len(ev['tetragon_events'])} Tetragon events")
            events.append(Event(enrich.finished, "Evidence collected", ", ".join(parts) or "pod details"))

        triage = self.steps.get("triage")
        verdict = self.verdict
        if triage and verdict:
            if verdict.verdict == "unavailable":
                events.append(Event(triage.finished, "AI triage not available", verdict.summary))
            else:
                label = VERDICT_LABELS.get(verdict.verdict, verdict.verdict)
                events.append(
                    Event(
                        triage.finished,
                        f"AI verdict: {label} ({round(verdict.confidence * 100)}% confidence)",
                        verdict.summary,
                        "bad" if verdict.verdict == "true_positive" else "info",
                    )
                )

        notify = self.steps.get("notify")
        if notify and notify.phase in ("Succeeded", "Failed", "Error"):
            sent = {k: v for k, v in self.notifications.items() if v != "not configured"}
            if sent:
                detail = ", ".join(f"{k}: {v}" for k, v in sent.items())
                tone = "bad" if any(str(v).startswith("error") for v in sent.values()) else "info"
                events.append(Event(notify.finished, "Notifications sent", detail, tone))
            else:
                events.append(Event(notify.finished, "No notification channels configured", "Slack, Jira, Grafana"))

        approve = self.steps.get("approve")
        if approve and approve.phase == "Running":
            events.append(Event(approve.started, "Waiting for an analyst decision", "", "warn"))
        elif approve and approve.phase == "Succeeded":
            label = ACTION_LABELS.get(self.chosen_action, self.chosen_action or "none")
            events.append(Event(approve.finished, f"Decision: {label}", approve.message))

        act = self.steps.get("act")
        if act and act.phase == "Succeeded":
            events.append(Event(act.finished, "Action executed", str(self.action_result.get("result", "")), "good"))
        elif act and act.phase in ("Failed", "Error"):
            events.append(Event(act.finished, "Action failed", act.message, "bad"))

        if self.phase in ("Failed", "Error") and self.message:
            events.append(Event(None, "Case failed", self.message, "bad"))
        return events


def from_workflow(wf: dict[str, Any]) -> Case:
    meta = wf.get("metadata") or {}
    status = wf.get("status") or {}
    arguments = (wf.get("spec") or {}).get("arguments") or {}
    params = {p.get("name"): p.get("value") for p in arguments.get("parameters") or []}
    alert: Alert | None
    try:
        alert = parse(params.get("alert") or "{}") if params.get("alert") else None
    except (ValueError, TypeError):
        alert = None

    steps: dict[str, Step] = {}
    nodes = sorted((status.get("nodes") or {}).values(), key=lambda n: n.get("startedAt") or "")
    for node in nodes:
        name = node.get("displayName", "")
        if node.get("type") not in ("Pod", "Suspend", "Skipped"):
            continue
        outputs = {p.get("name"): p.get("value", "") for p in (node.get("outputs") or {}).get("parameters") or []}
        steps[name] = Step(
            name=name,
            phase=node.get("phase", ""),
            started=_time(node.get("startedAt")),
            finished=_time(node.get("finishedAt")),
            message=node.get("message", ""),
            outputs=outputs,
        )
    return Case(
        name=meta.get("name", ""),
        created=_time(meta.get("creationTimestamp")),
        phase=status.get("phase", ""),
        message=status.get("message", ""),
        alert=alert,
        steps=steps,
    )


def sort_key(case: Case) -> tuple[int, float]:
    order = [AWAITING, IN_PROGRESS, FAILED, CLOSED, SKIPPED]
    created = case.created.timestamp() if case.created else 0
    return (order.index(case.status), -created)
