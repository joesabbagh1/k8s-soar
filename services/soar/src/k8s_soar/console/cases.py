"""Turn a falco-response Workflow into a case an analyst can read.

Pure functions over the Workflow JSON returned by the Argo Server API, so the
mapping is testable without a cluster. Everything taken from the alert or the
evidence is attacker-controlled; the templates render it auto-escaped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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

STEP_TITLES = {
    "guard": "Route the alert",
    "contain": "Quarantine the pod",
    "enrich": "Collect evidence",
    "triage": "AI triage",
    "decide": "Choose the follow-up",
    "notify": "Notify",
    "approve": "Analyst decision",
    "act": "Run the decided action",
    "follow-up": "Automatic action or analyst decision",
}
STEP_RUNNING = {
    "guard": "Checking the namespace and recent cases, then claiming the pod so no duplicate case opens",
    "contain": "Labelling the pod for the Cilium quarantine policy and detaching it from its controller",
    "enrich": "Reading the pod spec, owners, events and logs, and related Falco and Tetragon activity from Loki",
    "triage": "The AI agent is investigating with read-only tools; busy providers are retried",
    "decide": "Applying the per-severity policy: automatic action or analyst decision",
    "notify": "Sending the case to the configured channels",
    "act": "Running the decided action on the pod",
    "auto-act": "Running the automatic action on the pod",
}
STEP_SKIPPED = {
    "contain": "Not a containment rule; the pod was left running",
    "auto-act": "No action to run",
    "act": "No action chosen",
    "approve": "Not needed",
}
# Annotations the console writes on the Workflow when an analyst decides.
ANN_BY = "k8s-soar.io/decided-by"
ANN_AT = "k8s-soar.io/decided-at"
ANN_NOTE = "k8s-soar.io/decision-note"

CLOSED_LABELS = {
    "none": "Closed — no action",
    "delete-pod": "Closed — pod deleted",
    "scale-to-zero": "Closed — scaled to zero",
    "release-quarantine": "Closed — false positive",
}

# Plain-language verdicts (the schema keeps the security terms).
VERDICT_LABELS = {
    "true_positive": "Real threat",
    "benign": "Not a threat",
    "needs_review": "Needs a human look",
    "unavailable": "Unavailable",
}
VERDICT_EXPLAINED = {
    "true_positive": "The AI thinks this is a real attack or compromise.",
    "benign": "The AI thinks this is expected or harmless activity, a false positive.",
    "needs_review": "The AI couldn't decide from the evidence; an analyst should look.",
    "unavailable": "",
}
VERDICT_TONE = {"true_positive": "bad", "benign": "good", "needs_review": "warn"}

_BARE_FIELD = re.compile(r"\s[\w.]+=")
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


def offset(when: datetime | None, start: datetime | None) -> str:
    """Timeline offset from detection: +0.8s, +12s, +3m 05s, +2h 10m."""
    if when is None or start is None:
        return ""
    seconds = (when - start).total_seconds()
    if seconds < 0:
        return "+0s"
    if seconds < 10:
        return f"+{seconds:.1f}s"
    if seconds < 60:
        return f"+{int(seconds)}s"
    if seconds < 3600:
        return f"+{int(seconds // 60)}m {int(seconds % 60):02d}s"
    return f"+{int(seconds // 3600)}h {int(seconds % 3600 // 60):02d}m"


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
    step: str = ""


@dataclass
class StepView:
    """One row of the response progress: what a step did, or is doing right now."""

    key: str
    title: str
    state: str  # done | running | waiting | pending | skipped | failed
    detail: str = ""
    when: datetime | None = None
    started: datetime | None = None
    tone: str = "info"


@dataclass
class DecisionRecord:
    action: str
    by: str  # analyst name, "automatic", or "Argo UI"
    at: datetime | None
    note: str = ""
    automatic: bool = False


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
    annotations: dict[str, str] = field(default_factory=dict)
    # The most specific case of this case's group (set by attach_related): it names the incident.
    lead: Case | None = None

    @property
    def merged(self) -> bool:
        """Routing and quarantine ran as one step (one pod) rather than guard then contain."""
        return "respond" in self.steps

    @property
    def specific(self) -> bool:
        """The rule names a concrete attack (crypto miner, reverse shell...) rather than generic activity."""
        return bool(self.alert and "soar_specific" in self.alert.tags)

    @property
    def shown(self) -> Case:
        """The case whose rule names the incident: the group's lead if there is one, else this case."""
        return self.lead or self

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
    def timing(self) -> list[tuple[str, float, str]]:
        """Where the time between detection and containment went: (label, seconds, what it covers)."""
        alert, guard, contain = self.alert, self.steps.get("guard"), self.steps.get("contain")

        def gap(label: str, start: datetime | None, end: datetime | None, covers: str) -> None:
            if start and end:
                rows.append((label, max((end - start).total_seconds(), 0.0), covers))

        rows: list[tuple[str, float, str]] = []
        if self.merged and guard:
            gap(
                "Falco to case",
                alert.time if alert else None,
                self.created,
                "Falco, falcosidekick, webhook, event bus, sensor, creating the workflow",
            )
            gap("Case to first step", self.created, guard.started, "the workflow controller starting the first step")
            gap(
                "Route and quarantine",
                guard.started,
                guard.finished,
                "its pod starting, then routing the alert, claiming the pod and labelling it",
            )
            return rows
        gap(
            "Falco to case",
            alert.time if alert else None,
            self.created,
            "Falco, falcosidekick, webhook, event bus, sensor, creating the workflow",
        )
        gap(
            "Case to first step",
            self.created,
            guard.started if guard else None,
            "the workflow controller starting the guard step",
        )
        gap(
            "Guard step",
            guard.started if guard else None,
            guard.finished if guard else None,
            "its pod starting, then routing the alert and claiming the pod",
        )
        gap(
            "Between steps",
            guard.finished if guard else None,
            contain.started if contain else None,
            "the controller starting the contain step",
        )
        gap(
            "Contain step",
            contain.started if contain else None,
            contain.finished if contain else None,
            "its pod starting, then labelling the pod",
        )
        return rows

    @property
    def time_to_contain(self) -> float | None:
        return self.containment.get("latency_seconds") if self.contained else None

    @property
    def commands(self) -> list[str]:
        """kubectl commands to look at this case by hand."""
        out = []
        if self.alert and self.alert.pod and self.alert.namespace:
            target = f"-n {self.alert.namespace} pod/{self.alert.pod}"
            container = f" -c {self.alert.container}" if self.alert.container else ""
            out += [
                f"kubectl describe {target}",
                f"kubectl logs {target}{container} --timestamps --tail=200",
                f"kubectl get {target} -o yaml",
            ]
        out.append(f"kubectl get workflow -n k8s-soar {self.name} -o yaml")
        return out

    @property
    def all_fields_text(self) -> str:
        if not self.alert:
            return ""
        return "\n".join(f"{k} = {v}" for k, v in sorted(self.alert.fields.items()) if v not in (None, ""))

    @property
    def pod_state(self) -> str:
        """Short state of the pod for the case list: quarantined / deleted / released / scaled to zero."""
        if not self.contained:
            return ""
        act = self.act_step
        done = act is not None and act.phase == "Succeeded"
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
    def route(self) -> dict[str, Any]:
        """Output of the decide step: {route: auto|human|none, action, reason}."""
        step = self.steps.get("decide")
        value = step.output("result") if step else None
        return value if isinstance(value, dict) else {}

    @property
    def automatic(self) -> bool:
        return self.route.get("route") == "auto"

    @property
    def chosen_action(self) -> str:
        if self.automatic and self.steps.get("decide") and self.steps["decide"].phase == "Succeeded":
            return self.route.get("action") or "none"
        step = self.steps.get("approve")
        return (step.outputs.get("action") or "") if step and step.phase == "Succeeded" else ""

    @property
    def act_step(self) -> Step | None:
        for name in ("auto-act", "act"):
            step = self.steps.get(name)
            if step and step.phase != "Skipped":
                return step
        return None

    @property
    def action_result(self) -> dict[str, Any]:
        step = self.act_step
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
            label = CLOSED_LABELS.get(self.chosen_action, f"Closed — {self.chosen_action}")
            return label + " (auto)" if self.automatic else label
        return STATUS_LABELS[self.status]

    @property
    def awaiting(self) -> bool:
        return self.status == AWAITING

    @property
    def title(self) -> str:
        shown = self.shown
        if not shown.alert:
            return self.name
        return re.sub(r"^K8sSoar\s+", "", shown.alert.rule)

    @property
    def mitre(self) -> list[dict[str, str]]:
        """Techniques of this case and of the group's lead, lead first."""
        out: list[dict[str, str]] = []
        for case in (self.shown, self):
            for technique in case.alert.mitre if case.alert else []:
                if technique not in out:
                    out.append(technique)
        return out

    @property
    def headline(self) -> str:
        """Falco's one-sentence description, without timestamp, priority and field dump."""
        shown = self.shown
        if not shown.alert or not shown.alert.output:
            return ""
        text = _FALCO_PREFIX.sub("", shown.alert.output.strip())
        # Our rules read "Sentence (field=value ...)"; Falco's own rules read "Sentence | field=value ...".
        text = text.split(" | ", 1)[0].split(" (", 1)[0]
        bare_field = _BARE_FIELD.search(text)
        if bare_field:
            text = text[: bare_field.start()]
        text = text.strip()
        return text if len(text) <= 140 else text[:139].rstrip() + "…"

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

    # --- decision record ------------------------------------------------
    @property
    def decision_record(self) -> DecisionRecord | None:
        """Who decided what, from the console's annotations; automatic and Argo UI decisions too."""
        if not self.chosen_action:
            return None
        if self.automatic:
            decide = self.steps.get("decide")
            return DecisionRecord(
                self.chosen_action,
                "automatic",
                decide.finished if decide else None,
                self.route.get("reason", ""),
                automatic=True,
            )
        a = self.annotations
        approve = self.steps.get("approve")
        if a.get(ANN_BY):
            return DecisionRecord(
                self.chosen_action,
                a[ANN_BY],
                _time(a.get(ANN_AT)) or (approve and approve.finished),
                a.get(ANN_NOTE, ""),
            )
        # Resumed outside the console (Argo UI / argo CLI): Argo only records its own service account.
        return DecisionRecord(self.chosen_action, "Argo UI", approve.finished if approve else None)

    @property
    def decision_note_line(self) -> str:
        record = self.decision_record
        if not record:
            return ""
        who = "automatically" if record.automatic else f"by {record.by}"
        return f"Decided {who}" + (f": {record.note}" if record.note else "")

    # --- progress ---------------------------------------------------------
    @property
    def progress(self) -> list[StepView]:
        """Every response step in order, with what it did or is doing now."""
        events = {e.step: e for e in self.timeline if e.step}
        rows: list[StepView] = []
        if self.alert:
            rows.append(StepView("detect", "Detected by Falco", "done", self.alert.rule, self.alert.time))
        plan = ["guard", "contain", "enrich", "triage", "decide", "notify"]
        route = self.route.get("route")
        if route == "auto":
            plan.append("auto-act")
        elif route == "human":
            plan += ["approve", "act"]
        elif not route:
            plan.append("follow-up")
        still_running = self.phase in ("Running", "Pending", "")
        for key in plan:
            step = self.steps.get(key) if key != "follow-up" else None
            title = STEP_TITLES.get(key, key)
            if key == "auto-act":
                action = self.route.get("action", "none")
                title = "Automatic action: " + ("none, case closed" if action == "none" else action)
            if step is None or step.phase == "Skipped":
                skipped = step is not None or (key in ("auto-act", "act") and not still_running)
                if key == "auto-act" and self.route.get("action") == "none":
                    skipped = True
                rows.append(
                    StepView(
                        key, title, "skipped" if skipped else "pending", STEP_SKIPPED.get(key, "") if skipped else ""
                    )
                )
                continue
            event = events.get("act" if key == "auto-act" else key)
            if step.phase in ("Failed", "Error"):
                rows.append(
                    StepView(
                        key,
                        title,
                        "failed",
                        step.message or (event.detail if event else ""),
                        step.finished,
                        step.started,
                        "bad",
                    )
                )
            elif key == "approve" and step.phase == "Running":
                rows.append(
                    StepView(
                        key,
                        "Analyst decision",
                        "waiting",
                        "Waiting for a decision in the console",
                        None,
                        step.started,
                        "warn",
                    )
                )
            elif step.phase in ("Running", "Pending"):
                doing = STEP_RUNNING.get(key, "")
                if step.phase == "Pending" and step.message:
                    doing = f"Starting: {step.message}"
                rows.append(StepView(key, title, "running", doing, None, step.started))
            elif key == "contain" and self.containment.get("error"):
                rows.append(
                    StepView(key, title, "failed", str(self.containment["error"]), step.finished, step.started, "bad")
                )
            elif key == "contain" and not self.contained and "latency_seconds" not in self.containment:
                rows.append(
                    StepView(
                        key,
                        title,
                        "skipped",
                        self.containment.get("skipped") or STEP_SKIPPED["contain"],
                        step.finished,
                        step.started,
                    )
                )
            else:
                detail = event.detail if event else ""
                done_title = event.title if event else title
                rows.append(
                    StepView(
                        key, done_title, "done", detail, step.finished, step.started, event.tone if event else "info"
                    )
                )
        return rows

    @property
    def current(self) -> StepView | None:
        """The step happening right now (or the decision being waited for)."""
        return next((r for r in self.progress if r.state in ("running", "waiting")), None)

    @property
    def timeline(self) -> list[Event]:
        events: list[Event] = []
        alert = self.alert
        if alert:
            events.append(Event(alert.time, "Detected by Falco", alert.rule, "info", "detect"))

        guard = self.steps.get("guard")
        if guard and guard.phase == "Succeeded":
            action = self.decision.get("action", "")
            title = {
                "contain": "Routed to automatic containment",
                "notify": "Routed to notification only",
                "skip": "Not handled",
            }.get(action, f"Routed: {action}")
            events.append(Event(guard.finished, title, self.decision.get("reason", ""), "info", "guard"))
        elif guard and guard.phase in ("Failed", "Error"):
            events.append(Event(guard.finished, "Routing failed", guard.message, "bad", "guard"))

        contain = self.steps.get("contain")
        c = self.containment
        if contain and "latency_seconds" in c:
            detail = f"{c['latency_seconds']}s after detection."
            if c.get("orphaned"):
                owners = ", ".join(c.get("owners") or ["its controller"])
                detail += f" Detached from {owners}; a clean replacement is scheduled."
            title = "Would quarantine the pod (dry-run)" if c.get("dry_run") else "Pod quarantined and network-isolated"
            events.append(Event(contain.finished, title, detail, "warn" if c.get("dry_run") else "good", "contain"))
        elif contain and "error" in c:
            events.append(Event(contain.finished, "Containment failed", str(c["error"]), "bad", "contain"))

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
            events.append(
                Event(enrich.finished, "Evidence collected", ", ".join(parts) or "pod details", "info", "enrich")
            )

        triage = self.steps.get("triage")
        verdict = self.verdict
        if triage and verdict:
            if verdict.verdict == "unavailable":
                events.append(Event(triage.finished, "AI triage not available", verdict.summary, "info", "triage"))
            else:
                label = VERDICT_LABELS.get(verdict.verdict, verdict.verdict)
                events.append(
                    Event(
                        triage.finished,
                        f"AI verdict: {label} ({round(verdict.confidence * 100)}% sure)",
                        verdict.summary,
                        "bad" if verdict.verdict == "true_positive" else "info",
                        "triage",
                    )
                )

        notify = self.steps.get("notify")
        if notify and notify.phase in ("Succeeded", "Failed", "Error"):
            sent = {k: v for k, v in self.notifications.items() if v != "not configured"}
            if sent:
                detail = ", ".join(f"{k}: {v}" for k, v in sent.items())
                tone = "bad" if any(str(v).startswith("error") for v in sent.values()) else "info"
                events.append(Event(notify.finished, "Notifications sent", detail, tone, "notify"))
            else:
                events.append(Event(notify.finished, "No notification channels configured", "", "info", "notify"))

        decide = self.steps.get("decide")
        route = self.route
        if decide and decide.phase == "Succeeded" and route:
            if route.get("route") == "auto":
                action = route.get("action", "none")
                title = "Automatic response: " + (
                    "no further action" if action == "none" else ACTION_LABELS.get(action, action).lower()
                )
                events.append(Event(decide.finished, title, route.get("reason", ""), "warn", "decide"))
            elif route.get("route") == "human":
                events.append(Event(decide.finished, "Sent to an analyst", route.get("reason", ""), "info", "decide"))

        approve = self.steps.get("approve")
        if approve and approve.phase == "Running":
            events.append(Event(approve.started, "Waiting for an analyst decision", "", "warn", "approve"))
        elif approve and approve.phase == "Succeeded":
            label = ACTION_LABELS.get(self.chosen_action, self.chosen_action or "none")
            events.append(Event(approve.finished, f"Decision: {label}", self.decision_note_line, "info", "approve"))

        act = self.act_step
        if act and act.phase == "Succeeded":
            events.append(
                Event(act.finished, "Action executed", str(self.action_result.get("result", "")), "good", "act")
            )
        elif act and act.phase in ("Failed", "Error"):
            events.append(Event(act.finished, "Action failed", act.message, "bad", "act"))

        far = datetime.max.replace(tzinfo=UTC)
        events.sort(key=lambda e: e.when or far)  # stable: same-second events keep step order
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
        if node.get("type") == "Skipped" and name in steps:
            continue  # never let a skipped branch hide the step that ran
        outputs = {p.get("name"): p.get("value", "") for p in (node.get("outputs") or {}).get("parameters") or []}
        steps[name] = Step(
            name=name,
            phase=node.get("phase", ""),
            started=_time(node.get("startedAt")),
            finished=_time(node.get("finishedAt")),
            message=node.get("message", ""),
            outputs=outputs,
        )
    if "respond" in steps:
        # Newer cases route and quarantine in one step. Expose it under the two names the rest of
        # the console reads (guard: the decision, contain: the quarantine result).
        both = steps["respond"]
        steps["guard"] = Step("guard", both.phase, both.started, both.finished, both.message, dict(both.outputs))
        result = both.outputs.get("contained", "")
        steps["contain"] = Step(
            "contain",
            both.phase,
            both.started,
            both.finished,
            both.message,
            {"result": result} if result not in ("", "{}") else {},
        )
    return Case(
        name=meta.get("name", ""),
        created=_time(meta.get("creationTimestamp")),
        phase=status.get("phase", ""),
        message=status.get("message", ""),
        alert=alert,
        steps=steps,
        annotations=meta.get("annotations") or {},
    )


GROUP_WINDOW = timedelta(minutes=15)


def _container_id(case: Case) -> str:
    return str(case.alert.fields.get("container.id") or "") if case.alert else ""


def _same_incident(group: list[Case], case: Case) -> bool:
    """Same pod, close in time, and not provably a different container.

    A pod re-created under the same name (a re-run, a restart) has a new container id and
    is a new incident. Cases from rules that don't report a container id match any group.
    """
    if case.created - group[-1].created > GROUP_WINDOW:
        return False
    seen = {_container_id(c) for c in group} - {""}
    cid = _container_id(case)
    return not cid or not seen or cid in seen


def group_cases(all_cases: list[Case]) -> list[list[Case]]:
    """Cases on the same pod and container, close in time, as groups of 2+; the primary is first.

    The primary is the case routed to containment (known as soon as its first step ends, so it
    doesn't change later), else the first case that was handled, else the first one.
    """
    by_workload: dict[str, list[Case]] = {}
    for case in all_cases:
        if case.alert and case.alert.pod and case.created:
            by_workload.setdefault(case.workload, []).append(case)
    out: list[list[Case]] = []
    for items in by_workload.values():
        items.sort(key=lambda c: c.created)
        groups: list[list[Case]] = []
        for case in items:
            home = next((g for g in reversed(groups) if _same_incident(g, case)), None)
            if home is None:
                groups.append([case])
            else:
                home.append(case)
        for group in groups:
            if len(group) < 2:
                continue
            primary = (
                next((c for c in group if c.contained or c.decision.get("action") == "contain"), None)
                or next((c for c in group if c.status != SKIPPED), None)
                or group[0]
            )
            out.append([primary] + [c for c in group if c is not primary])
    return out


def group_mates(name: str, all_cases: list[Case]) -> list[Case]:
    """The other cases in the group that case `name` belongs to."""
    for group in group_cases(all_cases):
        if any(c.name == name for c in group):
            return [c for c in group if c.name != name]
    return []


def attach_related(all_cases: list[Case]) -> tuple[dict[str, list[Case]], set[str]]:
    """One case per pod: {primary name: [other cases, oldest first]} and the hidden case names.

    A case waiting for a decision is only listed on its own when its primary has finished
    without a decision to make (closed, failed, skipped): then nothing else would ever show it.
    While the primary is still running or waiting, the primary's decision closes it.
    """
    related: dict[str, list[Case]] = {}
    attached: set[str] = set()
    for case in all_cases:
        case.lead = None
    for primary, *members in group_cases(all_cases):
        # Name the incident after the most specific rule in the group, even when a generic rule
        # won the race to quarantine the pod (that one still does the work).
        lead = next((c for c in [primary, *members] if c.specific), None)
        if lead is not None and lead is not primary:
            primary.lead = lead
        for case in members:
            if case.awaiting and primary.status in (CLOSED, FAILED, SKIPPED):
                continue
            related.setdefault(primary.name, []).append(case)
            attached.add(case.name)
    for items in related.values():
        items.sort(key=lambda c: c.created)
    return related, attached


def sort_key(case: Case) -> tuple[int, float]:
    order = [AWAITING, IN_PROGRESS, FAILED, CLOSED, SKIPPED]
    created = case.created.timestamp() if case.created else 0
    return (order.index(case.status), -created)
