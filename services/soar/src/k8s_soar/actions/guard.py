"""Step 1 — decide whether this alert opens a case, and what kind.

Dedup is done by atomically recording the alert on the pod itself
(annotation + resourceVersion precondition), so concurrent workflows for the
same burst of Falco events cannot both pass.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from k8s_soar.alert import Alert
from k8s_soar.config import Settings
from k8s_soar.kube import ApiException, Kube, is_conflict, is_not_found

log = logging.getLogger(__name__)

SEEN_ANNOTATION = "k8s-soar.io/seen-rules"
MAX_CLAIM_ATTEMPTS = 3

CONTAIN = "contain"
NOTIFY = "notify"
SKIP = "skip"


@dataclass
class Decision:
    action: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"action": self.action, "reason": self.reason}


def _wanted_action(alert: Alert, settings: Settings) -> Decision | None:
    if not alert.wants_notification and alert.priority_rank < 5:  # below "critical"
        return Decision(SKIP, "rule is not routed to SOAR (no soar_* tag) and priority < critical")
    if alert.namespace in settings.trusted_namespaces:
        return Decision(NOTIFY, f"namespace {alert.namespace} is trusted; never contained")
    if not alert.pod:
        return Decision(NOTIFY, "alert has no pod (host or cluster-level event)")
    return None  # needs the pod to be checked and claimed


def _is_quarantined(pod, settings: Settings) -> bool:
    labels = pod.metadata.labels or {}
    return labels.get(settings.quarantine_label_key) == settings.quarantine_label_value


def decide(alert: Alert, k: Kube, settings: Settings, now: datetime | None = None) -> Decision:
    early = _wanted_action(alert, settings)
    if early is not None:
        return early

    target = CONTAIN if alert.wants_containment and settings.mode != "notify" else NOTIFY
    now = now or datetime.now(UTC)
    window = timedelta(minutes=settings.dedup_minutes)

    for _ in range(MAX_CLAIM_ATTEMPTS):
        try:
            pod = k.core.read_namespaced_pod(alert.pod, alert.namespace)
        except ApiException as exc:
            if is_not_found(exc):
                return Decision(NOTIFY, "pod no longer exists")
            raise

        if _is_quarantined(pod, settings):
            return Decision(SKIP, "pod is already quarantined; case already open")

        annotations = pod.metadata.annotations or {}
        try:
            seen: dict[str, str] = json.loads(annotations.get(SEEN_ANNOTATION, "{}"))
        except json.JSONDecodeError:
            seen = {}
        # All containment rules share one key: one case per compromised pod.
        key = "contain" if target == CONTAIN else alert.slug
        last = seen.get(key)
        if last and now - datetime.fromisoformat(last) < window:
            return Decision(SKIP, f"duplicate of an alert handled at {last} (window {window})")

        seen[key] = now.isoformat()
        body = {
            "metadata": {
                "resourceVersion": pod.metadata.resource_version,
                "annotations": {SEEN_ANNOTATION: json.dumps(seen, sort_keys=True)},
            }
        }
        # Claiming only writes a bookkeeping annotation, so it also runs in dry-run
        # mode to keep duplicate cases down.
        try:
            k.core.patch_namespaced_pod(alert.pod, alert.namespace, body)
            reason = f"claimed pod; rule tagged for {target}"
            if target == NOTIFY and alert.wants_containment:
                reason = "response mode is notify; containment disabled"
            return Decision(target, reason)
        except ApiException as exc:
            if is_not_found(exc):
                return Decision(NOTIFY, "pod no longer exists")
            if is_conflict(exc):
                log.info("pod changed while claiming, retrying")
                continue
            raise
    return Decision(SKIP, "could not claim pod after concurrent updates; another case owns it")
