"""Step 2 — network-quarantine the pod and preserve it for forensics.

1. Label the pod with the quarantine label -> the CiliumClusterwideNetworkPolicy
   cuts its traffic (kubelet probes still pass, so the container is not restarted).
2. Optionally orphan it from its ReplicaSet/DaemonSet/Job by removing the
   controller's selector labels. The controller spins up a clean replacement
   (service keeps running), Services stop routing to the compromised pod, and
   the original stays alive as evidence.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from k8s_soar.alert import Alert
from k8s_soar.config import Settings
from k8s_soar.context import OWNER_ANNOTATION, owner_chain
from k8s_soar.kube import ApiException, Kube

log = logging.getLogger(__name__)

ORIGINAL_LABELS_ANNOTATION = "k8s-soar.io/original-labels"
CASE_LABEL = "k8s-soar.io/case"
ORPHANABLE = {"ReplicaSet", "DaemonSet", "Job"}


def _selector_keys(k: Kube, namespace: str, kind: str, name: str) -> set[str]:
    if kind == "ReplicaSet":
        obj = k.apps.read_namespaced_replica_set(name, namespace)
    elif kind == "DaemonSet":
        obj = k.apps.read_namespaced_daemon_set(name, namespace)
    else:
        obj = k.batch.read_namespaced_job(name, namespace)
    selector = obj.spec.selector
    keys = set((selector.match_labels or {}).keys())
    keys.update(expr.key for expr in selector.match_expressions or [])
    return keys


FAST_ANNOTATION = "soar-fast-quarantined-at"  # set by the Sensor's fast path (no dots: it is a patch parameter)


def _fast_quarantine_time(pod) -> datetime | None:
    value = (pod.metadata.annotations or {}).get(FAST_ANNOTATION)
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def contain(alert: Alert, k: Kube, settings: Settings, case_id: str) -> dict[str, Any]:
    now = datetime.now(UTC)
    pod = k.core.read_namespaced_pod(alert.pod, alert.namespace)
    labels = pod.metadata.labels or {}
    # When the Sensor already labelled the pod, containment happened then; this step only finishes the job
    # (case label, detaching the pod from its controller).
    fast_at = _fast_quarantine_time(pod)
    landed = fast_at or now
    latency = max((landed - alert.time).total_seconds(), 0.0)
    chain = owner_chain(k, alert.namespace, pod)

    removed: dict[str, str] = {}
    controller = next((r for r in pod.metadata.owner_references or [] if r.controller), None)
    if settings.orphan_from_controller and controller and controller.kind in ORPHANABLE:
        try:
            keys = _selector_keys(k, alert.namespace, controller.kind, controller.name)
            removed = {key: labels[key] for key in keys if key in labels}
        except ApiException as exc:
            log.warning("could not read %s/%s selector: %s", controller.kind, controller.name, exc.reason)

    patch_labels: dict[str, str | None] = {
        settings.quarantine_label_key: settings.quarantine_label_value,
        CASE_LABEL: case_id[:63],
    }
    patch_labels.update(dict.fromkeys(removed))  # None removes the label
    annotations = {
        "k8s-soar.io/quarantined-at": landed.isoformat(),
        "k8s-soar.io/quarantine-rule": alert.rule,
        OWNER_ANNOTATION: chain[-1] if chain else "",
    }
    if removed:
        annotations[ORIGINAL_LABELS_ANNOTATION] = json.dumps(removed, sort_keys=True)

    result = {
        "pod": f"{alert.namespace}/{alert.pod}",
        "owners": chain,
        "orphaned": bool(removed),
        "removed_labels": sorted(removed),
        "latency_seconds": round(latency, 3),
        "fast": fast_at is not None,
        "dry_run": settings.dry_run,
    }
    if settings.dry_run:
        log.info("dry-run: would patch labels=%s annotations=%s", patch_labels, annotations)
        return result

    k.core.patch_namespaced_pod(
        alert.pod, alert.namespace, {"metadata": {"labels": patch_labels, "annotations": annotations}}
    )
    log.info("quarantined %s/%s in %.2fs after detection", alert.namespace, alert.pod, latency)
    return result
