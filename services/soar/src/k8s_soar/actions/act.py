"""Step 6 — actions an analyst approved at the workflow's approval gate."""

from __future__ import annotations

import json
import logging
from typing import Any

from k8s_soar.config import Settings
from k8s_soar.context import OWNER_ANNOTATION
from k8s_soar.kube import ApiException, Kube, is_not_found

from .contain import CASE_LABEL, ORIGINAL_LABELS_ANNOTATION

log = logging.getLogger(__name__)

NONE = "none"
DELETE_POD = "delete-pod"
SCALE_TO_ZERO = "scale-to-zero"
RELEASE = "release-quarantine"
ACTIONS = (NONE, DELETE_POD, SCALE_TO_ZERO, RELEASE)

SCALABLE = {"Deployment", "StatefulSet", "ReplicaSet"}


def _delete_pod(k: Kube, namespace: str, pod: str) -> str:
    k.core.delete_namespaced_pod(pod, namespace)
    return f"deleted pod {namespace}/{pod}"


def _scale_to_zero(k: Kube, namespace: str, pod: str) -> str:
    obj = k.core.read_namespaced_pod(pod, namespace)
    owner = (obj.metadata.annotations or {}).get(OWNER_ANNOTATION, "")
    kind, _, name = owner.partition("/")
    if kind not in SCALABLE or not name:
        return f"owner '{owner or 'none'}' is not scalable; nothing done"
    body = {"spec": {"replicas": 0}}
    if kind == "Deployment":
        k.apps.patch_namespaced_deployment_scale(name, namespace, body)
    elif kind == "StatefulSet":
        k.apps.patch_namespaced_stateful_set_scale(name, namespace, body)
    else:
        k.apps.patch_namespaced_replica_set_scale(name, namespace, body)
    return f"scaled {kind}/{name} to 0 replicas"


def _release(k: Kube, namespace: str, pod: str, settings: Settings) -> str:
    obj = k.core.read_namespaced_pod(pod, namespace)
    annotations = obj.metadata.annotations or {}
    labels: dict[str, str | None] = {settings.quarantine_label_key: None, CASE_LABEL: None}
    restored = json.loads(annotations.get(ORIGINAL_LABELS_ANNOTATION, "{}"))
    labels.update(restored)
    k.core.patch_namespaced_pod(
        pod,
        namespace,
        {
            "metadata": {
                "labels": labels,
                "annotations": {ORIGINAL_LABELS_ANNOTATION: None, "k8s-soar.io/released": "true"},
            }
        },
    )
    note = " and restored controller labels (controller will reconcile replicas)" if restored else ""
    return f"released {namespace}/{pod} from quarantine{note}"


def run(action: str, namespace: str, pod: str, k: Kube, settings: Settings) -> dict[str, Any]:
    if action not in ACTIONS:
        raise ValueError(f"unknown action {action!r}; expected one of {ACTIONS}")
    if action == NONE:
        return {"action": action, "result": "no action approved"}
    if namespace in settings.trusted_namespaces:
        raise PermissionError(f"refusing to act on trusted namespace {namespace}")
    if settings.dry_run:
        return {"action": action, "result": f"dry-run: would {action} {namespace}/{pod}"}
    try:
        if action == DELETE_POD:
            result = _delete_pod(k, namespace, pod)
        elif action == SCALE_TO_ZERO:
            result = _scale_to_zero(k, namespace, pod)
        else:
            result = _release(k, namespace, pod, settings)
    except ApiException as exc:
        if is_not_found(exc):
            result = f"{namespace}/{pod} no longer exists"
        else:
            raise
    log.info(result)
    return {"action": action, "result": result}
