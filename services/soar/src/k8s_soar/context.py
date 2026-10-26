"""Read-only evidence collection, shared by the `enrich` step and the AI agent tools.

Everything returned here is compact, JSON-serialisable and size-capped so it
fits in an Argo output parameter and an LLM context window.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from k8s_soar.config import Settings
from k8s_soar.kube import ApiException, Kube, is_not_found

MAX_LOG_CHARS = 4000
MAX_LOKI_LINES = 50

# Annotation written by `contain` so later steps can find the original owner
# even after the pod has been orphaned from its ReplicaSet.
OWNER_ANNOTATION = "k8s-soar.io/owner"


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else "...[truncated]...\n" + text[-limit:]


def owner_chain(k: Kube, namespace: str, pod) -> list[str]:
    """Return e.g. ["ReplicaSet/web-5d9c", "Deployment/web"]."""
    chain: list[str] = []
    refs = pod.metadata.owner_references or []
    controller = next((r for r in refs if r.controller), None)
    if controller is None:
        recorded = (pod.metadata.annotations or {}).get(OWNER_ANNOTATION)
        return [recorded] if recorded else []
    chain.append(f"{controller.kind}/{controller.name}")
    if controller.kind == "ReplicaSet":
        try:
            rs = k.apps.read_namespaced_replica_set(controller.name, namespace)
            parent = next((r for r in rs.metadata.owner_references or [] if r.controller), None)
            if parent:
                chain.append(f"{parent.kind}/{parent.name}")
        except ApiException:
            pass
    elif controller.kind == "Job":
        try:
            job = k.batch.read_namespaced_job(controller.name, namespace)
            parent = next((r for r in job.metadata.owner_references or [] if r.controller), None)
            if parent:
                chain.append(f"{parent.kind}/{parent.name}")
        except ApiException:
            pass
    return chain


def pod_summary(k: Kube, namespace: str, name: str) -> dict[str, Any]:
    try:
        pod = k.core.read_namespaced_pod(name, namespace)
    except ApiException as exc:
        if is_not_found(exc):
            return {"found": False}
        raise
    spec = pod.spec
    containers = []
    for c in (spec.containers or []) + (spec.init_containers or []):
        sc = c.security_context
        containers.append(
            {
                "name": c.name,
                "image": c.image,
                "privileged": bool(sc and sc.privileged),
                "run_as_user": sc.run_as_user if sc else None,
                "allow_privilege_escalation": sc.allow_privilege_escalation if sc else None,
                "capabilities_add": (sc.capabilities.add if sc and sc.capabilities else None) or [],
                "read_only_root_fs": sc.read_only_root_filesystem if sc else None,
            }
        )
    host_paths = [v.host_path.path for v in spec.volumes or [] if v.host_path]
    statuses = {s.name: s for s in pod.status.container_statuses or []}
    return {
        "found": True,
        "namespace": namespace,
        "name": name,
        "node": spec.node_name,
        "service_account": spec.service_account_name,
        "automount_sa_token": spec.automount_service_account_token,
        "host_network": bool(spec.host_network),
        "host_pid": bool(spec.host_pid),
        "host_ipc": bool(spec.host_ipc),
        "host_paths": host_paths,
        "phase": pod.status.phase,
        "pod_ip": pod.status.pod_ip,
        "started": pod.status.start_time.isoformat() if pod.status.start_time else None,
        "restarts": {n: s.restart_count for n, s in statuses.items()},
        "labels": pod.metadata.labels or {},
        "owners": owner_chain(k, namespace, pod),
        "containers": containers,
    }


def pod_events(k: Kube, namespace: str, name: str, limit: int = 15) -> list[dict[str, Any]]:
    try:
        events = k.core.list_namespaced_event(
            namespace, field_selector=f"involvedObject.kind=Pod,involvedObject.name={name}"
        )
    except ApiException:
        return []
    items = sorted(
        events.items,
        key=lambda e: (e.last_timestamp or e.event_time or e.metadata.creation_timestamp).isoformat(),
    )
    return [
        {"type": e.type, "reason": e.reason, "message": (e.message or "")[:300], "count": e.count}
        for e in items[-limit:]
    ]


def pod_logs(k: Kube, namespace: str, name: str, container: str | None = None, lines: int = 50) -> str:
    try:
        text = k.core.read_namespaced_pod_log(name, namespace, container=container, tail_lines=lines, timestamps=True)
    except ApiException as exc:
        return f"<logs unavailable: {exc.status} {exc.reason}>"
    return _truncate(text or "", MAX_LOG_CHARS)


def network_policies(k: Kube, namespace: str) -> list[str]:
    try:
        return [p.metadata.name for p in k.networking.list_namespaced_network_policy(namespace).items]
    except ApiException:
        return []


def _logql_string(value: str) -> str:
    return json.dumps(value)  # JSON string escaping is valid LogQL string escaping


def loki_query(settings: Settings, query: str, minutes: int = 60, limit: int = MAX_LOKI_LINES) -> list[str]:
    if not settings.loki_url:
        return []
    now_ns = time.time_ns()
    params = {
        "query": query,
        "start": str(now_ns - minutes * 60 * 10**9),
        "end": str(now_ns),
        "limit": str(limit),
        "direction": "backward",
    }
    try:
        resp = httpx.get(f"{settings.loki_url}/loki/api/v1/query_range", params=params, timeout=settings.http_timeout)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        return [f"<loki unavailable: {exc}>"]
    lines: list[str] = []
    for stream in resp.json().get("data", {}).get("result", []):
        lines.extend(value[1][:600] for value in stream.get("values", []))
    return lines[:limit]


def falco_history(settings: Settings, pod: str, minutes: int = 60) -> list[str]:
    return loki_query(settings, f'{{namespace="falco"}} |= {_logql_string(pod)} |= "rule"', minutes)


def tetragon_events(settings: Settings, namespace: str, pod: str, minutes: int = 15) -> list[str]:
    query = f'{{container="export-stdout"}} |= {_logql_string(pod)} |= {_logql_string(namespace)}'
    return loki_query(settings, query, minutes)


def collect(k: Kube, settings: Settings, namespace: str | None, pod: str | None) -> dict[str, Any]:
    """Everything the `enrich` step attaches to a case."""
    if not (namespace and pod):
        return {"pod": {"found": False}}
    summary = pod_summary(k, namespace, pod)
    ctx: dict[str, Any] = {"pod": summary}
    if summary.get("found"):
        ctx["events"] = pod_events(k, namespace, pod)
        ctx["logs"] = pod_logs(k, namespace, pod, lines=30)
        ctx["network_policies"] = network_policies(k, namespace)
    ctx["falco_history"] = falco_history(settings, pod)[:20]
    ctx["tetragon_events"] = tetragon_events(settings, namespace, pod)[:20]
    return ctx
