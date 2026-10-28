"""HTTP API of the soar-agent Deployment.

POST /triage  {alert, context, decision} -> Verdict
GET  /config  provider/model in use (no secrets)
GET  /healthz
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from k8s_soar.alert import SEVERITY_LEVELS, Alert
from k8s_soar.config import settings
from k8s_soar.kube import kube
from k8s_soar.verdict import Verdict

from .settings import agent_settings
from .tools import CaseTools
from .triage import run_triage

log = logging.getLogger("k8s_soar.agent")
audit = logging.getLogger("k8s_soar.audit")

app = FastAPI(title="k8s-soar agent", version="0.5.1")


class TriageRequest(BaseModel):
    alert: Alert
    context: dict[str, Any] = Field(default_factory=dict)
    decision: dict[str, Any] = Field(default_factory=dict)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config")
def config() -> dict[str, object]:
    return agent_settings().public()


# A pod under attack trips several rules at once and each opens a case. They are one incident, so
# cases on the same pod that arrive close together share a single triage: the first one runs the
# model while the others wait for it, then reuse its verdict (and cost no tokens).
_SHARED: dict[tuple[str, str], tuple[float, str, Verdict]] = {}
_LOCKS: dict[tuple[str, str], threading.Lock] = {}
_REGISTRY = threading.Lock()


def _shared_verdict(key: tuple[str, str], container: str, ttl: float) -> Verdict | None:
    hit = _SHARED.get(key)
    if hit and time.monotonic() - hit[0] < ttl and (not container or not hit[1] or container == hit[1]):
        return hit[2].model_copy(update={"reused": True, "calls": 0, "tokens": 0})
    return None


def _run(req: TriageRequest, cfg) -> Verdict:
    tools = CaseTools(k=kube(), settings=settings(), agent=cfg, namespace=req.alert.namespace or "default")
    try:
        return run_triage(req.alert, req.context, req.decision, tools, cfg)
    except Exception as exc:  # provider outage, auth error, timeout...
        log.exception("triage failed")
        # Name the model actually used: most provider errors are a wrong model or key.
        return Verdict.unavailable(f"model {cfg.litellm_model}: {type(exc).__name__}: {exc}")


@app.post("/triage", response_model=Verdict)
def triage(req: TriageRequest) -> Verdict:
    started = time.monotonic()
    cfg = agent_settings()
    alert = req.alert
    if SEVERITY_LEVELS.index(alert.severity) < SEVERITY_LEVELS.index(
        cfg.min_severity if cfg.min_severity in SEVERITY_LEVELS else "low"
    ):
        verdict = Verdict.unavailable(f"skipped: {alert.severity} alerts are below ai.minSeverity ({cfg.min_severity})")
    elif alert.pod and cfg.share_seconds > 0:
        key, container = (alert.namespace or "", alert.pod), str(alert.fields.get("container.id") or "")
        with _REGISTRY:
            lock = _LOCKS.setdefault(key, threading.Lock())
        with lock:  # same-pod cases queue here; the first pays for the model, the rest reuse its verdict
            verdict = _shared_verdict(key, container, cfg.share_seconds)
            if verdict is None:
                verdict = _run(req, cfg)
                if verdict.verdict != "unavailable":
                    _SHARED[key] = (time.monotonic(), container, verdict)
    else:
        verdict = _run(req, cfg)
    # One JSON line per case -> Promtail -> Loki, for audit and quality review.
    audit.info(
        json.dumps(
            {
                "event": "triage",
                "rule": req.alert.rule,
                "namespace": req.alert.namespace,
                "pod": req.alert.pod,
                "model": cfg.litellm_model,
                "duration_s": round(time.monotonic() - started, 2),
                "calls": verdict.calls,
                "tokens": verdict.tokens,
                "reused": verdict.reused,
                "verdict": verdict.model_dump(),
            }
        )
    )
    return verdict


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # LiteLLM logs every call at INFO; our triage lines and the audit line are enough.
    logging.getLogger("LiteLLM").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").addFilter(lambda r: "/healthz" not in r.getMessage())
    port = int(os.environ.get("PORT", "8080"))
    if os.environ.get("SOAR_DEV_RELOAD") == "true":
        # Dev mode: source mounted from the node (PYTHONPATH); restart on every save.
        uvicorn.run(
            "k8s_soar.agent.server:app",
            host="0.0.0.0",  # noqa: S104
            port=port,
            reload=True,
            reload_dirs=[os.environ.get("PYTHONPATH", ".")],
            reload_includes=["*.py", "*.html"],
        )
        return
    uvicorn.run(app, host="0.0.0.0", port=port)  # noqa: S104


if __name__ == "__main__":
    main()
