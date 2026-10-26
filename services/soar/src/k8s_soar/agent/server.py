"""HTTP API of the soar-agent Deployment.

POST /triage  {alert, context, decision} -> Verdict
GET  /config  provider/model in use (no secrets)
GET  /healthz
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from k8s_soar.alert import Alert
from k8s_soar.config import settings
from k8s_soar.kube import kube
from k8s_soar.verdict import Verdict

from .settings import agent_settings
from .tools import CaseTools
from .triage import run_triage

log = logging.getLogger("k8s_soar.agent")
audit = logging.getLogger("k8s_soar.audit")

app = FastAPI(title="k8s-soar agent", version="0.3.0")


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


@app.post("/triage", response_model=Verdict)
def triage(req: TriageRequest) -> Verdict:
    started = time.monotonic()
    cfg = agent_settings()
    tools = CaseTools(k=kube(), settings=settings(), agent=cfg, namespace=req.alert.namespace or "default")
    try:
        verdict = run_triage(req.alert, req.context, req.decision, tools, cfg)
    except Exception as exc:  # provider outage, auth error, timeout...
        log.exception("triage failed")
        verdict = Verdict.unavailable(f"{type(exc).__name__}: {exc}")
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
                "verdict": verdict.model_dump(),
            }
        )
    )
    return verdict


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))  # noqa: S104


if __name__ == "__main__":
    main()
