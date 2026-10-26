"""Step 4 — ask the soar-agent for a verdict. Never fails the workflow."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from pydantic import ValidationError

from k8s_soar.alert import Alert
from k8s_soar.config import Settings
from k8s_soar.verdict import Verdict

log = logging.getLogger(__name__)

AGENT_TIMEOUT = 120.0


def triage(alert: Alert, context: dict[str, Any], decision: dict[str, Any], settings: Settings) -> Verdict:
    if not settings.agent_url:
        return Verdict.unavailable("AI agent disabled")
    payload = {
        "alert": alert.model_dump(mode="json"),
        "context": context,
        "decision": decision,
    }
    try:
        resp = httpx.post(f"{settings.agent_url}/triage", json=payload, timeout=AGENT_TIMEOUT)
        resp.raise_for_status()
        return Verdict.model_validate(resp.json())
    except (httpx.HTTPError, ValidationError, ValueError) as exc:
        log.warning("agent triage failed: %s", exc)
        return Verdict.unavailable(type(exc).__name__)
