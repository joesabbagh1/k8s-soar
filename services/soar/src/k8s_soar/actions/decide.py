"""Step 5 — who decides the follow-up action: an analyst, or k8s-soar automatically.

Configured per severity level (critical / high / medium / low) at setup time:

  approval: human   the case waits at the approval gate (console or Argo UI)
  approval: auto    k8s-soar acts on its own, using the strategy:
                      policy  the level's fixed action (delete-pod, scale-to-zero, none)
                      ai      the AI's recommended action when the verdict is a true
                              positive with confidence >= aiMinConfidence; anything
                              else (benign, unsure, AI down) goes to a human

Outputs route = auto | human | none, plus the action and a one-line reason that
the console and notifications show.
"""

from __future__ import annotations

import json
import os
from typing import Any, Literal

from pydantic import BaseModel, Field

from k8s_soar.alert import SEVERITY_LEVELS, Alert
from k8s_soar.config import Settings
from k8s_soar.verdict import Verdict

HUMAN = "human"
AUTO = "auto"
NONE = "none"
AUTO_ACTIONS = ("none", "delete-pod", "scale-to-zero")


class LevelPolicy(BaseModel):
    approval: Literal["human", "auto"] = "human"
    # Action when approval is auto and strategy is policy.
    action: Literal["none", "delete-pod", "scale-to-zero"] = "none"


class DecisionConfig(BaseModel):
    strategy: Literal["policy", "ai"] = "policy"
    ai_min_confidence: float = Field(default=0.85, ge=0, le=1, alias="aiMinConfidence")
    levels: dict[str, LevelPolicy] = Field(default_factory=lambda: {lvl: LevelPolicy() for lvl in SEVERITY_LEVELS})

    model_config = {"populate_by_name": True}

    def level(self, name: str) -> LevelPolicy:
        return self.levels.get(name) or LevelPolicy()


def load_config(raw: str | None = None) -> DecisionConfig:
    raw = os.environ.get("SOAR_DECISIONS", "") if raw is None else raw
    return DecisionConfig.model_validate(json.loads(raw)) if raw.strip() else DecisionConfig()


def _route(route: str, action: str, reason: str) -> dict[str, str]:
    return {"route": route, "action": action, "reason": reason}


def decide(alert: Alert, verdict: Verdict | None, settings: Settings, cfg: DecisionConfig) -> dict[str, str]:
    if not alert.pod:
        return _route(NONE, "none", "no pod to act on (host or cluster-level event)")
    if alert.namespace in settings.trusted_namespaces:
        return _route(NONE, "none", f"namespace {alert.namespace} is trusted; k8s-soar never acts there")
    if settings.mode == "notify":
        return _route(HUMAN, "none", "response mode is notify: no automatic actions")

    level = cfg.level(alert.severity)
    if level.approval == HUMAN:
        return _route(HUMAN, "none", f"{alert.severity} alerts need an analyst decision")

    if cfg.strategy == "policy":
        return _route(AUTO, level.action, f"automatic policy for {alert.severity} alerts: {level.action}")

    # strategy == "ai"
    if verdict is None or verdict.verdict == "unavailable":
        return _route(HUMAN, "none", "AI verdict unavailable; sent to an analyst")
    pct, need = round(verdict.confidence * 100), round(cfg.ai_min_confidence * 100)
    if verdict.verdict != "true_positive":
        return _route(HUMAN, "none", f"AI says {verdict.verdict.replace('_', ' ')} ({pct}%); sent to an analyst")
    if verdict.confidence < cfg.ai_min_confidence:
        return _route(HUMAN, "none", f"AI confidence {pct}% is below the {need}% threshold; sent to an analyst")
    action = verdict.approval_default
    if action not in AUTO_ACTIONS:
        return _route(HUMAN, "none", f"AI recommends {action}; only an analyst may do that")
    return _route(AUTO, action, f"AI: true positive at {pct}% (threshold {need}%), recommends {action}")


def describe(route: dict[str, Any]) -> str:
    """One line for notifications: what happens next."""
    if route.get("route") == AUTO:
        action = route.get("action", "none")
        return "Automatic: " + ("no further action" if action == "none" else action) + f" ({route.get('reason', '')})"
    if route.get("route") == HUMAN:
        return "Waiting for an analyst decision"
    return "No follow-up action"
