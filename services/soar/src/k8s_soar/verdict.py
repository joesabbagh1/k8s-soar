"""The structured result of AI triage. Shared by the agent (producer) and the workflow (consumer)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

RecommendedAction = Literal["none", "delete-pod", "scale-to-zero", "release-quarantine", "investigate"]


class Verdict(BaseModel):
    verdict: Literal["true_positive", "benign", "needs_review", "unavailable"]
    confidence: float = Field(ge=0, le=1)
    severity: Literal["low", "medium", "high", "critical"]
    summary: str = Field(max_length=2000)
    evidence: list[str] = Field(default_factory=list, max_length=15)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list, max_length=5)
    rationale: str = Field(default="", max_length=2000)
    model: str = ""

    @property
    def approval_default(self) -> str:
        """The action pre-selected at the approval gate. Only workflow-executable actions."""
        for action in self.recommended_actions:
            if action in ("delete-pod", "scale-to-zero", "release-quarantine"):
                return action
        return "none"

    @classmethod
    def unavailable(cls, reason: str) -> Verdict:
        return cls(
            verdict="unavailable",
            confidence=0,
            severity="medium",
            summary=f"AI triage unavailable: {reason}"[:2000],
        )
