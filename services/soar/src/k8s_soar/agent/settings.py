"""Model/provider configuration for the agent (Helm `ai.*` values -> env)."""

from __future__ import annotations

import os
from functools import lru_cache

from pydantic import BaseModel

# LiteLLM provider prefixes. https://docs.litellm.ai/docs/providers
PROVIDERS = {
    "anthropic",
    "openai",
    "gemini",
    "azure",
    "bedrock",
    "vertex_ai",
    "ollama",
    "openrouter",
    "mistral",
    "deepseek",
}
# Gateways whose model IDs contain another vendor's name ("deepseek/...:free" on
# OpenRouter): always routed through the gateway, never to that vendor.
GATEWAYS = {"openrouter"}


class AgentSettings(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-sonnet-5-5"
    api_key: str = ""
    base_url: str = ""
    max_tool_calls: int = 8
    max_tokens: int = 4096
    timeout_seconds: float = 120.0
    # Transient provider errors (429, 5xx, timeouts) are retried with backoff,
    # all within budget_seconds per case; then fallback_model is tried, if set.
    max_retries: int = 4
    budget_seconds: float = 360.0
    fallback_model: str = ""
    # None = provider default. Gemini 3 degrades (and can loop) below 1.0.
    temperature: float | None = None
    # "" = provider default, except Gemini/Vertex where triage uses "low" thinking
    # (much faster, plenty for triage). low | medium | high.
    reasoning_effort: str = ""
    send_logs: bool = True

    @property
    def litellm_model(self) -> str:
        return self._litellm(self.model)

    @property
    def effective_reasoning_effort(self) -> str:
        if self.reasoning_effort:
            return self.reasoning_effort
        return "low" if self.provider in ("gemini", "vertex_ai") else ""

    @property
    def litellm_fallback(self) -> str:
        return self._litellm(self.fallback_model) if self.fallback_model.strip() else ""

    def _litellm(self, model: str) -> str:
        model = model.strip()
        # Google lists models as "models/gemini-..."; LiteLLM wants the bare ID.
        if model.startswith("models/"):
            model = model.removeprefix("models/")
        if model.startswith(f"{self.provider}/"):
            return model
        if self.provider in GATEWAYS:
            return f"{self.provider}/{model}"
        if "/" in model and model.split("/", 1)[0] in PROVIDERS:
            return model
        return f"{self.provider}/{model}"

    def public(self) -> dict[str, object]:
        """Safe to expose: never includes the key."""
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url or None,
            "api_key_configured": bool(self.api_key),
            "max_tool_calls": self.max_tool_calls,
            "fallback_model": self.fallback_model or None,
            "max_retries": self.max_retries,
            "budget_seconds": self.budget_seconds,
            "send_logs": self.send_logs,
        }


@lru_cache(maxsize=1)
def agent_settings() -> AgentSettings:
    env = os.environ.get
    return AgentSettings(
        provider=env("AI_PROVIDER", "anthropic").strip(),
        model=env("AI_MODEL", "claude-sonnet-5-5").strip(),
        api_key=env("AI_API_KEY", "").strip(),
        base_url=env("AI_BASE_URL", "").strip(),
        max_tool_calls=int(env("AI_MAX_TOOL_CALLS", "8")),
        max_tokens=int(env("AI_MAX_TOKENS", "4096")),
        timeout_seconds=float(env("AI_TIMEOUT_SECONDS", "120")),
        temperature=float(env("AI_TEMPERATURE")) if env("AI_TEMPERATURE", "").strip() else None,
        reasoning_effort=env("AI_REASONING_EFFORT", "").strip().lower(),
        max_retries=int(env("AI_MAX_RETRIES", "4")),
        budget_seconds=float(env("AI_BUDGET_SECONDS", "360")),
        fallback_model=env("AI_FALLBACK_MODEL", "").strip(),
        send_logs=env("AI_SEND_LOGS", "true").lower() == "true",
    )
