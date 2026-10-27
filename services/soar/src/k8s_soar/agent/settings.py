"""Model/provider configuration for the agent (Helm `ai.*` values -> env)."""

from __future__ import annotations

import os
from functools import lru_cache

from pydantic import BaseModel

# LiteLLM provider prefixes. https://docs.litellm.ai/docs/providers
PROVIDERS = {"anthropic", "openai", "gemini", "azure", "bedrock", "vertex_ai", "ollama", "openrouter", "mistral"}


class AgentSettings(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-sonnet-5-5"
    api_key: str = ""
    base_url: str = ""
    max_tool_calls: int = 8
    max_tokens: int = 2048
    timeout_seconds: float = 60.0
    # Transient provider errors (429, 5xx, timeouts) are retried with backoff,
    # all within budget_seconds per case; then fallback_model is tried, if set.
    max_retries: int = 4
    budget_seconds: float = 240.0
    fallback_model: str = ""
    temperature: float = 0.0
    send_logs: bool = True

    @property
    def litellm_model(self) -> str:
        return self._litellm(self.model)

    @property
    def litellm_fallback(self) -> str:
        return self._litellm(self.fallback_model) if self.fallback_model.strip() else ""

    def _litellm(self, model: str) -> str:
        model = model.strip()
        # Google lists models as "models/gemini-..."; LiteLLM wants the bare ID.
        if model.startswith("models/"):
            model = model.removeprefix("models/")
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
        max_tokens=int(env("AI_MAX_TOKENS", "2048")),
        timeout_seconds=float(env("AI_TIMEOUT_SECONDS", "60")),
        max_retries=int(env("AI_MAX_RETRIES", "4")),
        budget_seconds=float(env("AI_BUDGET_SECONDS", "240")),
        fallback_model=env("AI_FALLBACK_MODEL", "").strip(),
        send_logs=env("AI_SEND_LOGS", "true").lower() == "true",
    )
