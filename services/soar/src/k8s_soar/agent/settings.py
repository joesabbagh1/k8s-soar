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
    temperature: float = 0.0
    send_logs: bool = True

    @property
    def litellm_model(self) -> str:
        if "/" in self.model and self.model.split("/", 1)[0] in PROVIDERS:
            return self.model
        return f"{self.provider}/{self.model}"

    def public(self) -> dict[str, object]:
        """Safe to expose: never includes the key."""
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url or None,
            "api_key_configured": bool(self.api_key),
            "max_tool_calls": self.max_tool_calls,
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
        send_logs=env("AI_SEND_LOGS", "true").lower() == "true",
    )
