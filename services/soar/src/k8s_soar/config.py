"""Runtime settings, read from environment variables set by the Helm chart."""

from __future__ import annotations

import os
from functools import lru_cache

from pydantic import BaseModel


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in _env(name, default).split(",") if item.strip()]


class Settings(BaseModel):
    # contain: quarantine + notify | notify: never touch workloads | dry-run: log what would happen
    mode: str = "contain"
    quarantine_label_key: str = "security.quarantine"
    quarantine_label_value: str = "true"
    orphan_from_controller: bool = True
    trusted_namespaces: list[str] = []
    dedup_minutes: int = 10
    agent_url: str = ""
    agent_timeout: float = 300.0
    loki_url: str = ""
    grafana_url: str = ""
    grafana_external_url: str = ""
    grafana_api_token: str = ""
    argo_external_url: str = ""
    console_external_url: str = ""
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    google_chat_webhook_url: str = ""
    webhook_url: str = ""
    webhook_secret: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_tls: str = "starttls"  # starttls | ssl | none
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: list[str] = []
    pagerduty_routing_key: str = ""
    pagerduty_min_severity: str = "critical"
    jira_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""
    jira_issue_type: str = "Task"
    http_timeout: float = 10.0

    @property
    def dry_run(self) -> bool:
        return self.mode == "dry-run"


@lru_cache(maxsize=1)
def settings() -> Settings:
    return Settings(
        mode=_env("SOAR_MODE", "contain"),
        quarantine_label_key=_env("SOAR_QUARANTINE_LABEL_KEY", "security.quarantine"),
        quarantine_label_value=_env("SOAR_QUARANTINE_LABEL_VALUE", "true"),
        orphan_from_controller=_env("SOAR_ORPHAN_FROM_CONTROLLER", "true").lower() == "true",
        trusted_namespaces=_env_list("SOAR_TRUSTED_NAMESPACES", "kube-system"),
        dedup_minutes=int(_env("SOAR_DEDUP_MINUTES", "10") or 10),
        agent_url=_env("SOAR_AGENT_URL"),
        agent_timeout=float(_env("SOAR_AGENT_TIMEOUT", "300") or 300),
        loki_url=_env("SOAR_LOKI_URL"),
        grafana_url=_env("SOAR_GRAFANA_URL"),
        grafana_external_url=_env("SOAR_GRAFANA_EXTERNAL_URL"),
        grafana_api_token=_env("GRAFANA_API_TOKEN"),
        argo_external_url=_env("SOAR_ARGO_EXTERNAL_URL"),
        console_external_url=_env("SOAR_CONSOLE_EXTERNAL_URL"),
        slack_webhook_url=_env("SLACK_WEBHOOK_URL"),
        teams_webhook_url=_env("TEAMS_WEBHOOK_URL"),
        google_chat_webhook_url=_env("GOOGLE_CHAT_WEBHOOK_URL"),
        webhook_url=_env("WEBHOOK_URL"),
        webhook_secret=_env("WEBHOOK_SECRET"),
        smtp_host=_env("SMTP_HOST"),
        smtp_port=int(_env("SMTP_PORT", "587") or 587),
        smtp_tls=_env("SMTP_TLS", "starttls").lower(),
        smtp_username=_env("SMTP_USERNAME"),
        smtp_password=_env("SMTP_PASSWORD"),
        smtp_from=_env("SMTP_FROM"),
        smtp_to=_env_list("SMTP_TO"),
        pagerduty_routing_key=_env("PAGERDUTY_ROUTING_KEY"),
        pagerduty_min_severity=_env("SOAR_PAGERDUTY_MIN_SEVERITY", "critical").lower(),
        jira_url=_env("JIRA_URL").rstrip("/"),
        jira_email=_env("JIRA_EMAIL"),
        jira_api_token=_env("JIRA_API_TOKEN"),
        jira_project_key=_env("JIRA_PROJECT_KEY"),
        jira_issue_type=_env("JIRA_ISSUE_TYPE", "Task"),
    )
