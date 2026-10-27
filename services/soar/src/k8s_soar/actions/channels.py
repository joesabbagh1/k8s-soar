"""Notification channels besides Slack and Jira: Teams, Google Chat, generic webhook, email, PagerDuty.

Each sender takes a prepared Message and returns False when its channel is not
configured. Alert content is attacker-controlled: it only goes into JSON string
fields or plain-text email bodies, never into markup that is interpreted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any

import httpx

from k8s_soar.alert import SEVERITY_LEVELS
from k8s_soar.config import Settings


@dataclass
class Message:
    case: str
    title: str  # "[CRITICAL] Rule on ns/pod"
    rule: str
    severity: str  # critical | high | medium | low
    rows: list[tuple[str, str]]
    output: str
    next_step: str
    ai_summary: str = ""
    links: dict[str, str] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)  # full case for the generic webhook


def _post(url: str, settings: Settings, **kwargs: Any) -> None:
    resp = httpx.post(url, timeout=settings.http_timeout, **kwargs)
    resp.raise_for_status()


def teams(msg: Message, settings: Settings) -> bool:
    """Microsoft Teams via a Workflows ("When a Teams webhook request is received") URL: Adaptive Card."""
    if not settings.teams_webhook_url:
        return False
    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": msg.title,
            "weight": "Bolder",
            "size": "Medium",
            "wrap": True,
            "color": "Attention" if msg.severity in ("critical", "high") else "Default",
        },
        {"type": "FactSet", "facts": [{"title": k, "value": v[:300]} for k, v in msg.rows[:12]]},
        {"type": "TextBlock", "text": msg.next_step, "wrap": True, "weight": "Bolder"},
    ]
    if msg.ai_summary:
        body.append({"type": "TextBlock", "text": "AI: " + msg.ai_summary[:1000], "wrap": True, "isSubtle": True})
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
        "actions": [{"type": "Action.OpenUrl", "title": name, "url": url} for name, url in list(msg.links.items())[:5]],
    }
    _post(
        settings.teams_webhook_url,
        settings,
        json={
            "type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
        },
    )
    return True


def google_chat(msg: Message, settings: Settings) -> bool:
    if not settings.google_chat_webhook_url:
        return False
    widgets: list[dict[str, Any]] = [
        {"decoratedText": {"topLabel": k, "text": v[:300], "wrapText": True}} for k, v in msg.rows[:12]
    ]
    widgets.append({"textParagraph": {"text": f"<b>{_html(msg.next_step)}</b>"}})
    if msg.ai_summary:
        widgets.append({"textParagraph": {"text": "AI: " + _html(msg.ai_summary[:1000])}})
    if msg.links:
        widgets.append(
            {
                "buttonList": {
                    "buttons": [{"text": n, "onClick": {"openLink": {"url": u}}} for n, u in msg.links.items()]
                }
            }
        )
    card = {
        "cardId": msg.case or "k8s-soar",
        "card": {"header": {"title": msg.title[:200]}, "sections": [{"widgets": widgets}]},
    }
    _post(settings.google_chat_webhook_url, settings, json={"text": msg.title, "cardsV2": [card]})
    return True


def _html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def webhook(msg: Message, settings: Settings) -> bool:
    """POST the case as JSON. With WEBHOOK_SECRET: header X-K8s-Soar-Signature: sha256=<hmac of body>."""
    if not settings.webhook_url:
        return False
    payload = {
        "event": "case.opened",
        "case": msg.case,
        "title": msg.title,
        "severity": msg.severity,
        "next_step": msg.next_step,
        "links": msg.links,
        **msg.data,
    }
    body = json.dumps(payload, default=str).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "k8s-soar"}
    if settings.webhook_secret:
        digest = hmac.new(settings.webhook_secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-K8s-Soar-Signature"] = f"sha256={digest}"
    _post(settings.webhook_url, settings, content=body, headers=headers)
    return True


def email(msg: Message, settings: Settings) -> bool:
    if not (settings.smtp_host and settings.smtp_from and settings.smtp_to):
        return False
    mail = EmailMessage()
    mail["Subject"] = f"[k8s-soar] {msg.title}"[:250]
    mail["From"] = settings.smtp_from
    mail["To"] = ", ".join(settings.smtp_to)
    lines = [msg.title, "", *(f"{k}: {v}" for k, v in msg.rows), "", msg.next_step]
    if msg.ai_summary:
        lines += ["", "AI: " + msg.ai_summary]
    lines += ["", "Falco output:", msg.output, ""]
    lines += [f"{name}: {url}" for name, url in msg.links.items()]
    mail.set_content("\n".join(lines))
    if settings.smtp_tls == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(
            settings.smtp_host, settings.smtp_port, timeout=settings.http_timeout, context=ssl.create_default_context()
        )
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.http_timeout)
    with server:
        if settings.smtp_tls == "starttls":
            server.starttls(context=ssl.create_default_context())
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(mail)
    return True


PAGERDUTY_SEVERITY = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}


def pagerduty(msg: Message, settings: Settings) -> bool:
    """PagerDuty Events API v2; only pages from SOAR_PAGERDUTY_MIN_SEVERITY up. One incident per case."""
    if not settings.pagerduty_routing_key:
        return False
    minimum = settings.pagerduty_min_severity if settings.pagerduty_min_severity in SEVERITY_LEVELS else "critical"
    if SEVERITY_LEVELS.index(msg.severity) < SEVERITY_LEVELS.index(minimum):
        return False
    _post(
        "https://events.pagerduty.com/v2/enqueue",
        settings,
        json={
            "routing_key": settings.pagerduty_routing_key,
            "event_action": "trigger",
            "dedup_key": msg.case or msg.title,
            "payload": {
                "summary": msg.title[:1000],
                "source": "k8s-soar",
                "severity": PAGERDUTY_SEVERITY.get(msg.severity, "warning"),
                "component": msg.rule,
                "custom_details": {**dict(msg.rows), "next_step": msg.next_step, "ai": msg.ai_summary},
            },
            "links": [{"href": url, "text": name} for name, url in msg.links.items()],
        },
    )
    return True


SENDERS = {
    "teams": teams,
    "google_chat": google_chat,
    "webhook": webhook,
    "email": email,
    "pagerduty": pagerduty,
}
