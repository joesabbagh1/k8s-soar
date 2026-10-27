from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest

from k8s_soar.actions import channels, decide, notify
from k8s_soar.alert import severity_level
from k8s_soar.config import Settings
from k8s_soar.verdict import Verdict


def _verdict(verdict="true_positive", confidence=0.9, actions=("delete-pod",)):
    return Verdict(
        verdict=verdict, confidence=confidence, severity="critical", summary="s", recommended_actions=list(actions)
    )


def _cfg(strategy="policy", **levels):
    return decide.DecisionConfig.model_validate(
        {
            "strategy": strategy,
            "aiMinConfidence": 0.8,
            "levels": {k: {"approval": "auto", "action": v} for k, v in levels.items()},
        }
    )


@pytest.mark.parametrize(
    ("priority", "level"),
    [
        ("Emergency", "critical"),
        ("critical", "critical"),
        ("Error", "high"),
        ("warning", "medium"),
        ("notice", "low"),
        ("debug", "low"),
        ("nonsense", "medium"),
    ],
)
def test_severity_levels(priority, level):
    assert severity_level(priority) == level


def test_default_config_asks_a_human(alert, settings):
    assert decide.decide(alert, None, settings, decide.load_config(""))["route"] == "human"


def test_policy_auto_action(alert, settings):
    route = decide.decide(alert, None, settings, _cfg(critical="delete-pod"))
    assert route == {
        "route": "auto",
        "action": "delete-pod",
        "reason": "automatic policy for critical alerts: delete-pod",
    }


def test_policy_only_applies_to_its_level(alert, settings):
    alert.priority = "warning"
    assert decide.decide(alert, None, settings, _cfg(critical="delete-pod"))["route"] == "human"


@pytest.mark.parametrize(
    ("verdict", "route", "action"),
    [
        (_verdict(), "auto", "delete-pod"),
        (_verdict(confidence=0.5), "human", "none"),
        (_verdict(verdict="benign", confidence=0.99, actions=("release-quarantine",)), "human", "none"),
        (_verdict(actions=("release-quarantine",)), "human", "none"),
        (_verdict(actions=("investigate",)), "auto", "none"),
        (Verdict.unavailable("down"), "human", "none"),
        (None, "human", "none"),
    ],
)
def test_ai_strategy(alert, settings, verdict, route, action):
    result = decide.decide(alert, verdict, settings, _cfg("ai", critical="none"))
    assert (result["route"], result["action"]) == (route, action)


def test_notify_mode_and_trusted_namespace_never_act(alert, settings):
    cfg = _cfg(critical="delete-pod")
    assert decide.decide(alert, None, settings.model_copy(update={"mode": "notify"}), cfg)["route"] == "human"
    alert.namespace = "kube-system"
    assert decide.decide(alert, None, settings, cfg)["route"] == "none"


def test_policy_rejects_release_as_automatic_action():
    with pytest.raises(ValueError):
        decide.load_config(json.dumps({"levels": {"critical": {"approval": "auto", "action": "release-quarantine"}}}))


# --- channels ------------------------------------------------------------------


@pytest.fixture
def sent(monkeypatch):
    calls = []

    def fake_post(url, timeout=None, **kwargs):
        calls.append((url, kwargs))
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(channels.httpx, "post", fake_post)
    return calls


def _msg(alert, settings, route=None):
    return notify.message(
        alert,
        {"action": "contain", "reason": "r"},
        {"latency_seconds": 1.2},
        _verdict(),
        settings,
        "case-1",
        route or {"route": "human", "action": "none", "reason": "x"},
    )


def test_unconfigured_channels_send_nothing(alert, settings, sent):
    msg = _msg(alert, settings)
    assert not any(send(msg, settings) for send in channels.SENDERS.values())
    assert sent == []


def test_teams_and_google_chat_payloads(alert, settings, sent):
    cfg = settings.model_copy(
        update={"teams_webhook_url": "https://teams/x", "google_chat_webhook_url": "https://chat/x"}
    )
    msg = _msg(alert, cfg)
    assert channels.teams(msg, cfg) and channels.google_chat(msg, cfg)
    teams_body, chat_body = sent[0][1]["json"], sent[1][1]["json"]
    card = teams_body["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and card["body"][0]["text"] == alert.short()
    assert {"title": "Next step", "value": "Waiting for an analyst decision"} in card["body"][1]["facts"]
    assert chat_body["cardsV2"][0]["card"]["header"]["title"] == alert.short()


def test_google_chat_escapes_markup(alert, settings, sent):
    cfg = settings.model_copy(update={"google_chat_webhook_url": "https://chat/x"})
    msg = _msg(alert, cfg)
    msg.next_step = "<a href=x>click</a>"
    channels.google_chat(msg, cfg)
    assert "<a href" not in json.dumps(sent[0][1]["json"])


def test_webhook_is_signed(alert, settings, sent):
    cfg = settings.model_copy(update={"webhook_url": "https://hook/x", "webhook_secret": "s3cret"})
    assert channels.webhook(_msg(alert, cfg), cfg)
    kwargs = sent[0][1]
    expected = hmac.new(b"s3cret", kwargs["content"], hashlib.sha256).hexdigest()
    assert kwargs["headers"]["X-K8s-Soar-Signature"] == f"sha256={expected}"
    body = json.loads(kwargs["content"])
    assert body["event"] == "case.opened" and body["alert"]["rule"] == alert.rule


def test_pagerduty_respects_min_severity(alert, settings, sent):
    cfg = settings.model_copy(update={"pagerduty_routing_key": "rk", "pagerduty_min_severity": "critical"})
    assert channels.pagerduty(_msg(alert, cfg), cfg)
    assert sent[0][1]["json"]["payload"]["severity"] == "critical"
    assert sent[0][1]["json"]["dedup_key"] == "case-1"
    alert.priority = "warning"
    assert not channels.pagerduty(_msg(alert, cfg), cfg)


def test_email(alert, settings, monkeypatch):
    sent_mail = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            self.host = host

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            sent_mail.append("starttls")

        def login(self, user, password):
            sent_mail.append(("login", user))

        def send_message(self, mail):
            sent_mail.append(mail)

    monkeypatch.setattr(channels.smtplib, "SMTP", FakeSMTP)
    cfg = settings.model_copy(
        update={
            "smtp_host": "smtp",
            "smtp_from": "soar@x",
            "smtp_to": ["a@x", "b@x"],
            "smtp_username": "u",
            "smtp_password": "p",
        }
    )
    assert channels.email(_msg(alert, cfg), cfg)
    assert sent_mail[0] == "starttls" and sent_mail[1] == ("login", "u")
    mail = sent_mail[2]
    assert mail["To"] == "a@x, b@x" and "Waiting for an analyst decision" in mail.get_content()


def test_notify_all_reports_each_channel(alert, settings, sent, monkeypatch):
    cfg = settings.model_copy(update={"teams_webhook_url": "https://teams/x"})
    result = notify.notify_all(
        alert,
        {"action": "contain"},
        {},
        _verdict(),
        cfg,
        "case-1",
        {"route": "auto", "action": "delete-pod", "reason": "policy"},
    )
    assert result["teams"] == "sent" and result["slack"] == "not configured" and result["pagerduty"] == "not configured"


def test_settings_reads_channel_env(monkeypatch):
    from k8s_soar import config

    monkeypatch.setenv("SMTP_TO", "a@x, b@x")
    monkeypatch.setenv("SMTP_PORT", "465")
    config.settings.cache_clear()
    try:
        s = config.settings()
        assert s.smtp_to == ["a@x", "b@x"] and s.smtp_port == 465
    finally:
        config.settings.cache_clear()
    assert isinstance(Settings(), Settings)
