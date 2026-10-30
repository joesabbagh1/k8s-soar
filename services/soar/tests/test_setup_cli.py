"""The setup wizard (deploy/cli/k8s_soar.py) is standard-library only; test its file handling here."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

CLI = Path(__file__).resolve().parents[3] / "deploy" / "cli" / "k8s_soar.py"


@pytest.fixture
def cli(tmp_path):
    spec = importlib.util.spec_from_file_location("k8s_soar_cli", CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SECRETS_FILE = tmp_path / "secrets.env"
    module.LOCAL_PROFILE = tmp_path / "local.yaml"
    return module


def test_secrets_survive_python_and_bash(cli):
    values = {
        "SMTP_PASSWORD": "p@ss w'ord\"$HOME`id`;#x",
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/A/B/C?x=1&y=2",
        "SMTP_TO": "a@x.com, b@y.com",
    }
    cli.write_secrets(values)
    assert cli.load_secrets() == values
    assert cli.SECRETS_FILE.stat().st_mode & 0o777 == 0o600
    # scripts/secrets.sh loads the file with `set -a; source`.
    script = f'set -a; source "{cli.SECRETS_FILE}"; printf "%s|%s|%s" "$SMTP_PASSWORD" "$SLACK_WEBHOOK_URL" "$SMTP_TO"'
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout
    assert out == "|".join(values[k] for k in ("SMTP_PASSWORD", "SLACK_WEBHOOK_URL", "SMTP_TO"))


def test_profile_round_trip_with_header(cli):
    profile = {"k8sSoar": {"response": {"mode": "contain"}}, "setup": {"cluster": "existing"}}
    cli.write_profile(profile)
    assert cli.LOCAL_PROFILE.read_text().startswith("#")
    assert cli.load_profile() == profile


def test_empty_secrets_are_not_written(cli):
    cli.write_secrets({"SLACK_WEBHOOK_URL": "", "AI_API_KEY": "k"})
    assert "SLACK_WEBHOOK_URL" not in cli.SECRETS_FILE.read_text()
    assert cli.load_secrets() == {"AI_API_KEY": "k"}


@pytest.mark.parametrize(
    ("provider", "model", "ok"),
    [
        ("gemini", "gemini-2.5-flash", True),
        ("gemini", "claude-sonnet-5-5", False),
        ("gemini", "models/gemini-2.5-flash", False),
        ("anthropic", "claude-sonnet-5-5", True),
        ("openai", "claude-sonnet-5-5", False),
        ("openrouter", "anthropic/claude-sonnet-5-5", True),
        ("anthropic", "Claude Sonnet", False),
    ],
)
def test_model_check(cli, provider, model, ok):
    assert (cli.model_check(provider, model) == "") is ok


def test_model_lists_are_filtered_and_ordered(cli, monkeypatch):
    responses = {
        "https://openrouter.ai/api/v1/key": {"data": {}},
        "https://openrouter.ai/api/v1/models": {
            "data": [
                {"id": "a/paid", "name": "Paid", "supported_parameters": ["tools"], "pricing": {"prompt": "0.1"}},
                {"id": "b/free:free", "name": "Free", "supported_parameters": ["tools"], "pricing": {}},
                {"id": "c/no-tools:free", "name": "NoTools", "supported_parameters": [], "pricing": {}},
            ]
        },
    }
    monkeypatch.setattr(cli, "_get_json", lambda url, headers=None: responses[url])
    models = cli.list_models("openrouter", "k")
    assert [m for m, _ in models] == ["b/free:free", "a/paid"]  # free first, no tool-less models
    assert "FREE" in models[0][1]

    gemini = {
        "models": [
            {"name": "models/gemini-3.8-flash", "supportedGenerationMethods": ["generateContent"]},
            {"name": "models/gemini-embedding-001", "supportedGenerationMethods": ["embedContent"]},
            {"name": "models/gemini-3.8-flash-tts", "supportedGenerationMethods": ["generateContent"]},
        ]
    }
    monkeypatch.setattr(cli, "_get_json", lambda url, headers=None: gemini)
    assert [m for m, _ in cli.list_models("gemini", "k")] == ["gemini-3.8-flash"]


def test_filter_terms(cli):
    assert cli._matches("deep free", "deepseek/x:free", "DeepSeek (free)")
    assert not cli._matches("deep paid", "deepseek/x:free", "DeepSeek (free)")


def test_install_stops_when_the_images_are_not_published(cli, monkeypatch, capsys):
    monkeypatch.setattr(cli, "image_status", lambda registry, image, tag: image != "k8s-soar-agent")
    with pytest.raises(SystemExit) as stop:
        cli.require_images({"k8sSoar": {"image": {"tag": "9.9.9"}}})
    message = str(stop.value)
    assert "9.9.9" in message and "k8s-soar-agent" in message and "./k8s-soar update" in message
    assert "k8s-soar-actions" not in message


def test_install_goes_ahead_when_images_exist_or_the_registry_is_unreachable(cli, monkeypatch):
    for answer in (True, None):  # None: offline, we cannot tell, so do not block
        monkeypatch.setattr(cli, "image_status", lambda registry, image, tag, a=answer: a)
        cli.require_images({})


def test_the_default_tag_is_the_charts_app_version(cli, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "image_status", lambda registry, image, tag: seen.append(tag) or True)
    cli.require_images({})
    assert set(seen) == {cli._chart_app_version()} and seen[0]
