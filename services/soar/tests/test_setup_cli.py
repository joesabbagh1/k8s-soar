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
