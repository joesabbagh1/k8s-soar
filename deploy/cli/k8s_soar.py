#!/usr/bin/env python3
"""k8s-soar setup CLI — standard library only, so it runs on a fresh machine.

  ./k8s-soar setup          guided setup, then install (new kubeadm cluster or existing cluster)
  ./k8s-soar configure      change settings on an installed stack (pre-filled), then apply
  ./k8s-soar test-notify    send a test message to every configured channel
  ./k8s-soar status         health check (scripts/verify.sh)

Settings go to deploy/profiles/local.yaml (helmfile applies it last) and secrets to
deploy/secrets.env (loaded into Kubernetes Secrets by scripts/secrets.sh). Both
files are gitignored.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import shlex
import shutil
import smtplib
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCAL_PROFILE = ROOT / "deploy" / "profiles" / "local.yaml"
SECRETS_FILE = ROOT / "deploy" / "secrets.env"
LEVELS = ["critical", "high", "medium", "low"]
LEVEL_HELP = {
    "critical": "Falco critical/alert/emergency, e.g. reverse shell, token theft, container escape",
    "high": "Falco error",
    "medium": "Falco warning, e.g. package manager or recon tools in a container",
    "low": "Falco notice and below",
}
PROVIDERS = [
    ("anthropic", "Anthropic (Claude)", "claude-sonnet-5-5"),
    ("openai", "OpenAI", ""),
    ("gemini", "Google Gemini", ""),
    ("azure", "Azure OpenAI", ""),
    ("bedrock", "AWS Bedrock (IAM, no key)", ""),
    ("ollama", "Ollama, self-hosted (no key)", "qwen2.5"),
    ("openrouter", "OpenRouter", ""),
    ("mistral", "Mistral", ""),
]
NO_KEY_PROVIDERS = {"ollama", "bedrock"}
CHANNELS = [
    ("slack", "Slack"),
    ("teams", "Microsoft Teams"),
    ("google_chat", "Google Chat"),
    ("webhook", "Generic webhook (JSON)"),
    ("email", "Email (SMTP)"),
    ("pagerduty", "PagerDuty"),
    ("jira", "Jira issues"),
]
CHANNEL_KEYS = {
    "slack": ["SLACK_WEBHOOK_URL"],
    "teams": ["TEAMS_WEBHOOK_URL"],
    "google_chat": ["GOOGLE_CHAT_WEBHOOK_URL"],
    "webhook": ["WEBHOOK_URL", "WEBHOOK_SECRET"],
    "email": ["SMTP_HOST", "SMTP_PORT", "SMTP_TLS", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_TO"],
    "pagerduty": ["PAGERDUTY_ROUTING_KEY"],
    "jira": ["JIRA_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"],
}
SECRET_ORDER = [k for keys in CHANNEL_KEYS.values() for k in keys] + [
    "GRAFANA_API_TOKEN",
    "AI_API_KEY",
    "GRAFANA_ADMIN_PASSWORD",
]

# --- terminal ------------------------------------------------------------------

COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


def green(t: str) -> str:
    return _c("32", t)


def yellow(t: str) -> str:
    return _c("33", t)


def red(t: str) -> str:
    return _c("31", t)


def step(n: int, total: int, title: str, help_text: str = "") -> None:
    print()
    print(bold(f"[{n}/{total}] {title}"))
    if help_text:
        print(dim(help_text))


def ask(question: str, default: str = "", required: bool = False, validate=None) -> str:
    hint = f" [{default}]" if default else ""
    while True:
        try:
            value = input(f"  {question}{dim(hint)}: ").strip() or default
        except EOFError:
            print()
            sys.exit(1)
        if required and not value:
            print(red("    required"))
            continue
        if value and validate:
            error = validate(value)
            if error:
                print(red(f"    {error}"))
                continue
        return value


def ask_secret(question: str, current: str = "", required: bool = False) -> str:
    """Hidden input. Enter keeps the current value."""
    hint = f" [keep …{current[-4:]}]" if current else ""
    while True:
        value = getpass.getpass(f"  {question}{dim(hint)}: ").strip()
        if not value and current:
            return current
        if required and not value:
            print(red("    required"))
            continue
        return value


def choose(question: str, options: list[tuple[str, str]], default: str | None = None) -> str:
    print(f"  {question}")
    for i, (value, label) in enumerate(options, 1):
        marker = green("›") if value == default else " "
        print(f"   {marker} {i}) {label}")
    default_index = next((str(i) for i, (v, _) in enumerate(options, 1) if v == default), "")
    while True:
        raw = ask("Choose", default_index, required=True)
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        print(red(f"    enter a number from 1 to {len(options)}"))


def choose_many(question: str, options: list[tuple[str, str]], defaults: list[str]) -> list[str]:
    print(f"  {question}")
    for i, (value, label) in enumerate(options, 1):
        marker = green("●") if value in defaults else dim("○")
        print(f"     {marker} {i}) {label}")
    default = ",".join(str(i) for i, (v, _) in enumerate(options, 1) if v in defaults)
    while True:
        raw = ask("Numbers separated by commas, or 0 for none", default or "0")
        if raw.strip() == "0":
            return []
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if all(p.isdigit() and 1 <= int(p) <= len(options) for p in parts):
            return [options[int(p) - 1][0] for p in parts]
        print(red(f"    enter numbers from 1 to {len(options)}"))


def confirm(question: str, default: bool = True) -> bool:
    raw = ask(f"{question} (y/n)", "y" if default else "n").lower()
    return raw.startswith("y")


def url_check(value: str) -> str:
    return "" if value.startswith(("https://", "http://")) else "must start with https:// or http://"


# --- config files ----------------------------------------------------------------


def load_profile() -> dict:
    if not LOCAL_PROFILE.exists():
        return {}
    try:
        text = "\n".join(line for line in LOCAL_PROFILE.read_text().splitlines() if not line.lstrip().startswith("#"))
        return json.loads(text or "{}")
    except ValueError:
        print(yellow(f"  {LOCAL_PROFILE} is not in the format this tool writes; starting from defaults."))
        return {}


def load_secrets() -> dict[str, str]:
    values: dict[str, str] = {}
    if not SECRETS_FILE.exists():
        return values
    for line in SECRETS_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        try:
            parts = shlex.split(raw, comments=True)
        except ValueError:
            parts = [raw]
        values[key.strip()] = parts[0] if parts else ""
    return values


def write_profile(profile: dict) -> None:
    LOCAL_PROFILE.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# Written by ./k8s-soar setup|configure. JSON is valid YAML; helmfile applies this\n"
        "# file after profiles/default.yaml. Re-run ./k8s-soar configure to change it.\n"
    )
    LOCAL_PROFILE.write_text(header + json.dumps(profile, indent=2) + "\n")


def write_secrets(values: dict[str, str]) -> None:
    keys = SECRET_ORDER + sorted(k for k in values if k not in SECRET_ORDER)
    lines = ["# Written by ./k8s-soar setup|configure. Loaded into Kubernetes Secrets by scripts/secrets.sh."]
    lines += [f"{k}={shlex.quote(values[k])}" for k in keys if values.get(k)]
    SECRETS_FILE.write_text("\n".join(lines) + "\n")
    SECRETS_FILE.chmod(0o600)


# --- channel tests (standard library HTTP/SMTP) ------------------------------------


def _post_json(url: str, payload: dict, headers: dict | None = None) -> None:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "k8s-soar", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - URL typed by the admin
        resp.read()


TEST_TEXT = "k8s-soar test message: notifications are set up correctly."


def send_test(channel: str, s: dict[str, str]) -> None:
    if channel == "slack":
        _post_json(s["SLACK_WEBHOOK_URL"], {"text": TEST_TEXT})
    elif channel == "teams":
        card = {
            "type": "AdaptiveCard",
            "version": "1.4",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "body": [{"type": "TextBlock", "text": TEST_TEXT, "wrap": True}],
        }
        _post_json(
            s["TEAMS_WEBHOOK_URL"],
            {
                "type": "message",
                "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
            },
        )
    elif channel == "google_chat":
        _post_json(s["GOOGLE_CHAT_WEBHOOK_URL"], {"text": TEST_TEXT})
    elif channel == "webhook":
        payload = {"event": "test", "message": TEST_TEXT}
        headers = {}
        if s.get("WEBHOOK_SECRET"):
            body = json.dumps(payload).encode()
            sig = hmac.new(s["WEBHOOK_SECRET"].encode(), body, hashlib.sha256).hexdigest()
            headers["X-K8s-Soar-Signature"] = f"sha256={sig}"
        _post_json(s["WEBHOOK_URL"], payload, headers)
    elif channel == "pagerduty":
        event = {
            "routing_key": s["PAGERDUTY_ROUTING_KEY"],
            "dedup_key": "k8s-soar-setup-test",
            "payload": {"summary": TEST_TEXT, "source": "k8s-soar", "severity": "info"},
        }
        _post_json("https://events.pagerduty.com/v2/enqueue", {**event, "event_action": "trigger"})
        _post_json("https://events.pagerduty.com/v2/enqueue", {**event, "event_action": "resolve"})
    elif channel == "email":
        mail = EmailMessage()
        mail["Subject"] = "[k8s-soar] test message"
        mail["From"] = s["SMTP_FROM"]
        mail["To"] = s["SMTP_TO"]
        mail.set_content(TEST_TEXT)
        port, tls = int(s.get("SMTP_PORT") or 587), s.get("SMTP_TLS", "starttls")
        ctx = ssl.create_default_context()
        server = (
            smtplib.SMTP_SSL(s["SMTP_HOST"], port, timeout=10, context=ctx)
            if tls == "ssl"
            else smtplib.SMTP(s["SMTP_HOST"], port, timeout=10)
        )
        with server:
            if tls == "starttls":
                server.starttls(context=ctx)
            if s.get("SMTP_USERNAME"):
                server.login(s["SMTP_USERNAME"], s.get("SMTP_PASSWORD", ""))
            server.send_message(mail)
    elif channel == "jira":
        req = urllib.request.Request(
            f"{s['JIRA_URL'].rstrip('/')}/rest/api/3/myself", headers={"Accept": "application/json"}
        )
        token = f"{s['JIRA_EMAIL']}:{s['JIRA_API_TOKEN']}".encode()
        req.add_header("Authorization", "Basic " + base64.b64encode(token).decode())
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            resp.read()


def try_test(channel: str, label: str, s: dict[str, str]) -> None:
    what = "check the credentials" if channel == "jira" else "send a test message"
    if not confirm(f"{what.capitalize()} to {label} now?", True):
        return
    try:
        send_test(channel, s)
        print(green(f"    ✓ {label} OK"))
    except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
        detail = exc.read().decode(errors="replace")[:200] if isinstance(exc, urllib.error.HTTPError) else str(exc)
        print(red(f"    ✗ {label} failed: {detail}"))
        print(dim("      Settings are kept; fix them later with ./k8s-soar configure."))


# --- wizard --------------------------------------------------------------------------


def cluster_reachable() -> str:
    """Current kubectl context if the cluster answers, else ''."""
    if not shutil.which("kubectl"):
        return ""
    try:
        ok = subprocess.run(["kubectl", "get", "--raw", "/readyz"], capture_output=True, timeout=8).returncode == 0
        ctx = subprocess.run(["kubectl", "config", "current-context"], capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    if not ok:
        return ""
    return ctx.stdout.strip() or "current context"


def configure_channels(secrets: dict[str, str], profile: dict, total: int, n: int) -> None:
    step(n, total, "Notifications", "Where new cases are announced. Each channel is optional.")
    current = [c for c, keys in CHANNEL_KEYS.items() if secrets.get(keys[0])]
    chosen = choose_many("Channels", CHANNELS, current)
    for channel, keys in CHANNEL_KEYS.items():
        if channel not in chosen:
            for key in keys:
                secrets.pop(key, None)
    labels = dict(CHANNELS)
    for channel in chosen:
        print()
        print(f"  {bold(labels[channel])}")
        if channel == "slack":
            print(dim("    api.slack.com/apps → your app → Incoming Webhooks → Add New Webhook"))
            secrets["SLACK_WEBHOOK_URL"] = ask_secret("Webhook URL", secrets.get("SLACK_WEBHOOK_URL", ""), True)
        elif channel == "teams":
            print(dim("    Teams channel → Workflows → 'Post to a channel when a webhook request is received'"))
            secrets["TEAMS_WEBHOOK_URL"] = ask_secret("Workflow URL", secrets.get("TEAMS_WEBHOOK_URL", ""), True)
        elif channel == "google_chat":
            print(dim("    Space → Apps & integrations → Webhooks → Add webhook"))
            secrets["GOOGLE_CHAT_WEBHOOK_URL"] = ask_secret(
                "Webhook URL", secrets.get("GOOGLE_CHAT_WEBHOOK_URL", ""), True
            )
        elif channel == "webhook":
            secrets["WEBHOOK_URL"] = ask(
                "URL that receives the case JSON", secrets.get("WEBHOOK_URL", ""), True, url_check
            )
            print(dim("    Optional: a shared secret signs each request (header X-K8s-Soar-Signature)."))
            secrets["WEBHOOK_SECRET"] = ask_secret("Signing secret (Enter to skip)", secrets.get("WEBHOOK_SECRET", ""))
        elif channel == "email":
            secrets["SMTP_HOST"] = ask("SMTP server", secrets.get("SMTP_HOST", ""), True)
            secrets["SMTP_TLS"] = choose(
                "Encryption",
                [("starttls", "STARTTLS (usually port 587)"), ("ssl", "SSL/TLS (usually port 465)"), ("none", "None")],
                secrets.get("SMTP_TLS", "starttls"),
            )
            secrets["SMTP_PORT"] = ask(
                "Port", secrets.get("SMTP_PORT") or {"ssl": "465", "none": "25"}.get(secrets["SMTP_TLS"], "587")
            )
            secrets["SMTP_USERNAME"] = ask("Username (Enter if none)", secrets.get("SMTP_USERNAME", ""))
            if secrets["SMTP_USERNAME"]:
                secrets["SMTP_PASSWORD"] = ask_secret("Password", secrets.get("SMTP_PASSWORD", ""), True)
            secrets["SMTP_FROM"] = ask("From address", secrets.get("SMTP_FROM", ""), True)
            secrets["SMTP_TO"] = ask("Recipients, comma-separated", secrets.get("SMTP_TO", ""), True)
        elif channel == "pagerduty":
            print(dim("    Service → Integrations → Events API v2 → Integration Key"))
            secrets["PAGERDUTY_ROUTING_KEY"] = ask_secret(
                "Integration key", secrets.get("PAGERDUTY_ROUTING_KEY", ""), True
            )
            integrations = profile.setdefault("integrations", {})
            integrations["pagerdutyMinSeverity"] = choose(
                "Page from which level?",
                [
                    ("critical", "Critical only"),
                    ("high", "High and above"),
                    ("medium", "Medium and above"),
                    ("low", "Everything"),
                ],
                integrations.get("pagerdutyMinSeverity", "critical"),
            )
        elif channel == "jira":
            secrets["JIRA_URL"] = ask("Jira URL", secrets.get("JIRA_URL", ""), True, url_check)
            secrets["JIRA_EMAIL"] = ask("Account email", secrets.get("JIRA_EMAIL", ""), True)
            print(dim("    id.atlassian.com/manage-profile/security/api-tokens"))
            secrets["JIRA_API_TOKEN"] = ask_secret("API token", secrets.get("JIRA_API_TOKEN", ""), True)
            secrets["JIRA_PROJECT_KEY"] = ask("Project key (e.g. SEC)", secrets.get("JIRA_PROJECT_KEY", ""), True)
        try_test(channel, labels[channel], secrets)


def wizard(full: bool) -> tuple[dict, dict[str, str], str]:
    root_profile = load_profile()
    profile = root_profile.get("k8sSoar", {})
    secrets = load_secrets()
    total = 6 if full else 5
    n = 0
    target = root_profile.get("setup", {}).get("cluster", "new")

    print(bold("\nk8s-soar setup") + dim(f"   ({ROOT})"))
    print(dim("Enter accepts the value in [brackets]. Nothing is applied until you confirm at the end."))

    if full:
        n += 1
        ctx = cluster_reachable()
        step(n, total, "Cluster")
        options = [("new", "Create a new single-node cluster on this machine (kubeadm + Cilium, via Ansible)")]
        if ctx:
            options.append(("existing", f"Install on the cluster kubectl is connected to ({ctx})"))
        else:
            print(dim("  No reachable cluster in your kubeconfig, so k8s-soar will create one."))
        target = choose("Where should k8s-soar run?", options, "existing" if ctx and target == "existing" else "new")

    response = profile.setdefault("response", {})
    n += 1
    step(n, total, "Response mode", "What k8s-soar may do on its own when a containment rule fires.")
    response["mode"] = choose(
        "Mode",
        [
            ("contain", "contain  — quarantine the pod automatically (recommended)"),
            ("notify", "notify   — never touch workloads, only notify"),
            ("dry-run", "dry-run  — run everything, log what would happen (first days on a new cluster)"),
        ],
        response.get("mode", "contain"),
    )

    ai = profile.setdefault("ai", {})
    n += 1
    step(n, total, "AI triage", "An LLM reviews each case and recommends an action. Optional.")
    ai["enabled"] = confirm("Enable AI triage?", ai.get("enabled", False))
    if ai["enabled"]:
        ai["provider"] = choose("Provider", [(p, label) for p, label, _ in PROVIDERS], ai.get("provider", "anthropic"))
        default_model = ai.get("model") if ai.get("provider") == ai["provider"] else ""
        default_model = default_model or next(m for p, _, m in PROVIDERS if p == ai["provider"])
        ai["model"] = ask("Model", default_model, required=True)
        if ai["provider"] in ("ollama", "azure"):
            hint = (
                "http://ollama.<namespace>:11434"
                if ai["provider"] == "ollama"
                else "https://<resource>.openai.azure.com"
            )
            ai["baseUrl"] = ask(f"Endpoint ({hint})", ai.get("baseUrl", ""), True, url_check)
        if ai["provider"] not in NO_KEY_PROVIDERS:
            secrets["AI_API_KEY"] = ask_secret("API key", secrets.get("AI_API_KEY", ""), required=True)
    ai_usable = ai["enabled"] and (ai.get("provider") in NO_KEY_PROVIDERS or bool(secrets.get("AI_API_KEY")))

    decisions = response.setdefault("decisions", {})
    levels = decisions.setdefault("levels", {})
    n += 1
    step(
        n,
        total,
        "Decisions",
        "After containment, who decides what happens to the pod: an analyst in the console, or k8s-soar.",
    )
    for level in LEVELS:
        current = levels.setdefault(level, {"approval": "human", "action": "none"})
        print()
        print(f"  {bold(level.capitalize())} {dim('· ' + LEVEL_HELP[level])}")
        current["approval"] = choose(
            "Decision",
            [("human", "Analyst approves (console)"), ("auto", "Automatic")],
            current.get("approval", "human"),
        )
    autos = [lvl for lvl in LEVELS if levels[lvl]["approval"] == "auto"]
    if autos:
        print()
        if ai_usable:
            decisions["strategy"] = choose(
                "For automatic levels, who picks the action?",
                [
                    ("policy", "A fixed action per level (predictable)"),
                    ("ai", "The AI, when it is confident it is a real attack; otherwise an analyst decides"),
                ],
                decisions.get("strategy", "policy"),
            )
        else:
            decisions["strategy"] = "policy"
            print(dim("  No AI key configured, so automatic levels use a fixed action per level."))
        if decisions["strategy"] == "ai":
            pct = ask(
                "Minimum AI confidence to act, in %",
                str(round(decisions.get("aiMinConfidence", 0.85) * 100)),
                validate=lambda v: "" if v.isdigit() and 50 <= int(v) <= 100 else "a number from 50 to 100",
            )
            decisions["aiMinConfidence"] = int(pct) / 100
        else:
            for level in autos:
                levels[level]["action"] = choose(
                    f"Automatic action for {level}",
                    [
                        ("none", "Keep the pod quarantined for investigation"),
                        ("delete-pod", "Delete the pod (its controller runs a clean replacement)"),
                        ("scale-to-zero", "Scale the whole workload to zero"),
                    ],
                    levels[level].get("action", "none"),
                )
    else:
        decisions.setdefault("strategy", "policy")

    n += 1
    configure_channels(secrets, profile, total, n)

    n += 1
    step(
        n,
        total,
        "Links (optional)",
        "Browser URLs used in notifications. Leave empty with make console / make grafana.",
    )
    integrations = profile.setdefault("integrations", {})
    console = profile.setdefault("console", {})
    console["externalUrl"] = ask("Console URL", console.get("externalUrl", ""), validate=url_check)
    integrations["grafanaExternalUrl"] = ask(
        "Grafana URL", integrations.get("grafanaExternalUrl", ""), validate=url_check
    )

    root_profile["k8sSoar"] = profile
    root_profile.setdefault("setup", {})["cluster"] = target
    return root_profile, secrets, target


def summary(root_profile: dict, secrets: dict[str, str], full: bool) -> None:
    p = root_profile["k8sSoar"]
    d = p["response"]["decisions"]
    print()
    print(bold("Summary"))
    rows = [("Response mode", p["response"]["mode"])]
    if full:
        cluster = "new kubeadm cluster" if root_profile["setup"]["cluster"] == "new" else "existing cluster"
        rows.insert(0, ("Cluster", cluster))
    for level in LEVELS:
        lp = d["levels"][level]
        if lp["approval"] == "human":
            what = "analyst approves"
        elif d["strategy"] == "ai":
            what = f"automatic — AI decides at ≥{round(d.get('aiMinConfidence', 0.85) * 100)}%, else analyst"
        else:
            what = f"automatic — {lp['action'] if lp['action'] != 'none' else 'keep quarantined'}"
        rows.append((f"  {level}", what))
    ai = p["ai"]
    rows.append(("AI triage", f"{ai['provider']}/{ai['model']}" if ai["enabled"] else "off"))
    chosen = [label for c, label in CHANNELS if secrets.get(CHANNEL_KEYS[c][0])]
    rows.append(("Notifications", ", ".join(chosen) or "none"))
    width = max(len(k) for k, _ in rows) + 2
    for k, v in rows:
        print(f"  {k.ljust(width)}{v}")


# --- apply ---------------------------------------------------------------------------


def run(cmd: list[str], env: dict[str, str] | None = None) -> None:
    print(dim("  $ " + " ".join(cmd)))
    result = subprocess.run(cmd, cwd=ROOT, env={**os.environ, **(env or {})})
    if result.returncode != 0:
        sys.exit(f"{red('failed')}: {' '.join(cmd)} (exit {result.returncode})")


def apply_existing(full: bool) -> None:
    if full:
        run(["./scripts/preflight.sh"])
    run(["./scripts/secrets.sh"], {"SOAR_SECRETS_REPLACE": "true"})
    run(["make", "deploy" if full else "deploy-soar"])
    subprocess.run(
        ["kubectl", "rollout", "restart", "deploy/soar-agent", "-n", "k8s-soar"], cwd=ROOT, capture_output=True
    )


def cmd_setup(_: argparse.Namespace) -> None:
    require_tty()
    root_profile, secrets, target = wizard(full=True)
    summary(root_profile, secrets, full=True)
    if not confirm("\nSave and install?", True):
        sys.exit("Nothing changed.")
    write_profile(root_profile)
    write_secrets(secrets)
    print(green(f"\n✓ Saved {LOCAL_PROFILE.relative_to(ROOT)} and {SECRETS_FILE.relative_to(ROOT)}"))
    if target == "new":
        run(["deploy/ansible/setup.sh"], {"K8S_SOAR_SKIP_WIZARD": "1"})
    else:
        apply_existing(full=True)
    print(green("\n✓ k8s-soar is installed.") + " Next: make smoke-test ARGS=--keep, then make console")


def cmd_configure(_: argparse.Namespace) -> None:
    require_tty()
    root_profile, secrets, _ = wizard(full=False)
    summary(root_profile, secrets, full=False)
    if not confirm("\nSave and apply to the cluster?", True):
        sys.exit("Nothing changed.")
    write_profile(root_profile)
    write_secrets(secrets)
    print(green(f"\n✓ Saved {LOCAL_PROFILE.relative_to(ROOT)} and {SECRETS_FILE.relative_to(ROOT)}"))
    if not cluster_reachable():
        print(yellow("No reachable cluster: settings are saved and will be applied by ./k8s-soar setup."))
        return
    apply_existing(full=False)
    print(green("\n✓ Applied."))


def cmd_test_notify(_: argparse.Namespace) -> None:
    secrets = load_secrets()
    configured = [(c, label) for c, label in CHANNELS if secrets.get(CHANNEL_KEYS[c][0])]
    if not configured:
        sys.exit("No channels configured. Run ./k8s-soar configure.")
    failed = False
    for channel, label in configured:
        try:
            send_test(channel, secrets)
            print(green(f"✓ {label}"))
        except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
            failed = True
            print(red(f"✗ {label}: {exc}"))
    sys.exit(1 if failed else 0)


def cmd_status(_: argparse.Namespace) -> None:
    sys.exit(subprocess.run(["./scripts/verify.sh"], cwd=ROOT).returncode)


def require_tty() -> None:
    if not sys.stdin.isatty():
        sys.exit(
            "This command is interactive. Without a terminal, edit deploy/profiles/local.yaml and "
            "deploy/secrets.env (see deploy/secrets.env.example), then run make secrets deploy."
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="k8s-soar", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("setup", help="guided setup, then install").set_defaults(func=cmd_setup)
    sub.add_parser("configure", help="change settings and apply them").set_defaults(func=cmd_configure)
    sub.add_parser("test-notify", help="send a test message to each channel").set_defaults(func=cmd_test_notify)
    sub.add_parser("status", help="health check").set_defaults(func=cmd_status)
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit("\nCancelled. Nothing was applied.")


if __name__ == "__main__":
    main()
