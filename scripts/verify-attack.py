#!/usr/bin/env python3
"""Check what k8s-soar did after an attack scenario ran. Standard library only.

  make verify-attack ATTACK=crypto-miner          # one scenario (slug or directory name)
  make verify-attack ATTACK=all ARGS="--since 60" # every scenario run in the last hour

It does not run anything. It reads the case Workflows in the k8s-soar namespace and, for
each Falco rule the scenario's README names in backticks, checks that:

  - a case was opened for it (inside the time window),
  - rules tagged soar_contain were routed to containment and the pod was quarantined,
  - the AI gave a verdict (a warning, not a failure, when AI is off or unavailable),

and lists other rules that fired on the same pod. Exit code 1 if any check FAILed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "charts" / "k8s-soar" / "files" / "falco-rules"
SCENARIOS_DIR = ROOT / "scenarios"
SOAR_NS = "k8s-soar"

COLORS = {"PASS": "32", "WARN": "33", "FAIL": "31", "INFO": "36", "SKIP": "2"}


def slug(rule: str) -> str:
    """The k8s-soar.io/rule label the Sensor writes (see events.yaml)."""
    return re.sub(r"[^a-z0-9]+", "-", rule.lower())[:63].rstrip("-")


def rule_tags() -> dict[str, list[str]]:
    """{rule name: tags} from the Falco rule files."""
    tags: dict[str, list[str]] = {}
    for path in sorted(RULES_DIR.glob("*.yaml")):
        text = path.read_text()
        for block in re.split(r"(?m)^- (?=rule:|list:|macro:)", text):
            name = re.match(r"rule:\s*(.+)", block)
            found = re.search(r"(?m)^\s*tags:\s*\[([^\]]*)\]", block)
            if name and found:
                tags[name.group(1).strip()] = [t.strip() for t in found.group(1).split(",")]
    return tags


def expected_rules(scenario_dir: Path) -> list[str]:
    readme = scenario_dir / "README.md"
    if not readme.exists():
        return []
    seen: list[str] = []
    for name in re.findall(r"`(K8sSoar [^`]+)`", readme.read_text()):
        if name not in seen:
            seen.append(name)
    return seen


def resolve(arg: str) -> list[Path]:
    dirs = sorted(p for p in SCENARIOS_DIR.glob("[0-9][0-9]-*") if p.is_dir())
    if arg == "all":
        return dirs
    hits = [d for d in dirs if arg in (d.name, d.name.split("-", 1)[1])]
    if not hits:
        names = ", ".join(d.name.split("-", 1)[1] for d in dirs)
        sys.exit(f"No scenario '{arg}'. Available: {names}")
    return hits


# --- reading cases ---------------------------------------------------------------------------


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _json(value: str | None):
    try:
        return json.loads(value) if value else None
    except ValueError:
        return None


def parse_case(wf: dict) -> dict:
    """The few facts about a case Workflow that the checks need."""
    labels = wf["metadata"].get("labels") or {}
    outputs: dict[str, dict] = {}
    for node in (wf.get("status", {}).get("nodes") or {}).values():
        params = {p["name"]: p.get("value", "") for p in (node.get("outputs") or {}).get("parameters") or []}
        outputs[node.get("displayName", "")] = {"phase": node.get("phase", ""), **params}
    if "respond" in outputs:  # route + quarantine in one step (newer cases)
        both = outputs["respond"]
        outputs["guard"] = both
        outputs["contain"] = {"result": both.get("contained", "")}
    guard = _json(outputs.get("guard", {}).get("decision")) or {}
    contain = _json(outputs.get("contain", {}).get("result")) or {}
    verdict = _json(outputs.get("triage", {}).get("verdict")) or {}
    route = _json(outputs.get("decide", {}).get("result")) or {}
    return {
        "name": wf["metadata"]["name"],
        "created": _time(wf["metadata"]["creationTimestamp"]),
        "rule": labels.get("k8s-soar.io/rule", ""),
        "namespace": labels.get("k8s-soar.io/namespace", ""),
        "pod": labels.get("k8s-soar.io/pod", ""),
        "phase": wf.get("status", {}).get("phase", ""),
        "action": guard.get("action", ""),
        "reason": guard.get("reason", ""),
        "contain": contain,
        "verdict": verdict,
        "route": route,
    }


def evaluate(
    scenario: str, rules: list[str], tags: dict[str, list[str]], cases: list[dict], now: datetime, since_minutes: int
) -> list[tuple[str, str]]:
    """The checks for one scenario, as (level, message) lines."""
    out: list[tuple[str, str]] = []
    window = now - timedelta(minutes=since_minutes)
    recent = [c for c in cases if c["created"] >= window]
    if not rules:
        return [
            (
                "SKIP",
                f"{scenario}: its README names no Falco rule (an admission or Tetragon scenario); "
                "check Kyverno / Tetragon output instead",
            )
        ]
    for rule in rules:
        mine = sorted((c for c in recent if c["rule"] == slug(rule)), key=lambda c: c["created"])
        if not mine:
            out.append(
                (
                    "FAIL",
                    f"{rule}: no case in the last {since_minutes} min "
                    "(did the scenario run? are the rules loaded: make deploy-soar)",
                )
            )
            continue
        handled = [c for c in mine if c["action"] != "skip"]
        case = (handled or mine)[0]
        where = f"{case['namespace']}/{case['pod']}" if case["pod"] else "no pod"
        out.append(("PASS", f"{rule}: case {case['name']} on {where}"))
        if len(mine) > len(handled):
            out.append(
                (
                    "INFO",
                    f"{len(mine) - len(handled)} more alert(s) for this rule were folded into "
                    "the open case (pod already handled)",
                )
            )
        if not handled:
            # Several containment rules often fire on one event: the first case quarantines the
            # pod, the others are skipped as duplicates. That still counts as handled.
            sibling = next(
                (
                    c
                    for c in recent
                    if c["action"] == "contain"
                    and (c["namespace"], c["pod"]) == (case["namespace"], case["pod"])
                    and c["contain"].get("latency_seconds") is not None
                ),
                None,
            )
            if sibling is None or "soar_contain" not in tags.get(rule, []):
                out.append(("FAIL", f"{rule}: every case was skipped: {case['reason'] or 'no reason recorded'}"))
                continue
            out.append(
                ("INFO", f"its case was merged into {sibling['name']} ({sibling['rule']}), which quarantined the pod")
            )
            case = sibling
        wants_containment = "soar_contain" in tags.get(rule, [])
        latency = case["contain"].get("latency_seconds")
        if wants_containment:
            if case["action"] != "contain":
                out.append(
                    ("FAIL", f"{rule}: should be contained, but routing said '{case['action']}': {case['reason']}")
                )
            elif case["contain"].get("dry_run"):
                out.append(("WARN", "response mode is dry-run: the pod would have been quarantined"))
            elif latency is not None:
                took = "under 1" if case["contain"].get("fast") and latency < 1 else latency
                out.append(
                    (
                        "PASS",
                        f"quarantined {took}s after detection"
                        + (", detached from its controller" if case["contain"].get("orphaned") else ""),
                    )
                )
            else:
                out.append(
                    (
                        "FAIL",
                        f"{rule}: contained step did not report a quarantine "
                        f"({case['contain'].get('error') or 'no result'})",
                    )
                )
        else:
            out.append(("INFO", "notify-only rule: no containment expected"))
        verdict = case["verdict"].get("verdict")
        if verdict and verdict != "unavailable":
            out.append(("PASS", f"AI verdict: {verdict} ({round(case['verdict'].get('confidence', 0) * 100)}% sure)"))
        elif case["phase"] in ("Running", "Pending") and not verdict:
            out.append(("INFO", "AI triage still running; run the check again in a minute"))
        else:
            out.append(("WARN", "no AI verdict: " + (case["verdict"].get("summary") or "AI triage did not run")))
        route = case["route"].get("route")
        if route:
            out.append(
                ("INFO", f"follow-up: {route}" + (f" ({case['route'].get('action')})" if route == "auto" else ""))
            )
        others = sorted({c["rule"] for c in recent if c["pod"] == case["pod"] and c["rule"] != case["rule"]})
        if others:
            out.append(("INFO", "other rules fired on the same pod: " + ", ".join(others)))
    return out


# --- command line ----------------------------------------------------------------------------


def fetch_cases() -> list[dict]:
    try:
        raw = subprocess.run(
            ["kubectl", "get", "workflows", "-n", SOAR_NS, "-o", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        detail = getattr(exc, "stderr", "") or exc
        sys.exit(f"Could not read cases from namespace {SOAR_NS}: {str(detail).strip()[:300]}")
    return [parse_case(wf) for wf in json.loads(raw).get("items", [])]


def paint(level: str, text: str) -> str:
    return f"\033[{COLORS[level]}m{text}\033[0m" if sys.stdout.isatty() else text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("attack", help="scenario slug or directory name (crypto-miner, 05-crypto-miner), or 'all'")
    parser.add_argument("--since", type=int, default=15, help="look at cases from the last N minutes (default 15)")
    args = parser.parse_args()

    cases = fetch_cases()
    tags = rule_tags()
    now = datetime.now(UTC)
    failed = 0
    for scenario_dir in resolve(args.attack):
        print(f"\n{scenario_dir.name}")
        for level, message in evaluate(scenario_dir.name, expected_rules(scenario_dir), tags, cases, now, args.since):
            print(
                f"  {paint(level, level):<4} {message}"
                if not sys.stdout.isatty()
                else f"  {paint(level, level)} {message}"
            )
            failed += level == "FAIL"
    print()
    print(paint("FAIL", f"{failed} check(s) failed") if failed else paint("PASS", "All checks passed"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
