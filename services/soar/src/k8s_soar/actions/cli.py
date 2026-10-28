"""`soar-actions <step>` — one subcommand per step of the falco-response workflow.

Inputs arrive as CLI arguments (Argo substitutes them as single argv entries,
no shell involved). Outputs are written as files under --out so the
WorkflowTemplate can expose them as output parameters, and echoed to stdout so
they are readable in the Argo UI logs.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from k8s_soar.alert import parse
from k8s_soar.config import settings
from k8s_soar.context import collect
from k8s_soar.kube import kube
from k8s_soar.verdict import Verdict

from . import act, contain, decide, guard, notify, triage


def _json_arg(value: str) -> dict[str, Any]:
    if not value:
        return {}
    data = json.loads(value)
    return data if isinstance(data, dict) else {}


def _write(out: Path, name: str, value: Any) -> None:
    out.mkdir(parents=True, exist_ok=True)
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    (out / name).write_text(text)
    print(f"{name}: {text}")


def cmd_guard(args: argparse.Namespace) -> None:
    alert = parse(args.alert)
    decision = guard.decide(alert, kube(), settings())
    print(f"alert: {alert.short()}")
    _write(args.out, "decision", decision.as_dict())
    _write(args.out, "action", decision.action)
    _write(args.out, "namespace", alert.namespace or "")
    _write(args.out, "pod", alert.pod or "")


def _process_age() -> float | None:
    """Seconds since this process was exec'd (Linux): interpreter start-up plus imports."""
    try:
        ticks = os.sysconf("SC_CLK_TCK")
        started = int(Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]) / ticks
        return round(float(Path("/proc/uptime").read_text().split()[0]) - started, 2)
    except (OSError, ValueError, IndexError):
        return None


def cmd_respond(args: argparse.Namespace) -> None:
    """Route the alert and, if it is a containment rule, quarantine the pod: both in one pod.

    Each workflow step is a pod and a pod start costs seconds, so the time to contain is the
    time to the first step that touches the pod. A containment error is recorded in
    `contained` and the case carries on (notifications still go out and say it failed).
    """
    startup = _process_age()  # exec to here: Python start-up and importing the libraries
    begun = time.monotonic()

    def record_timing() -> None:
        _write(args.out, "timing", {"startup_seconds": startup, "work_seconds": round(time.monotonic() - begun, 2)})

    alert = parse(args.alert)
    decision = guard.decide(alert, kube(), settings())
    print(f"alert: {alert.short()}")
    _write(args.out, "decision", decision.as_dict())
    _write(args.out, "action", decision.action)
    _write(args.out, "namespace", alert.namespace or "")
    _write(args.out, "pod", alert.pod or "")
    if decision.action != guard.CONTAIN:
        _write(args.out, "contained", {"skipped": f"decision is {decision.action!r}; nothing to contain"})
        record_timing()
        return
    try:
        result = contain.contain(alert, kube(), settings(), args.case)
    except Exception as exc:  # noqa: BLE001 - the case must carry on and report the failure
        logging.getLogger(__name__).exception("containment failed")
        _write(args.out, "contained", {"error": f"containment failed: {type(exc).__name__}: {exc}"})
        record_timing()
        return
    _write(args.out, "contained", result)
    record_timing()
    print(f"metric=containment rule={alert.slug} time_to_contain_seconds={result['latency_seconds']}")


def cmd_contain(args: argparse.Namespace) -> None:
    if args.action != guard.CONTAIN:
        _write(args.out, "result", {"skipped": f"decision is {args.action!r}; nothing to contain"})
        return
    alert = parse(args.alert)
    try:
        result = contain.contain(alert, kube(), settings(), args.case)
    except Exception as exc:
        # Record the failure for the notify step, then fail the step so it is red in the UI.
        _write(args.out, "result", {"error": f"containment failed: {type(exc).__name__}: {exc}"})
        raise
    _write(args.out, "result", result)
    # logfmt line parsed by the Grafana "Response" dashboard (Loki unwrap).
    print(f"metric=containment rule={alert.slug} time_to_contain_seconds={result['latency_seconds']}")


def cmd_enrich(args: argparse.Namespace) -> None:
    alert = parse(args.alert)
    try:
        ctx = collect(kube(), settings(), alert.namespace, alert.pod)
    except Exception as exc:  # evidence is best-effort; the case continues without it
        logging.getLogger(__name__).exception("enrichment failed")
        ctx = {"error": f"{type(exc).__name__}: {exc}"}
    _write(args.out, "context", ctx)


def cmd_triage(args: argparse.Namespace) -> None:
    alert = parse(args.alert)
    verdict = triage.triage(alert, _json_arg(args.context), _json_arg(args.decision), settings())
    _write(args.out, "verdict", verdict.model_dump())
    _write(args.out, "recommended", verdict.approval_default)


def _verdict(raw: str) -> Verdict | None:
    data = _json_arg(raw)
    return Verdict.model_validate(data) if data else None


def cmd_decide(args: argparse.Namespace) -> None:
    alert = parse(args.alert)
    route = decide.decide(alert, _verdict(args.verdict), settings(), decide.load_config())
    print(f"severity: {alert.severity}")
    _write(args.out, "route", route["route"])
    _write(args.out, "action", route["action"])
    _write(args.out, "result", route)


def cmd_notify(args: argparse.Namespace) -> None:
    alert = parse(args.alert)
    verdict = _verdict(args.verdict) or Verdict.unavailable("not run")
    result = notify.notify_all(
        alert,
        _json_arg(args.decision),
        _json_arg(args.contained),
        verdict,
        settings(),
        args.workflow,
        _json_arg(args.route) or None,
    )
    _write(args.out, "result", result)


def cmd_act(args: argparse.Namespace) -> None:
    _write(args.out, "result", act.run(args.action, args.namespace, args.pod, kube(), settings()))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soar-actions", description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("/tmp/outputs"))  # noqa: S108 - Argo output dir
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("guard", help="decide contain / notify / skip and claim the pod")
    p.add_argument("--alert", required=True)
    p.set_defaults(func=cmd_guard)

    p = sub.add_parser("respond", help="route the alert and quarantine the pod, in one step")
    p.add_argument("--alert", required=True)
    p.add_argument("--case", required=True, help="case id (workflow name)")
    p.set_defaults(func=cmd_respond)

    p = sub.add_parser("contain", help="quarantine and orphan the pod")
    p.add_argument("--alert", required=True)
    p.add_argument("--case", required=True, help="case id (workflow name)")
    p.add_argument("--action", default=guard.CONTAIN, help="guard decision; anything but 'contain' is a no-op")
    p.set_defaults(func=cmd_contain)

    p = sub.add_parser("enrich", help="collect read-only evidence")
    p.add_argument("--alert", required=True)
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("triage", help="ask the AI agent for a verdict")
    p.add_argument("--alert", required=True)
    p.add_argument("--context", default="")
    p.add_argument("--decision", default="")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("decide", help="automatic action or analyst approval, per severity")
    p.add_argument("--alert", required=True)
    p.add_argument("--verdict", default="")
    p.set_defaults(func=cmd_decide)

    p = sub.add_parser("notify", help="Slack, Teams, Google Chat, webhook, email, PagerDuty, Jira, Grafana")
    p.add_argument("--alert", required=True)
    p.add_argument("--decision", default="")
    p.add_argument("--contained", default="")
    p.add_argument("--verdict", default="")
    p.add_argument("--workflow", default="")
    p.add_argument("--route", default="", help="output of the decide step")
    p.set_defaults(func=cmd_notify)

    p = sub.add_parser("act", help="run an analyst-approved action")
    p.add_argument("--action", required=True, choices=act.ACTIONS)
    p.add_argument("--namespace", required=True)
    p.add_argument("--pod", required=True)
    p.set_defaults(func=cmd_act)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
