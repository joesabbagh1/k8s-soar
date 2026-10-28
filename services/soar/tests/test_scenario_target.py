"""scenario_pick_target in scripts/lab/scenario-lib.sh, with a stub kubectl (no cluster)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

LIB = Path(__file__).resolve().parents[3] / "scripts" / "lab" / "scenario-lib.sh"

KUBECTL = """#!/usr/bin/env bash
# Stub: `get pod -n shop -l app=<tier> ...` answers with $DEMO_PODS (tier=pod pairs) when the app exists.
for arg in "$@"; do [[ "$arg" == app=* ]] && tier="${arg#app=}"; done
for pair in $DEMO_PODS; do [[ "${pair%%=*}" == "$tier" ]] && printf '%s' "${pair#*=}"; done
exit 0
"""


@pytest.fixture
def run(tmp_path):
    (tmp_path / "kubectl").write_text(KUBECTL)
    (tmp_path / "kubectl").chmod(0o755)

    def _run(target, demo_pods, tier="web"):
        script = f'source "{LIB}"; if scenario_pick_target {tier}; then echo "PICKED pod=$SCENARIO_TARGET_POD ns=$SCENARIO_NS"; else echo "OWN ns=$SCENARIO_NS"; fi'
        env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "DEMO_PODS": demo_pods, "HOME": str(tmp_path)}
        if target is not None:
            env["SCENARIO_TARGET"] = target
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
        return result.returncode, result.stdout, result.stderr

    return _run


def test_auto_uses_the_demo_app_when_it_is_installed(run):
    code, out, _ = run(None, "web=web-7d9f-abcde api=api-1")
    assert code == 0 and "PICKED pod=web-7d9f-abcde ns=shop" in out


def test_auto_falls_back_quietly_without_the_demo_app(run):
    code, out, err = run(None, "")
    assert code == 0 and "OWN ns=default" in out and err == ""


def test_auto_falls_back_when_the_demo_app_lacks_that_tier(run):
    code, out, _ = run("auto", "api=api-1", tier="web")
    assert code == 0 and "OWN ns=default" in out


def test_own_never_uses_the_demo_app(run):
    code, out, _ = run("own", "web=web-1")
    assert code == 0 and "OWN ns=default" in out


def test_demo_requires_the_demo_app(run):
    code, out, err = run("demo", "")
    assert code == 1 and "make demo-app" in err and "PICKED" not in out


def test_demo_uses_it_when_present(run):
    code, out, _ = run("demo", "db=db-0", tier="db")
    assert code == 0 and "PICKED pod=db-0 ns=shop" in out


def test_unknown_target_is_rejected(run):
    code, _, err = run("prod", "web=web-1")
    assert code == 1 and "Unknown TARGET" in err
