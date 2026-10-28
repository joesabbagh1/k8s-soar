"""scripts/verify-attack.py: what it concludes from case Workflows (no cluster needed)."""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "verify-attack.py"
NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
MINER = "K8sSoar Crypto Miner Execution"
TAGS = {MINER: ["k8s-soar", "soar_contain"], "K8sSoar Process Discovery": ["k8s-soar", "soar_notify"]}


@pytest.fixture(scope="module")
def v():
    spec = importlib.util.spec_from_file_location("verify_attack", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def case(
    v,
    rule=MINER,
    pod="miner-1",
    action="contain",
    contained=True,
    verdict="true_positive",
    minutes_ago=2,
    route="human",
    phase="Succeeded",
):
    nodes = {
        "g": {
            "displayName": "guard",
            "outputs": {"parameters": [{"name": "decision", "value": json.dumps({"action": action, "reason": "r"})}]},
        },
        "c": {
            "displayName": "contain",
            "outputs": {
                "parameters": [
                    {
                        "name": "result",
                        "value": json.dumps({"latency_seconds": 0.8, "orphaned": True} if contained else {}),
                    }
                ]
            },
        },
        "d": {
            "displayName": "decide",
            "outputs": {"parameters": [{"name": "result", "value": json.dumps({"route": route, "action": "none"})}]},
        },
    }
    if verdict:
        nodes["t"] = {
            "displayName": "triage",
            "outputs": {
                "parameters": [
                    {
                        "name": "verdict",
                        "value": json.dumps(
                            {
                                "verdict": verdict,
                                "confidence": 0.9,
                                "summary": "AI triage unavailable: AI agent disabled",
                            }
                        ),
                    }
                ]
            },
        }
    wf = {
        "metadata": {
            "name": f"case-{pod}-{minutes_ago}",
            "creationTimestamp": (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "labels": {"k8s-soar.io/rule": v.slug(rule), "k8s-soar.io/namespace": "shop", "k8s-soar.io/pod": pod},
        },
        "status": {"phase": phase, "nodes": nodes},
    }
    return v.parse_case(wf)


def levels(lines):
    return [level for level, _ in lines]


def test_slug_matches_the_sensor_label(v):
    assert (
        v.slug("K8sSoar Service Account Token Read By Shell Tool") == "k8ssoar-service-account-token-read-by-shell-tool"
    )
    assert len(v.slug("K8sSoar " + "x" * 100)) <= 63


def test_contained_case_with_verdict_passes(v):
    out = v.evaluate("05-crypto-miner", [MINER], TAGS, [case(v)], NOW, 15)
    assert "FAIL" not in levels(out) and "WARN" not in levels(out)
    assert any("quarantined 0.8s after detection" in m for _, m in out)
    assert any("AI verdict: true_positive" in m for _, m in out)


def test_no_case_in_window_fails(v):
    out = v.evaluate("05-crypto-miner", [MINER], TAGS, [case(v, minutes_ago=40)], NOW, 15)
    assert levels(out) == ["FAIL"] and "no case in the last 15 min" in out[0][1]


def test_only_skipped_cases_fail(v):
    out = v.evaluate("x", [MINER], TAGS, [case(v, action="skip", contained=False)], NOW, 15)
    assert "FAIL" in levels(out) and any("every case was skipped" in m for _, m in out)


def test_a_skipped_containment_rule_merged_into_a_sibling_that_quarantined_is_a_pass(v):
    # Two containment rules fired on one event; the other rule's case won the race and quarantined the pod.
    skipped = case(v, action="skip", contained=False, minutes_ago=2)
    winner = case(v, rule="K8sSoar Drifted Binary Executed", contained=True, minutes_ago=2)
    out = v.evaluate("05-crypto-miner", [MINER], TAGS, [skipped, winner], NOW, 15)
    assert "FAIL" not in levels(out)
    assert any("merged into" in m and "quarantined the pod" in m for _, m in out)
    assert any("quarantined 0.8s" in m for _, m in out)


def test_a_skipped_containment_rule_without_a_quarantining_sibling_still_fails(v):
    out = v.evaluate("x", [MINER], TAGS, [case(v, action="skip", contained=False)], NOW, 15)
    assert "FAIL" in levels(out)


def test_containment_rule_routed_to_notify_fails(v):
    out = v.evaluate("x", [MINER], TAGS, [case(v, action="notify", contained=False)], NOW, 15)
    assert any(lvl == "FAIL" and "should be contained" in m for lvl, m in out)


def test_contain_without_quarantine_fails(v):
    out = v.evaluate("x", [MINER], TAGS, [case(v, contained=False)], NOW, 15)
    assert any(lvl == "FAIL" and "did not report a quarantine" in m for lvl, m in out)


def test_ai_unavailable_is_a_warning_not_a_failure(v):
    out = v.evaluate("x", [MINER], TAGS, [case(v, verdict="unavailable")], NOW, 15)
    assert "FAIL" not in levels(out) and any(lvl == "WARN" and "AI agent disabled" in m for lvl, m in out)


def test_running_triage_is_not_reported_as_missing(v):
    out = v.evaluate("x", [MINER], TAGS, [case(v, verdict=None, phase="Running")], NOW, 15)
    assert any("still running" in m for _, m in out) and "WARN" not in levels(out)


def test_later_alerts_are_folded_and_other_rules_listed(v):
    cases = [
        case(v, minutes_ago=3),
        case(v, minutes_ago=2, action="skip", contained=False),
        case(v, rule="K8sSoar Process Discovery", action="notify", contained=False, minutes_ago=1),
    ]
    out = v.evaluate("x", [MINER], TAGS, cases, NOW, 15)
    assert "FAIL" not in levels(out)
    assert any("other rules fired on the same pod: k8ssoar-process-discovery" in m for _, m in out)


def test_scenario_without_a_rule_is_skipped(v):
    assert v.evaluate("02-privileged-pod", [], TAGS, [], NOW, 15)[0][0] == "SKIP"


def test_expected_rules_come_from_the_readme_backticks(v, tmp_path):
    (tmp_path / "README.md").write_text(
        "Rule `K8sSoar Crypto Miner Execution` fires; also `K8sSoar Crypto Miner Execution`.\n"
        "Prose about K8sSoar Something Else is ignored."
    )
    assert v.expected_rules(tmp_path) == [MINER]


def test_real_rule_files_define_containment_tags(v):
    tags = v.rule_tags()
    assert "soar_contain" in tags[MINER] and "soar_notify" in tags["K8sSoar Process Discovery"]
