from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from k8s_soar.actions import act, contain, guard, notify
from k8s_soar.alert import parse
from k8s_soar.verdict import Verdict


def test_parse_falco(alert):
    assert alert.rule == "K8sSoar Reverse Shell"
    assert alert.priority == "critical"
    assert alert.namespace == "shop" and alert.pod == "web-5d9c-abcde"
    assert alert.image == "nginx:1.27"
    assert alert.wants_containment
    assert alert.mitre[0]["id"] == "T1059.004"
    assert alert.slug == "k8ssoar-reverse-shell"


def test_parse_alertmanager():
    a = parse(
        {"alerts": [{"labels": {"alertname": "X", "severity": "critical", "namespace": "n"}, "status": "firing"}]}
    )
    assert a.source == "alertmanager" and a.rule == "X" and not a.wants_containment


def test_guard_contains_and_claims(alert, kube_fake, settings):
    d = guard.decide(alert, kube_fake, settings)
    assert d.action == guard.CONTAIN
    pod = kube_fake.core.pods[("shop", "web-5d9c-abcde")]
    assert "contain" in json.loads(pod.metadata.annotations[guard.SEEN_ANNOTATION])


def test_guard_dedups_within_window(alert, kube_fake, settings):
    assert guard.decide(alert, kube_fake, settings).action == guard.CONTAIN
    second = guard.decide(alert, kube_fake, settings)
    assert second.action == guard.SKIP and "duplicate" in second.reason


def test_guard_window_expires(alert, kube_fake, settings):
    guard.decide(alert, kube_fake, settings, now=datetime.now(UTC) - timedelta(minutes=30))
    assert guard.decide(alert, kube_fake, settings).action == guard.CONTAIN


def test_guard_retries_on_conflict(alert, kube_fake, settings):
    kube_fake.core.conflicts_left = 1
    assert guard.decide(alert, kube_fake, settings).action == guard.CONTAIN


def test_guard_skips_quarantined(alert, kube_fake, settings):
    kube_fake.core.pods[("shop", "web-5d9c-abcde")].metadata.labels["security.quarantine"] = "true"
    assert guard.decide(alert, kube_fake, settings).action == guard.SKIP


def test_guard_never_contains_trusted_namespace(alert, kube_fake, settings):
    alert.namespace = "kube-system"
    assert guard.decide(alert, kube_fake, settings).action == guard.NOTIFY


def test_guard_notify_mode(alert, kube_fake, settings):
    settings.mode = "notify"
    d = guard.decide(alert, kube_fake, settings)
    assert d.action == guard.NOTIFY and "notify" in d.reason


def test_guard_untagged_low_priority_skipped(alert, kube_fake, settings):
    alert.tags = []
    alert.priority = "warning"
    assert guard.decide(alert, kube_fake, settings).action == guard.SKIP


def test_guard_pod_gone(alert, kube_fake, settings):
    alert.pod = "missing"
    assert guard.decide(alert, kube_fake, settings).action == guard.NOTIFY


def test_contain_labels_and_orphans(alert, kube_fake, settings):
    result = contain.contain(alert, kube_fake, settings, "case-1")
    pod = kube_fake.core.pods[("shop", "web-5d9c-abcde")]
    assert pod.metadata.labels["security.quarantine"] == "true"
    assert "app" not in pod.metadata.labels and "pod-template-hash" not in pod.metadata.labels
    assert json.loads(pod.metadata.annotations[contain.ORIGINAL_LABELS_ANNOTATION]) == {
        "app": "web",
        "pod-template-hash": "5d9c",
    }
    assert pod.metadata.annotations["k8s-soar.io/owner"] == "Deployment/web"
    assert result["orphaned"] and result["owners"] == ["ReplicaSet/web-5d9c", "Deployment/web"]


def test_contain_dry_run_changes_nothing(alert, kube_fake, settings):
    settings.mode = "dry-run"
    contain.contain(alert, kube_fake, settings, "case-1")
    assert kube_fake.core.patches == []


def test_act_release_restores_labels(alert, kube_fake, settings):
    contain.contain(alert, kube_fake, settings, "case-1")
    act.run(act.RELEASE, "shop", "web-5d9c-abcde", kube_fake, settings)
    labels = kube_fake.core.pods[("shop", "web-5d9c-abcde")].metadata.labels
    assert "security.quarantine" not in labels and labels["app"] == "web"


def test_act_scale_uses_recorded_owner(alert, kube_fake, settings):
    contain.contain(alert, kube_fake, settings, "case-1")
    act.run(act.SCALE_TO_ZERO, "shop", "web-5d9c-abcde", kube_fake, settings)
    assert kube_fake.apps.scaled == [("Deployment", "shop", "web", {"spec": {"replicas": 0}})]


def test_act_refuses_trusted_namespace(kube_fake, settings):
    with pytest.raises(PermissionError):
        act.run(act.DELETE_POD, "kube-system", "coredns", kube_fake, settings)


def test_act_none_is_noop(kube_fake, settings):
    assert act.run(act.NONE, "shop", "web-5d9c-abcde", kube_fake, settings)["result"] == "no action approved"
    assert kube_fake.core.deleted == []


def test_jira_body_is_valid_adf(alert, settings):
    settings.jira_project_key = "SEC"
    settings.grafana_external_url = "https://grafana.example"
    verdict = Verdict(
        verdict="true_positive", confidence=0.9, severity="critical", summary="s", recommended_actions=["delete-pod"]
    )
    body = notify.jira_body(
        alert, {"action": "contain", "reason": "r"}, {"latency_seconds": 1.2}, verdict, settings, "wf"
    )
    fields = body["fields"]
    assert fields["project"] == {"key": "SEC"}
    assert fields["description"]["type"] == "doc"
    assert "T1059_004" in fields["labels"]
    json.dumps(body)


def test_slack_escapes_attacker_text(alert):
    alert.output = "<!channel> <http://evil|click>"
    assert "<" not in notify._slack_escape(alert.output)


def test_verdict_approval_default():
    v = Verdict(
        verdict="benign",
        confidence=0.8,
        severity="low",
        summary="",
        recommended_actions=["investigate", "release-quarantine"],
    )
    assert v.approval_default == "release-quarantine"
    assert Verdict.unavailable("x").approval_default == "none"


def test_cli_contain_noop_when_not_contain(tmp_path, raw_alert):
    from k8s_soar.actions import cli

    cli.main(["--out", str(tmp_path), "contain", "--alert", json.dumps(raw_alert), "--case", "c", "--action", "notify"])
    assert "skipped" in json.loads((tmp_path / "result").read_text())
