"""The Sensor's fast quarantine: rendered only where it is allowed to modify workloads."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
CHART = Path(__file__).resolve().parents[3] / "charts" / "k8s-soar"
pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")


def render(*sets: str) -> list[dict]:
    args = ["helm", "template", "t", str(CHART)] + [x for s in sets for x in ("--set", s)]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def named(docs, kind, name):
    return next((d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name), None)


def test_contain_mode_renders_the_fast_sensor_with_the_right_scope():
    docs = render()
    sensor = named(docs, "Sensor", "soar-fast")
    assert sensor is not None and named(docs, "Sensor", "soar-router") is not None
    dep = sensor["spec"]["dependencies"][0]
    assert dep["filters"]["data"][0]["value"] == ['.*"soar_contain".*']  # only containment rules
    expr = dep["filters"]["exprs"][0]["expr"]
    for namespace in ("kube-system", "falco", "k8s-soar", "kyverno"):
        assert f'ns != "{namespace}"' in expr  # platform namespaces are excluded
    trigger = sensor["spec"]["triggers"][0]["template"]["k8s"]
    assert trigger["operation"] == "patch" and trigger["source"]["resource"]["metadata"]["labels"] == {
        "security.quarantine": "true"
    }
    assert {p["dest"] for p in trigger["parameters"]} == {
        "metadata.name",
        "metadata.namespace",
        "metadata.annotations.soar-fast-quarantined-at",
    }


def test_its_service_account_can_only_get_and_patch_pods():
    docs = render()
    role = named(docs, "ClusterRole", "k8s-soar-fast-quarantine")
    assert role["rules"] == [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "patch"]}]
    subject = named(docs, "ClusterRoleBinding", "k8s-soar-fast-quarantine")["subjects"][0]
    assert subject["name"] == "soar-fast"


def test_kyverno_keeps_it_out_of_platform_namespaces():
    policy = named(render(), "ClusterPolicy", "k8s-soar-responder-scope")
    subjects = {s["name"] for m in policy["spec"]["rules"][0]["match"]["any"] for s in m["subjects"]}
    assert subjects == {"soar-responder", "soar-fast"}


@pytest.mark.parametrize(
    "sets", [["response.mode=notify"], ["response.mode=dry-run"], ["response.fastQuarantine.enabled=false"]]
)
def test_it_is_never_rendered_where_workloads_must_not_change(sets):
    docs = render(*sets)
    assert named(docs, "Sensor", "soar-fast") is None
    assert named(docs, "ClusterRole", "k8s-soar-fast-quarantine") is None
    assert named(docs, "Sensor", "soar-router") is not None  # the case pipeline is unaffected
