from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from k8s_soar.console import cases, server
from k8s_soar.console.argo import ArgoClient, ConsoleSettings

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "falco_reverse_shell.json").read_text())


def _node(
    name, phase="Succeeded", type_="Pod", started="2026-10-26T10:00:01Z", finished="2026-10-26T10:00:02Z", **outputs
):
    return {
        "displayName": name,
        "type": type_,
        "phase": phase,
        "startedAt": started,
        "finishedAt": finished if phase != "Running" else None,
        "outputs": {"parameters": [{"name": k, "value": v} for k, v in outputs.items()]},
    }


def workflow(
    *, approve="Running", act=None, alert=None, verdict=None, phase="Running", name="k8ssoar-reverse-shell-abcde"
):
    verdict = verdict or {
        "verdict": "true_positive",
        "confidence": 0.9,
        "severity": "critical",
        "summary": "Interactive bash with stdio on a socket to 1.2.3.4.",
        "evidence": ["bash -i connected to 1.2.3.4:4444"],
        "recommended_actions": ["delete-pod"],
        "model": "anthropic/claude-sonnet-5-5",
    }
    nodes = {
        "g": _node(
            "guard", decision=json.dumps({"action": "contain", "reason": "soar_contain rule"}), action="contain"
        ),
        "c": _node(
            "contain",
            result=json.dumps(
                {
                    "pod": "shop/web-5d9c-abcde",
                    "owners": ["ReplicaSet/web-5d9c", "Deployment/web"],
                    "orphaned": True,
                    "removed_labels": ["app"],
                    "latency_seconds": 0.8,
                    "dry_run": False,
                }
            ),
        ),
        "e": _node(
            "enrich",
            context=json.dumps(
                {
                    "pod": {
                        "found": True,
                        "phase": "Running",
                        "owners": ["Deployment/web"],
                        "containers": [],
                        "host_paths": [],
                    },
                    "events": [{"type": "Normal", "reason": "Started", "message": "Started container web", "count": 1}],
                    "logs": "GET / 200",
                }
            ),
        ),
        "t": _node("triage", verdict=json.dumps(verdict), recommended="delete-pod"),
        "n": _node(
            "notify", result=json.dumps({"slack": "sent", "jira": "not configured", "grafana": "not configured"})
        ),
    }
    if approve:
        nodes["a"] = _node(
            "approve", phase=approve, type_="Suspend", action="" if approve == "Running" else "delete-pod"
        )
        if approve == "Succeeded":
            nodes["a"]["message"] = "delete-pod by alice: confirmed reverse shell"
    if act:
        nodes["x"] = _node(
            "act", phase=act, result=json.dumps({"action": "delete-pod", "result": "deleted pod shop/web"})
        )
    return {
        "metadata": {"name": name, "creationTimestamp": "2026-10-26T10:00:00Z"},
        "spec": {"arguments": {"parameters": [{"name": "alert", "value": json.dumps(alert or FIXTURE)}]}},
        "status": {"phase": phase, "nodes": nodes},
    }


# --- case mapping ----------------------------------------------------------


def test_awaiting_case_reads_like_a_case():
    case = cases.from_workflow(workflow())
    assert case.status == cases.AWAITING
    assert case.title == "Reverse Shell"
    assert case.headline == "Reverse shell: stdio redirected to network socket"
    assert case.workload == "shop/web-5d9c-abcde"
    assert case.contained and case.owner == "Deployment/web"
    assert case.recommended == "delete-pod"
    assert ("Command line", "bash -i") in case.key_fields
    titles = [e.title for e in case.timeline]
    assert titles[0] == "Falco detected the activity"
    assert "Pod quarantined and network-isolated" in titles
    assert "AI verdict: True positive (90% confidence)" in titles
    assert titles[-1] == "Waiting for an analyst decision"


def test_choices_offer_release_only_when_contained():
    contained = cases.from_workflow(workflow())
    assert [c.action for c in contained.choices] == ["none", "delete-pod", "scale-to-zero", "release-quarantine"]
    assert next(c for c in contained.choices if c.recommended).action == "delete-pod"

    wf = workflow()
    wf["status"]["nodes"]["c"]["outputs"]["parameters"][0]["value"] = json.dumps({"skipped": "decision is 'notify'"})
    notified = cases.from_workflow(wf)
    assert not notified.contained
    assert "release-quarantine" not in [c.action for c in notified.choices]


def test_closed_case_shows_decision_and_result():
    case = cases.from_workflow(workflow(approve="Succeeded", act="Succeeded", phase="Succeeded"))
    assert case.status == cases.CLOSED
    assert case.status_label == "Closed — pod deleted"
    titles = [e.title for e in case.timeline]
    assert "Decision: Delete pod" in titles and "Action executed" in titles


def test_unavailable_ai_recommends_nothing():
    verdict = {
        "verdict": "unavailable",
        "confidence": 0,
        "severity": "medium",
        "summary": "AI triage unavailable: disabled",
    }
    case = cases.from_workflow(workflow(verdict=verdict))
    assert case.recommended == ""
    assert not any(c.recommended for c in case.choices)


def test_skipped_and_failed_cases():
    wf = workflow(approve=None, phase="Succeeded")
    wf["status"]["nodes"] = {
        "g": _node("guard", decision=json.dumps({"action": "skip", "reason": "dup"}), action="skip")
    }
    assert cases.from_workflow(wf).status == cases.SKIPPED
    assert cases.from_workflow(workflow(phase="Failed", approve=None)).status == cases.FAILED


def test_sort_puts_awaiting_first():
    closed = cases.from_workflow(workflow(approve="Succeeded", phase="Succeeded", name="b"))
    awaiting = cases.from_workflow(workflow(name="a"))
    assert sorted([closed, awaiting], key=cases.sort_key)[0].name == "a"


# --- HTTP ------------------------------------------------------------------


class FakeArgo:
    def __init__(self, workflows):
        self.workflows = {wf["metadata"]["name"]: wf for wf in workflows}
        self.decisions = []

    def list_workflows(self):
        return list(self.workflows.values())

    def get_workflow(self, name):
        return self.workflows[name]

    def decide(self, name, action, message):
        self.decisions.append((name, action, message))


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "console_settings", lambda: ConsoleSettings())
    fake = FakeArgo([workflow(), workflow(approve="Succeeded", act="Succeeded", phase="Succeeded", name="old-case")])
    server.app.state.argo = fake
    yield TestClient(server.app), fake
    server.app.state.argo = None


def test_list_and_case_pages_render(client):
    http, _ = client
    page = http.get("/")
    assert page.status_code == 200
    assert "Reverse Shell" in page.text and "1 waiting for a decision" in page.text
    assert "old-case" not in page.text  # closed cases are not "open"
    assert "old-case" in http.get("/?show=closed").text

    case = http.get("/cases/k8ssoar-reverse-shell-abcde")
    assert case.status_code == 200
    assert "Your decision" in case.text and "AI recommends" in case.text
    assert "Pod quarantined and network-isolated" in case.text


def test_decision_resumes_the_gate(client):
    http, fake = client
    resp = http.post(
        "/cases/k8ssoar-reverse-shell-abcde/decide",
        data={"action": "delete-pod", "comment": "confirmed  reverse\nshell", "analyst": "alice"},
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert fake.decisions == [
        ("k8ssoar-reverse-shell-abcde", "delete-pod", "delete-pod by alice: confirmed reverse shell")
    ]
    assert "soar_analyst=alice" in resp.headers["set-cookie"]


@pytest.mark.parametrize(
    ("data", "headers", "status"),
    [
        ({"action": "delete-pod", "analyst": "eve"}, {"origin": "http://evil.example"}, 403),
        ({"action": "delete-pod", "analyst": ""}, {}, 400),
        ({"action": "rm -rf", "analyst": "alice"}, {}, 400),
    ],
)
def test_decision_rejections(client, data, headers, status):
    http, fake = client
    resp = http.post("/cases/k8ssoar-reverse-shell-abcde/decide", data=data, headers=headers)
    assert resp.status_code == status
    assert fake.decisions == []


def test_decision_on_closed_case_is_refused(client):
    http, fake = client
    resp = http.post("/cases/old-case/decide", data={"action": "none", "analyst": "alice"})
    assert resp.status_code == 409 and fake.decisions == []


def test_attacker_content_is_escaped(client):
    http, fake = client
    evil = dict(FIXTURE, output="<script>alert(1)</script> owned (proc=sh)")
    evil["output_fields"] = dict(FIXTURE["output_fields"], **{"proc.cmdline": "<img src=x onerror=alert(1)>"})
    fake.workflows["evil"] = workflow(alert=evil, name="evil")
    body = http.get("/cases/evil").text
    assert "<script>alert(1)" not in body and "<img src=x" not in body
    assert "&lt;img src=x onerror=alert(1)&gt;" in body


def test_invalid_case_name_is_404(client):
    http, _ = client
    assert http.get("/cases/..%2F..%2Fsecrets").status_code == 404


# --- Argo client -------------------------------------------------------------


def test_argo_client_set_then_resume():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, json.loads(request.content or b"{}")))
        return httpx.Response(200, json={})

    client = ArgoClient(ConsoleSettings(argo_server_url="http://argo:2746"), transport=httpx.MockTransport(handler))
    client.decide("case-1", "delete-pod", "delete-pod by alice")
    assert [c[1] for c in calls] == [
        "/api/v1/workflows/k8s-soar/case-1/set",
        "/api/v1/workflows/k8s-soar/case-1/resume",
    ]
    assert calls[0][2]["outputParameters"] == '{"action": "delete-pod"}'
    assert calls[0][2]["nodeFieldSelector"] == "displayName=approve"
