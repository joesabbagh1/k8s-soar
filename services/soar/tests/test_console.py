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
    *,
    approve="Running",
    act=None,
    alert=None,
    verdict=None,
    phase="Running",
    name="k8ssoar-reverse-shell-abcde",
    route=None,
):
    route = route or {"route": "human", "action": "none", "reason": "critical alerts need an analyst decision"}
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
        "d": _node("decide", result=json.dumps(route), route=route["route"], action=route["action"]),
        "n": _node(
            "notify", result=json.dumps({"slack": "sent", "jira": "not configured", "grafana": "not configured"})
        ),
    }
    later = {"started": "2026-10-26T10:00:03Z", "finished": "2026-10-26T10:00:04Z"}
    if approve:
        nodes["a"] = _node(
            "approve", phase=approve, type_="Suspend", action="" if approve == "Running" else "delete-pod", **later
        )
        if approve == "Succeeded":
            nodes["a"]["message"] = "delete-pod by alice: confirmed reverse shell"
    if act:
        nodes["x"] = _node(
            "auto-act" if route["route"] == "auto" else "act",
            phase=act,
            result=json.dumps({"action": "delete-pod", "result": "deleted pod shop/web"}),
            started="2026-10-26T10:00:05Z",
            finished="2026-10-26T10:00:06Z",
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
    assert titles[0] == "Detected by Falco"
    assert "Pod quarantined and network-isolated" in titles
    assert "AI verdict: Real threat (90% sure)" in titles
    assert titles[-1] == "Waiting for an analyst decision"


def test_automatic_case_closes_without_a_decision():
    route = {"route": "auto", "action": "delete-pod", "reason": "automatic policy for critical alerts: delete-pod"}
    case = cases.from_workflow(workflow(approve=None, act="Succeeded", phase="Succeeded", route=route))
    assert case.automatic and case.chosen_action == "delete-pod"
    assert case.status_label == "Closed — pod deleted (auto)"
    assert case.pod_state == "deleted"
    titles = [e.title for e in case.timeline]
    assert "Automatic response: delete pod" in titles and titles[-1] == "Action executed"


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

    def annotate(self, name, annotations):
        self.workflows[name]["metadata"].setdefault("annotations", {}).update(annotations)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "console_settings", lambda: ConsoleSettings())
    other_pod = dict(FIXTURE, output_fields=dict(FIXTURE["output_fields"], **{"k8s.pod.name": "web-old-1"}))
    fake = FakeArgo(
        [
            workflow(),
            workflow(alert=other_pod, approve="Succeeded", act="Succeeded", phase="Succeeded", name="old-case"),
        ]
    )
    server.app.state.argo = fake
    server._CACHE.clear()
    yield TestClient(server.app), fake
    server.app.state.argo = None
    server._CACHE.clear()


def test_list_and_case_pages_render(client):
    http, _ = client
    page = http.get("/")
    assert page.status_code == 200
    assert "Reverse Shell" in page.text and 'id="awaiting-count"' in page.text and ">1</span>" in page.text
    assert "old-case" not in page.text  # closed cases are not "open"
    assert "old-case" in http.get("/?show=closed").text

    case = http.get("/cases/k8ssoar-reverse-shell-abcde")
    assert case.status_code == 200
    assert "Your decision" in case.text and "AI PICK" in case.text
    assert "Pod quarantined and network-isolated" in case.text
    # Logs are linked to Grafana for the case's time window, not dumped into the page.
    assert "http://testserver:3000/explore?" in case.text
    assert "GET / 200" not in case.text
    assert "kubectl describe -n shop pod/web-5d9c-abcde" in case.text


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


# --- Grafana links -------------------------------------------------------------


def test_grafana_explore_link_is_scoped_to_the_alert():
    from datetime import UTC, datetime
    from urllib.parse import parse_qs, urlparse

    from k8s_soar import grafana

    at = datetime(2026, 10, 26, 10, 0, tzinfo=UTC)
    links = grafana.case_log_links("http://grafana:3000", at, "shop", "web-1", "case-1")
    assert [link.title for link in links] == [
        "Falco alerts on this pod",
        "Container logs",
        "Kernel activity (Tetragon)",
        "Response steps",
    ]
    assert links[1].expr == '{namespace="shop", pod="web-1"}'
    panes = json.loads(parse_qs(urlparse(links[1].url).query)["panes"][0])
    pane = panes["k8s-soar"]
    assert pane["queries"][0]["expr"] == links[1].expr
    assert pane["queries"][0]["datasource"] == {"type": "loki", "uid": "loki"}
    start, end = int(pane["range"]["from"]), int(pane["range"]["to"])
    assert end - start == 45 * 60 * 1000 and start == int(at.timestamp() * 1000) - 15 * 60 * 1000


def test_decision_is_recorded_and_shown(client):
    http, fake = client
    http.post(
        "/cases/k8ssoar-reverse-shell-abcde/decide",
        data={"action": "none", "comment": "lab test", "analyst": "alice"},
        headers={"origin": "http://testserver"},
    )
    wf = fake.workflows["k8ssoar-reverse-shell-abcde"]
    ann = wf["metadata"]["annotations"]
    assert ann[cases.ANN_BY] == "alice" and ann[cases.ANN_NOTE] == "lab test"
    # Argo then resumes the node and overwrites its message with its own service account.
    for node in wf["status"]["nodes"].values():
        if node["displayName"] == "approve":
            node.update(
                phase="Succeeded",
                finishedAt="2026-10-26T10:00:05Z",
                message="Resumed by: map[User:system:serviceaccount:argo:argo-workflows-server]",
            )
            node["outputs"]["parameters"] = [{"name": "action", "value": "none"}]
    wf["status"]["phase"] = "Succeeded"
    case = cases.from_workflow(wf)
    assert case.decision_record.by == "alice" and case.decision_record.note == "lab test"
    page = http.get("/cases/k8ssoar-reverse-shell-abcde").text
    assert "Decided by" in page and "alice" in page and "Resumed by" not in page


def test_argo_ui_resume_is_named_plainly():
    wf = workflow(approve="Succeeded", phase="Succeeded")
    for node in wf["status"]["nodes"].values():
        if node["displayName"] == "approve":
            node["message"] = "Resumed by: map[User:system:serviceaccount:argo:argo-workflows-server]"
    assert cases.from_workflow(wf).decision_record.by == "Argo UI"


def test_progress_shows_the_running_step():
    wf = workflow(approve=None)
    nodes = wf["status"]["nodes"]
    for key in ("d", "n"):
        nodes.pop(key)
    nodes["t"].update(phase="Running", finishedAt=None)
    nodes["t"]["outputs"] = {}
    case = cases.from_workflow(wf)
    assert case.status == cases.IN_PROGRESS
    assert case.current.key == "triage" and "investigating" in case.current.detail
    states = {row.key: row.state for row in case.progress}
    assert states["contain"] == "done" and states["decide"] == "pending" and states["follow-up"] == "pending"


def test_skipped_alerts_attach_to_the_open_case(client):
    http, fake = client
    later = workflow(approve=None, phase="Succeeded", name="k8ssoar-api-server-access-q1")
    later["metadata"]["creationTimestamp"] = "2026-10-26T10:05:00Z"
    later["status"]["nodes"] = {
        "g": _node(
            "guard",
            decision=json.dumps({"action": "skip", "reason": "pod is already quarantined; case already open"}),
            action="skip",
        )
    }
    fake.workflows[later["metadata"]["name"]] = later
    listed = http.get("/?show=all").text
    assert "k8ssoar-api-server-access-q1" not in listed  # not its own row
    assert "+1 more alert" in listed
    page = http.get("/cases/k8ssoar-reverse-shell-abcde").text
    assert "Also detected on this pod" in page and "k8ssoar-api-server-access-q1" in page


# --- one case per pod -----------------------------------------------------------------------------


def member(
    name,
    rule,
    minutes_after=0,
    contained=False,
    approve="Running",
    pod="web-5d9c-abcde",
    phase="Running",
    container_id=None,
):
    """A case on the same pod as the default fixture, for another rule."""
    fields = dict(FIXTURE["output_fields"], **{"k8s.pod.name": pod})
    if container_id:
        fields["container.id"] = container_id
    alert = dict(FIXTURE, rule=rule, output_fields=fields)
    wf = workflow(alert=alert, approve=approve, phase=phase, name=name)
    wf["metadata"]["creationTimestamp"] = f"2026-10-26T10:{minutes_after:02d}:00Z"
    if not contained:
        wf["status"]["nodes"]["c"]["outputs"]["parameters"][0]["value"] = json.dumps(
            {"skipped": "not a containment rule"}
        )
        # Notify-only rules are routed to notify, not containment.
        guard = wf["status"]["nodes"]["g"]["outputs"]["parameters"]
        guard[0]["value"] = json.dumps({"action": "notify", "reason": "notify-only rule"})
        guard[1]["value"] = "notify"
    return wf


def test_alerts_on_one_pod_become_one_case():
    primary = member("quarantine-case", "K8sSoar Crypto Miner Execution", 1, contained=True)
    earlier = member("stock-rule-case", "Drop and execute new binary in container", 0)
    later = member("later-case", "K8sSoar Process Discovery", 3, approve="Succeeded", phase="Succeeded")
    cs = [cases.from_workflow(w) for w in (earlier, primary, later)]
    related, attached = cases.attach_related(cs)
    assert list(related) == ["quarantine-case"]  # the case that quarantined the pod is the primary
    assert [c.name for c in related["quarantine-case"]] == ["stock-rule-case", "later-case"]
    assert attached == {"stock-rule-case", "later-case"}


def test_cases_far_apart_or_on_other_pods_stay_separate():
    a = member("a", "K8sSoar Crypto Miner Execution", 0, contained=True)
    b = member("b", "K8sSoar Crypto Miner Execution", 40, contained=True)  # outside the 15 minute window
    c = member("c", "K8sSoar Crypto Miner Execution", 1, contained=True, pod="web-other-1")
    assert cases.attach_related([cases.from_workflow(w) for w in (a, b, c)]) == ({}, set())


def test_a_waiting_case_stays_visible_when_its_primary_is_not_waiting():
    primary = member(
        "closed-primary", "K8sSoar Crypto Miner Execution", 0, contained=True, approve="Succeeded", phase="Succeeded"
    )
    waiting = member("still-waiting", "K8sSoar Process Discovery", 1)
    related, attached = cases.attach_related([cases.from_workflow(w) for w in (primary, waiting)])
    assert attached == set() and related == {}  # otherwise nobody could ever decide it


def test_one_decision_closes_the_grouped_cases(client):
    http, fake = client
    fake.workflows.clear()
    for wf in (
        member("quarantine-case", "K8sSoar Crypto Miner Execution", 1, contained=True),
        member("stock-rule-case", "Drop and execute new binary in container", 0),
    ):
        fake.workflows[wf["metadata"]["name"]] = wf
    assert http.get("/").text.count("/cases/stock-rule-case") == 0  # one row, not two
    resp = http.post(
        "/cases/quarantine-case/decide",
        data={"action": "none", "analyst": "alice", "comment": "ok"},
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert [(n, a) for n, a, _ in fake.decisions] == [("quarantine-case", "none"), ("stock-rule-case", "none")]
    assert (
        "closed with the decision on quarantine-case"
        in fake.workflows["stock-rule-case"]["metadata"]["annotations"][cases.ANN_NOTE]
    )


def test_headline_is_short_for_falco_stock_rules(client):
    noisy = dict(
        FIXTURE,
        rule="Drop and execute new binary in container",
        output="10:00:00.1: Critical Executing binary not part of base image | proc_exe=/tmp/xmrig proc_sname=sh "
        "gparent=containerd-shim proc_exe_ino_ctime=1793198821586334020 evt_type=execve user=root",
    )
    case = cases.from_workflow(workflow(alert=noisy))
    assert case.headline == "Executing binary not part of base image"
    ours = cases.from_workflow(workflow())
    assert ours.headline == "Reverse shell: stdio redirected to network socket"
    long = dict(FIXTURE, output="10:00:00.1: Critical " + "word " * 80)
    assert len(cases.from_workflow(workflow(alert=long)).headline) <= 140


def test_a_recreated_pod_with_the_same_name_is_a_new_incident():
    first = member("run-1", "K8sSoar Crypto Miner Execution", 0, contained=True, container_id="aaa111")
    second = member(
        "run-2",
        "K8sSoar Crypto Miner Execution",
        5,
        contained=True,
        container_id="bbb222",
        approve=None,
        phase="Running",
    )
    assert cases.attach_related([cases.from_workflow(w) for w in (first, second)]) == ({}, set())


def test_same_container_and_rules_without_a_container_id_still_group():
    a = member("ours", "K8sSoar Crypto Miner Execution", 0, contained=True, container_id="aaa111")
    b = member("stock", "Drop and execute new binary in container", 1, container_id="aaa111")
    c = member("old-rule", "K8sSoar Process Discovery", 2)  # no container id: matches any group
    related, attached = cases.attach_related([cases.from_workflow(w) for w in (a, b, c)])
    assert list(related) == ["ours"] and attached == {"stock", "old-rule"}


def test_a_group_does_not_flicker_while_cases_reach_their_gates():
    contain = member("contain-case", "K8sSoar Crypto Miner Execution", 0, contained=True, phase="Running")
    other = member("stock-case", "Drop and execute new binary in container", 0)
    # The notify-only case waits for a decision while the contain case is still running (its AI
    # triage is not done): it stays folded in, because the decision on the group will close it.
    contain["status"]["nodes"].pop("a")
    contain["status"]["nodes"]["t"]["phase"] = "Running"
    related, attached = cases.attach_related([cases.from_workflow(w) for w in (other, contain)])
    assert list(related) == ["contain-case"] and attached == {"stock-case"}


def test_the_case_routed_to_containment_is_primary_from_its_first_step():
    contain = member("contain-case", "K8sSoar Crypto Miner Execution", 1, contained=True)
    del contain["status"]["nodes"]["c"]  # quarantine not finished yet, but guard already routed it
    first = member("stock-case", "Drop and execute new binary in container", 0)
    (group,) = cases.group_cases([cases.from_workflow(w) for w in (first, contain)])
    assert [c.name for c in group] == ["contain-case", "stock-case"]


def test_deciding_on_a_grouped_case_closes_its_primary_too(client):
    http, fake = client
    fake.workflows.clear()
    for wf in (
        member("quarantine-case", "K8sSoar Crypto Miner Execution", 1, contained=True),
        member("stock-rule-case", "Drop and execute new binary in container", 0),
    ):
        fake.workflows[wf["metadata"]["name"]] = wf
    http.post(
        "/cases/stock-rule-case/decide",
        data={"action": "none", "analyst": "alice"},
        headers={"origin": "http://testserver"},
    )
    assert sorted(n for n, _, _ in fake.decisions) == ["quarantine-case", "stock-rule-case"]


def test_a_case_reaching_its_gate_after_the_decision_is_closed_automatically(client):
    http, fake = client
    fake.workflows.clear()
    decided = member(
        "quarantine-case", "K8sSoar Crypto Miner Execution", 1, contained=True, approve="Succeeded", phase="Succeeded"
    )
    decided["metadata"]["annotations"] = {cases.ANN_BY: "alice", cases.ANN_NOTE: "ok"}
    late = member("stock-rule-case", "Drop and execute new binary in container", 0)  # now waiting at its gate
    for wf in (decided, late):
        fake.workflows[wf["metadata"]["name"]] = wf
    assert server.reconcile_once() == 1
    assert [(n, a) for n, a, _ in fake.decisions] == [("stock-rule-case", "none")]
    note = fake.workflows["stock-rule-case"]["metadata"]["annotations"][cases.ANN_NOTE]
    assert "closed with the decision on quarantine-case" in note


def test_nothing_is_closed_while_the_primary_is_undecided(client):
    http, fake = client
    fake.workflows.clear()
    for wf in (
        member("a", "K8sSoar Crypto Miner Execution", 1, contained=True),
        member("b", "Drop and execute new binary in container", 0),
    ):
        fake.workflows[wf["metadata"]["name"]] = wf
    assert server.reconcile_once() == 0 and fake.decisions == []
