"""POST /triage: one triage per pod, and the severity floor (no model, no cluster)."""

from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from k8s_soar.agent import server
from k8s_soar.agent.settings import AgentSettings
from k8s_soar.alert import parse
from k8s_soar.verdict import Verdict


def _verdict(tokens=900):
    return Verdict(verdict="true_positive", confidence=0.9, severity="critical", summary="s", calls=3, tokens=tokens)


@pytest.fixture
def agent(monkeypatch, raw_alert):
    calls = []

    def fake_run(alert, context, decision, tools, cfg):
        calls.append(alert.rule)
        time.sleep(0.15)
        return _verdict()

    cfg = AgentSettings(provider="openai", model="m", api_key="k")
    monkeypatch.setattr(server, "run_triage", fake_run)
    monkeypatch.setattr(server, "agent_settings", lambda: cfg)
    monkeypatch.setattr(server, "kube", lambda: None)
    server._SHARED.clear()

    def body(rule, **fields):
        alert = parse(raw_alert).model_dump(mode="json")  # the agent takes the normalised Alert, not Falco's JSON
        alert["rule"] = rule
        alert["fields"] = {**alert["fields"], **fields}
        return {"alert": alert, "context": {}, "decision": {}}

    yield TestClient(server.app), calls, cfg, body
    server._SHARED.clear()


def test_a_second_case_on_the_same_pod_reuses_the_first_verdict(agent):
    http, calls, _, body = agent
    first = http.post("/triage", json=body("Rule A")).json()
    second = http.post("/triage", json=body("Rule B")).json()
    assert calls == ["Rule A"]
    assert (first["reused"], first["tokens"]) == (False, 900)
    assert (second["reused"], second["tokens"], second["calls"]) == (True, 0, 0)  # shared: no extra cost
    assert second["verdict"] == "true_positive"


def test_cases_arriving_together_pay_for_one_triage(agent):
    http, calls, _, body = agent
    results = []
    threads = [
        threading.Thread(target=lambda r=r: results.append(http.post("/triage", json=body(r)).json()))
        for r in ("Rule A", "Rule B", "Rule C")
    ]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(calls) == 1 and sorted(r["reused"] for r in results) == [False, True, True]


def test_a_different_container_is_a_different_incident(agent):
    http, calls, _, body = agent
    http.post("/triage", json=body("Rule A", **{"container.id": "aaa"}))
    http.post("/triage", json=body("Rule A", **{"container.id": "bbb"}))
    assert len(calls) == 2


def test_a_failed_triage_is_not_shared(agent, monkeypatch):
    http, calls, _, body = agent
    monkeypatch.setattr(server, "run_triage", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("provider down")))
    assert http.post("/triage", json=body("Rule A")).json()["verdict"] == "unavailable"
    monkeypatch.setattr(server, "run_triage", lambda *a, **k: _verdict())
    assert http.post("/triage", json=body("Rule A")).json()["reused"] is False  # retried, not stuck on the failure


def test_sharing_can_be_turned_off(agent):
    http, calls, cfg, body = agent
    cfg.share_seconds = 0
    http.post("/triage", json=body("Rule A"))
    http.post("/triage", json=body("Rule B"))
    assert len(calls) == 2


def test_alerts_below_the_severity_floor_skip_the_model(agent):
    http, calls, cfg, body = agent
    cfg.min_severity = "high"
    low = body("Rule A")
    low["alert"]["priority"] = "warning"  # a medium alert
    out = http.post("/triage", json=low).json()
    assert calls == [] and out["verdict"] == "unavailable" and "ai.minSeverity" in out["summary"]
    assert http.post("/triage", json=body("Rule B")).json()["verdict"] == "true_positive"  # critical goes through
