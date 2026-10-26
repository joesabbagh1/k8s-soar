"""Read-only investigation tools exposed to the model.

Every tool is bound to the case's namespace: the model cannot choose a
namespace, so a prompt-injected instruction inside a log line cannot make it
read (and ship to the LLM provider) data from other namespaces.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from k8s_soar import context, mitre
from k8s_soar.config import Settings
from k8s_soar.kube import ApiException, Kube

from .settings import AgentSettings

SUBMIT_VERDICT = "submit_verdict"


def _fn(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required or []},
        },
    }


TOOL_SPECS: list[dict[str, Any]] = [
    _fn(
        "get_pod",
        "Spec summary of a pod in the case namespace: images, security context, host access, owners.",
        {"pod": {"type": "string"}},
        ["pod"],
    ),
    _fn(
        "list_pods",
        "Names, images and phases of all pods in the case namespace.",
        {},
    ),
    _fn(
        "get_pod_logs",
        "Last N log lines of a pod container in the case namespace.",
        {
            "pod": {"type": "string"},
            "container": {"type": "string"},
            "lines": {"type": "integer", "minimum": 1, "maximum": 200},
        },
        ["pod"],
    ),
    _fn("get_pod_events", "Kubernetes events for a pod in the case namespace.", {"pod": {"type": "string"}}, ["pod"]),
    _fn(
        "falco_history",
        "Falco alerts that mention the pod over the last N minutes (from Loki).",
        {"pod": {"type": "string"}, "minutes": {"type": "integer", "minimum": 1, "maximum": 1440}},
        ["pod"],
    ),
    _fn(
        "tetragon_events",
        "Kernel-level process/network events recorded by Tetragon for the pod (from Loki).",
        {"pod": {"type": "string"}, "minutes": {"type": "integer", "minimum": 1, "maximum": 240}},
        ["pod"],
    ),
    _fn("list_network_policies", "NetworkPolicies in the case namespace.", {}),
    _fn(
        "mitre_lookup",
        "Name, tactic and URL of a MITRE ATT&CK technique ID such as T1059.004.",
        {"technique_id": {"type": "string"}},
        ["technique_id"],
    ),
    _fn(
        SUBMIT_VERDICT,
        "Submit the final triage verdict. Call exactly once, when the investigation is done.",
        {
            "verdict": {"type": "string", "enum": ["true_positive", "benign", "needs_review"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "summary": {"type": "string", "description": "3-6 sentences for the on-call analyst."},
            "evidence": {"type": "array", "items": {"type": "string"}, "maxItems": 15},
            "recommended_actions": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["none", "delete-pod", "scale-to-zero", "release-quarantine", "investigate"],
                },
                "maxItems": 5,
            },
            "rationale": {"type": "string"},
        },
        ["verdict", "confidence", "severity", "summary", "recommended_actions"],
    ),
]


@dataclass
class CaseTools:
    k: Kube
    settings: Settings
    agent: AgentSettings
    namespace: str

    def run(self, name: str, raw_args: str | dict[str, Any]) -> str:
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args or {})
        except json.JSONDecodeError:
            return json.dumps({"error": "arguments were not valid JSON"})
        handler = getattr(self, f"_tool_{name}", None)
        if handler is None:
            return json.dumps({"error": f"unknown tool {name}"})
        try:
            return json.dumps(handler(**args), default=str)[:12000]
        except TypeError as exc:
            return json.dumps({"error": f"bad arguments: {exc}"})
        except ApiException as exc:
            return json.dumps({"error": f"kubernetes API: {exc.status} {exc.reason}"})

    def _tool_get_pod(self, pod: str) -> dict[str, Any]:
        return context.pod_summary(self.k, self.namespace, pod)

    def _tool_list_pods(self) -> list[dict[str, Any]]:
        pods = self.k.core.list_namespaced_pod(self.namespace).items
        return [
            {"name": p.metadata.name, "phase": p.status.phase, "images": [c.image for c in p.spec.containers]}
            for p in pods[:100]
        ]

    def _tool_get_pod_logs(self, pod: str, container: str | None = None, lines: int = 50) -> dict[str, Any]:
        if not self.agent.send_logs:
            return {"error": "log access disabled by configuration (ai.sendLogs=false)"}
        return {"logs": context.pod_logs(self.k, self.namespace, pod, container, min(lines, 200))}

    def _tool_get_pod_events(self, pod: str) -> list[dict[str, Any]]:
        return context.pod_events(self.k, self.namespace, pod)

    def _tool_falco_history(self, pod: str, minutes: int = 60) -> list[str]:
        return context.falco_history(self.settings, pod, min(minutes, 1440))

    def _tool_tetragon_events(self, pod: str, minutes: int = 15) -> list[str]:
        return context.tetragon_events(self.settings, self.namespace, pod, min(minutes, 240))

    def _tool_list_network_policies(self) -> list[str]:
        return context.network_policies(self.k, self.namespace)

    def _tool_mitre_lookup(self, technique_id: str) -> dict[str, str]:
        return mitre.lookup(technique_id.strip().upper())
