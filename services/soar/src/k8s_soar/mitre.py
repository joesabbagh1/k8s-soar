"""MITRE ATT&CK lookups for the techniques k8s-soar rules are tagged with."""

from __future__ import annotations

import re

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1072": ("Software Deployment Tools", "Execution"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1552.005": ("Unsecured Credentials: Cloud Instance Metadata API", "Credential Access"),
    "T1552.007": ("Unsecured Credentials: Container API", "Credential Access"),
    "T1611": ("Escape to Host", "Privilege Escalation"),
    "T1613": ("Container and Resource Discovery", "Discovery"),
}

_TECHNIQUE_TAG = re.compile(r"^T\d{4}(\.\d{3})?$")


def url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def lookup(technique_id: str) -> dict[str, str]:
    name, tactic = TECHNIQUES.get(technique_id, ("Unknown technique", "Unknown"))
    return {"id": technique_id, "name": name, "tactic": tactic, "url": url(technique_id)}


def techniques_from_tags(tags: list[str]) -> list[dict[str, str]]:
    return [lookup(tag) for tag in tags if _TECHNIQUE_TAG.match(tag)]
