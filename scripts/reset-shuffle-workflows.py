#!/usr/bin/env python3
"""Delete all Shuffle workflows and re-import the canonical k8s-soar set."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = os.environ.get("SHUFFLE_API_URL", "http://localhost:3001/api/v1")
USERNAME = os.environ.get("SHUFFLE_USERNAME", "admin@k8s-soar.local")

CHILD_WORKFLOWS = [
    "Quarantine-Pod.json",
    "Delete-Pod.json",
    "observability-responder.json",
]
MASTER_WORKFLOW = "K8s-SOAR-Master-Responder.json"

SUBFLOW_BINDINGS = {
    "Trigger Quarantine-Pod": "Quarantine-Pod.json",
    "Trigger Delete-Pod": "Delete-Pod.json",
    "Log to Jira": "observability-responder.json",
}


def make_request(endpoint: str, *, auth: tuple[str, str] | None = None, payload=None, method: str = "GET"):
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    if auth:
        auth_type, auth_val = auth
        if auth_type == "cookie":
            headers["Cookie"] = f"session_token={auth_val}"
        else:
            headers["Authorization"] = f"Bearer {auth_val}"

    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            body = response.read().decode()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        print(f"HTTPError on {method} {url}: {exc.code} - {body}", file=sys.stderr)
        return None


def login(password: str) -> tuple[str, str]:
    res = make_request("/login", payload={"username": USERNAME, "password": password}, method="POST")
    if not res or not res.get("success"):
        print(">>> Failed to login to Shuffle", file=sys.stderr)
        sys.exit(1)
    for cookie in res.get("cookies", []):
        if cookie.get("key") == "session_token":
            return ("cookie", cookie["value"])
    token = res.get("token") or res.get("access_token")
    if token:
        return ("bearer", token)
    print(">>> Login succeeded but no session token returned", file=sys.stderr)
    sys.exit(1)


def list_workflows(auth: tuple[str, str]) -> list[dict]:
    res = make_request("/workflows", auth=auth, method="GET")
    if isinstance(res, list):
        return res
    if isinstance(res, dict):
        return res.get("workflows") or []
    return []


def delete_workflow(auth: tuple[str, str], workflow_id: str) -> bool:
    res = make_request(f"/workflows/{workflow_id}", auth=auth, method="DELETE")
    return bool(res and res.get("success"))


def import_workflow(auth: tuple[str, str], workflow_path: Path) -> dict | None:
    workflow = json.loads(workflow_path.read_text())
    workflow.pop("id", None)
    res = make_request("/workflows", auth=auth, payload=workflow, method="POST")
    if res and res.get("id"):
        print(f">>> Imported {workflow_path.name} -> {res['id']}")
        return res
    print(f">>> Failed to import {workflow_path.name}", file=sys.stderr)
    return None


def patch_master_subflows(master: dict, imported: dict[str, str]) -> dict:
    for trigger in master.get("triggers", []):
        label = trigger.get("label")
        source_name = SUBFLOW_BINDINGS.get(label)
        if not source_name:
            continue
        workflow_id = imported.get(source_name)
        if not workflow_id:
            continue
        for param in trigger.get("parameters", []):
            if param.get("name") == "workflow":
                param["value"] = workflow_id
    return master


def master_webhook_url(master: dict, public_base: str | None = None) -> str | None:
    for trigger in master.get("triggers", []):
        if trigger.get("app_name") != "Webhook":
            continue
        trigger_id = trigger.get("id", "")
        hook_id = trigger_id if trigger_id.startswith("webhook_") else f"webhook_{trigger_id}"
        if public_base:
            return f"{public_base.rstrip('/')}/api/v1/hooks/{hook_id}"
        for param in trigger.get("parameters", []):
            if param.get("name") == "url" and param.get("value"):
                return param["value"]
    return None


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: reset-shuffle-workflows.py <shuffle_admin_password> [public_webhook_base]")
        print("Example: reset-shuffle-workflows.py '$PASS' http://192.168.0.12:3001")
        sys.exit(1)

    password = sys.argv[1]
    public_base = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("SHUFFLE_PUBLIC_URL")

    root = Path(__file__).resolve().parent.parent
    workflows_dir = root / "workflows"
    auth = login(password)

    existing = list_workflows(auth)
    print(f">>> Found {len(existing)} workflow(s) in Shuffle")
    for wf in existing:
        wf_id = wf.get("id")
        wf_name = wf.get("name", "unknown")
        if not wf_id:
            continue
        if delete_workflow(auth, wf_id):
            print(f">>> Deleted {wf_name} ({wf_id})")
        else:
            auth = login(password)
            if delete_workflow(auth, wf_id):
                print(f">>> Deleted {wf_name} ({wf_id})")
            else:
                print(f">>> Failed to delete {wf_name} ({wf_id})", file=sys.stderr)

    imported_ids: dict[str, str] = {}
    for filename in CHILD_WORKFLOWS:
        path = workflows_dir / filename
        if not path.exists():
            print(f">>> Missing workflow file: {path}", file=sys.stderr)
            sys.exit(1)
        res = import_workflow(auth, path)
        if not res:
            sys.exit(1)
        imported_ids[filename] = res["id"]

    master_path = workflows_dir / MASTER_WORKFLOW
    master = json.loads(master_path.read_text())
    master.pop("id", None)
    master = patch_master_subflows(master, imported_ids)

    master_res = make_request("/workflows", auth=auth, payload=master, method="POST")
    if not master_res or not master_res.get("id"):
        print(">>> Failed to import master responder workflow", file=sys.stderr)
        sys.exit(1)
    print(f">>> Imported {MASTER_WORKFLOW} -> {master_res['id']}")

    # Fetch full workflow so trigger IDs reflect the live Shuffle state.
    master_live = make_request(f"/workflows/{master_res['id']}", auth=auth, method="GET") or master_res
    webhook = master_webhook_url(master_live, public_base)
    if webhook:
        print(f">>> Master responder webhook: {webhook}")
        link_script = root / "scripts" / "link-shuffle.sh"
        if link_script.exists() and os.environ.get("SKIP_FALCO_LINK") != "1":
            os.system(f"{link_script} '{webhook}'")
    else:
        print(">>> Warning: could not determine master responder webhook URL", file=sys.stderr)

    print(">>> Shuffle workflow reset complete")


if __name__ == "__main__":
    main()
