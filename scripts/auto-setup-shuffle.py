#!/usr/bin/env python3
import sys
import time
import json
import urllib.request
import urllib.error
import urllib.parse
import subprocess
import os

BASE_URL = "http://localhost:3001/api/v1"
USERNAME = "admin"
PASSWORD = "admin_password123!" # Enforce a slightly complex password in case Shuffle requires it
PLAYBOOK_PATH = os.path.join(os.path.dirname(__file__), "..", "playbooks", "master-responder.json")

def make_request(endpoint, payload=None, token=None, method="POST"):
    url = f"{BASE_URL}{endpoint}"
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f"Bearer {token}"
        
    data = json.dumps(payload).encode('utf-8') if payload else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"HTTPError on {url}: {e.code} - {body}")
        return None
    except Exception as e:
        # Catch connection refused while starting up
        return None

def wait_for_shuffle():
    print(">>> Waiting for Shuffle API to become responsive on localhost:3001...")
    for _ in range(30):
        # A simple GET request to check if server is up
        try:
            req = urllib.request.Request(f"{BASE_URL}/info", method="GET")
            urllib.request.urlopen(req, timeout=5)
            print(">>> Shuffle API is up!")
            return True
        except:
            time.sleep(5)
    print(">>> Error: Timed out waiting for Shuffle API.")
    sys.exit(1)

def register_and_login():
    print(">>> Attempting to register admin user...")
    payload = {"username": USERNAME, "password": PASSWORD}
    # Some versions use /setuppassword, others /register
    res = make_request("/register", payload)
    if not res:
        res = make_request("/setuppassword", payload)
        
    print(">>> Attempting to login...")
    login_res = make_request("/login", payload)
    if not login_res or not login_res.get("success"):
        print(">>> Failed to login. Shuffle might already be configured or API differs.")
        # We won't crash the script; we'll exit gracefully so helm-install can finish
        sys.exit(0)
        
    return login_res.get("token") or login_res.get("access_token")

def import_playbook(token):
    if not os.path.exists(PLAYBOOK_PATH):
        print(f">>> Playbook not found at {PLAYBOOK_PATH}")
        sys.exit(0)
        
    with open(PLAYBOOK_PATH, 'r') as f:
        workflow_data = json.load(f)
        
    print(">>> Importing Workflow...")
    res = make_request("/workflows", payload=workflow_data, token=token)
    if not res or not res.get("id"):
        print(">>> Failed to import workflow.")
        sys.exit(0)
        
    return res.get("id")

def generate_webhook(token, workflow_id):
    print(">>> Starting Webhook...")
    # Typically in shuffle, saving the workflow with the webhook node triggers its creation,
    # or hitting /workflows/{id}/execute creates it. Since API docs are sparse, we will try to extract it from the workflow nodes.
    res = make_request(f"/workflows/{workflow_id}", token=token, method="GET")
    if not res: return None
    
    triggers = [n for n in res.get('triggers', []) if n.get('app_name') == 'Webhook']
    if triggers:
        # In shuffle, webhooks are usually <server>/api/v1/hooks/webhook_<id>
        trigger_id = triggers[0].get('id')
        webhook_url = f"http://shuffle-webhook.shuffle.svc.cluster.local:5001/api/v1/hooks/{trigger_id}"
        print(f">>> Discovered webhook URL: {webhook_url}")
        return webhook_url
    return None

def main():
    wait_for_shuffle()
    token = register_and_login()
    if not token:
        print(">>> Could not retrieve auth token. Manual Shuffle setup required.")
        sys.exit(0)
        
    wf_id = import_playbook(token)
    webhook_url = generate_webhook(token, wf_id)
    
    if webhook_url:
        print("\n==============================================")
        print(">>> AUTO-SETUP SUCCESS!")
        print(f">>> Found Webhook URL: {webhook_url}")
        print("==============================================\n")
        # Run link-shuffle.sh
        script_dir = os.path.dirname(__file__)
        link_script = os.path.join(script_dir, "link-shuffle.sh")
        subprocess.run([link_script, webhook_url], check=True)
    else:
        print(">>> Workflow imported, but could not auto-generate webhook URL.")
        print(">>> Please open the Shuffle UI, start the Webhook node, and use link-shuffle.sh")

if __name__ == "__main__":
    main()
