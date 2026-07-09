#!/usr/bin/env python3
import sys
import time
import json
import urllib.request
import urllib.error
import urllib.parse
import subprocess
import os
import glob

BASE_URL = "http://localhost:3001/api/v1"
USERNAME = "admin@k8s-soar.local"

def make_request(endpoint, payload=None, auth=None, method="POST"):
    url = f"{BASE_URL}{endpoint}"
    headers = {'Content-Type': 'application/json'}
    if auth:
        auth_type, auth_val = auth
        if auth_type == "cookie":
            headers['Cookie'] = f"session_token={auth_val}"
        else:
            headers['Authorization'] = f"Bearer {auth_val}"
        
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
        return None

def wait_for_shuffle():
    print(">>> Waiting for Shuffle API to become responsive on localhost:3001...")
    for _ in range(60):
        try:
            req = urllib.request.Request(f"{BASE_URL}/info", method="GET")
            urllib.request.urlopen(req, timeout=5)
            print(">>> Shuffle API is up! Waiting 30s for database migrations...")
            time.sleep(30)
            return True
        except urllib.error.HTTPError as e:
            if e.code in [502, 503, 504]:
                time.sleep(5)
                continue
            # If we get a 401, 403, or 404, the server is UP and responding to HTTP
            print(">>> Shuffle API is up! Waiting 30s for database migrations...")
            time.sleep(30)
            return True
        except Exception as e:
            time.sleep(5)
    print(">>> Error: Timed out waiting for Shuffle API.")
    sys.exit(1)

def login(password):
    print(">>> Attempting to login...")
    payload = {"username": USERNAME, "password": password}
    
    # Retry login with larger delay to avoid 429 Too Many Requests
    for _ in range(12):
        login_res = make_request("/login", payload)
        if login_res and login_res.get("success"):
            # Check for token in cookies (Shuffle 1.2+ style)
            cookies = login_res.get("cookies", [])
            for c in cookies:
                if c.get("key") == "session_token":
                    return ("cookie", c.get("value"))
            # Fallback to root token
            return ("bearer", login_res.get("token") or login_res.get("access_token"))
        time.sleep(15)
        
    print(">>> Failed to login. User may not be initialized yet.")
    sys.exit(1)

def download_app(auth, app_id, app_name):
    print(f">>> Downloading App '{app_name}' (ID: {app_id}) from public registry...")
    res = make_request("/apps/download", payload={"id": app_id}, auth=auth)
    # Give Shuffle a few seconds to process the downloaded app
    time.sleep(5)
    if res:
        print(f">>> Successfully triggered download for {app_name}")
    else:
        print(f">>> Failed to download {app_name}. Manual activation may be required.")

def import_workflows(auth, workflows_dir, k8s_token=None, slack_webhook=None):
    workflow_files = glob.glob(os.path.join(workflows_dir, "*.json"))
    if not workflow_files:
        print(f">>> No workflows found in {workflows_dir}")
        return []
        
    imported_ids = []
    for wf_path in workflow_files:
        with open(wf_path, 'r') as f:
            workflow_content = f.read()
            
        if k8s_token:
            workflow_content = workflow_content.replace('##K8S_TOKEN##', k8s_token)
        if slack_webhook:
            workflow_content = workflow_content.replace('##SLACK_WEBHOOK##', slack_webhook)
            
        workflow_data = json.loads(workflow_content)
            
        print(f">>> Importing Workflow: {os.path.basename(wf_path)}...")
        res = make_request("/workflows", payload=workflow_data, auth=auth)
        if res and res.get("id"):
            imported_ids.append(res.get("id"))
            print(f">>> Successfully imported {os.path.basename(wf_path)} with ID: {res.get('id')}")
        else:
            print(f">>> Failed to import {os.path.basename(wf_path)}.")
            
    return imported_ids

def generate_webhook(auth, workflow_id):
    res = make_request(f"/workflows/{workflow_id}", auth=auth, method="GET")
    if not res: return None
    
    triggers = [n for n in res.get('triggers', []) if n.get('app_name') == 'Webhook']
    if triggers:
        trigger_id = triggers[0].get('id')
        if trigger_id == "alertmanager-webhook-trigger":
            return None # Skip this one, it's hardcoded in Alertmanager config
            
        # Shuffle webhook URLs usually require the 'webhook_' prefix before the ID
        actual_hook_id = trigger_id if trigger_id.startswith("webhook_") else f"webhook_{trigger_id}"
        webhook_url = f"http://shuffle-backend.shuffle.svc.cluster.local:5001/api/v1/hooks/{actual_hook_id}"
        
        print(f">>> Discovered webhook URL: {webhook_url}")
        return webhook_url
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: auto-setup-shuffle.py <admin_password> [k8s_token] [slack_webhook]")
        sys.exit(1)
        
    password = sys.argv[1]
    k8s_token = sys.argv[2] if len(sys.argv) > 2 else None
    slack_webhook = sys.argv[3] if len(sys.argv) > 3 else None
    
    script_dir = os.path.dirname(__file__)
    workflows_dir = os.path.join(script_dir, "..", "workflows")
    
    wait_for_shuffle()
    auth = login(password)
    if not auth:
        print(">>> Could not retrieve auth token. Manual Shuffle setup required.")
        sys.exit(0)
        
    # Pre-download required apps to avoid "App doesn't exist" errors
    download_app(auth, "d1ed0d085876172d9a0158e6a5a844e0", "Jira")
        
    wf_ids = import_workflows(auth, workflows_dir, k8s_token, slack_webhook)
    
    found_webhook = False
    for wf_id in wf_ids:
        webhook_url = generate_webhook(auth, wf_id)
        if webhook_url:
            print(f">>> Linking Falco to Webhook: {webhook_url}")
            link_script = os.path.join(script_dir, "link-shuffle.sh")
            if os.path.exists(link_script):
                subprocess.run([link_script, webhook_url], check=True)
                found_webhook = True
                break # Only link the first webhook found
                
    if not found_webhook:
        print(">>> No Webhook trigger found in the imported workflows.")
        print(">>> Falco will continue using the default webhook URL.")
        
    print("\n==============================================")
    print(">>> SHUFFLE AUTO-SETUP COMPLETED!")
    print(f">>> Username: {USERNAME}")
    print(f">>> Password: {password}")
    print("==============================================\n")

if __name__ == "__main__":
    main()
