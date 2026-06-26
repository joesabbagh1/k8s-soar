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
            print(">>> Shuffle API is up!")
            return True
        except urllib.error.HTTPError:
            # Server responded with 401, 404, etc., meaning it is UP!
            print(">>> Shuffle API is up!")
            return True
        except Exception as e:
            time.sleep(5)
    print(">>> Error: Timed out waiting for Shuffle API.")
    sys.exit(1)

def login(password):
    print(">>> Attempting to login...")
    payload = {"username": USERNAME, "password": password}
    
    # Retry login in case the backend is still initializing the user
    for _ in range(5):
        login_res = make_request("/login", payload)
        if login_res and login_res.get("success"):
            # Check for token in cookies (Shuffle 1.2+ style)
            cookies = login_res.get("cookies", [])
            for c in cookies:
                if c.get("key") == "session_token":
                    return ("cookie", c.get("value"))
            # Fallback to root token
            return ("bearer", login_res.get("token") or login_res.get("access_token"))
        time.sleep(5)
        
    print(">>> Failed to login. User may not be initialized yet.")
    sys.exit(0)

def import_playbooks(auth, playbooks_dir):
    playbook_files = glob.glob(os.path.join(playbooks_dir, "*.json"))
    if not playbook_files:
        print(f">>> No playbooks found in {playbooks_dir}")
        return []
        
    imported_ids = []
    for pb_path in playbook_files:
        with open(pb_path, 'r') as f:
            workflow_data = json.load(f)
            
        print(f">>> Importing Workflow: {os.path.basename(pb_path)}...")
        res = make_request("/workflows", payload=workflow_data, auth=auth)
        if res and res.get("id"):
            imported_ids.append(res.get("id"))
            print(f">>> Successfully imported {os.path.basename(pb_path)} with ID: {res.get('id')}")
        else:
            print(f">>> Failed to import {os.path.basename(pb_path)}.")
            
    return imported_ids

def generate_webhook(auth, workflow_id):
    res = make_request(f"/workflows/{workflow_id}", auth=auth, method="GET")
    if not res: return None
    
    triggers = [n for n in res.get('triggers', []) if n.get('app_name') == 'Webhook']
    if triggers:
        trigger_id = triggers[0].get('id')
        webhook_url = f"http://shuffle-webhook.shuffle.svc.cluster.local:5001/api/v1/hooks/{trigger_id}"
        print(f">>> Discovered webhook URL: {webhook_url}")
        return webhook_url
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: auto-setup-shuffle.py <admin_password>")
        sys.exit(1)
        
    password = sys.argv[1]
    script_dir = os.path.dirname(__file__)
    playbooks_dir = os.path.join(script_dir, "..", "playbooks")
    
    wait_for_shuffle()
    auth = login(password)
    if not auth:
        print(">>> Could not retrieve auth token. Manual Shuffle setup required.")
        sys.exit(0)
        
    wf_ids = import_playbooks(auth, playbooks_dir)
    
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
