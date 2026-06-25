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
        return None

def wait_for_shuffle():
    print(">>> Waiting for Shuffle API to become responsive on localhost:3001...")
    for _ in range(60):
        try:
            req = urllib.request.Request(f"{BASE_URL}/info", method="GET")
            urllib.request.urlopen(req, timeout=5)
            print(">>> Shuffle API is up!")
            return True
        except:
            time.sleep(5)
    print(">>> Error: Timed out waiting for Shuffle API.")
    sys.exit(1)

def register_and_login(password):
    print(">>> Attempting to register admin user...")
    payload = {"username": USERNAME, "password": password}
    res = make_request("/register", payload)
    if not res:
        res = make_request("/setuppassword", payload)
        
    print(">>> Attempting to login...")
    login_res = make_request("/login", payload)
    if not login_res or not login_res.get("success"):
        print(">>> Failed to login. Shuffle might already be configured.")
        sys.exit(0)
        
    return login_res.get("token") or login_res.get("access_token")

def import_playbooks(token, playbooks_dir):
    playbook_files = glob.glob(os.path.join(playbooks_dir, "*.json"))
    if not playbook_files:
        print(f">>> No playbooks found in {playbooks_dir}")
        return []
        
    imported_ids = []
    for pb_path in playbook_files:
        with open(pb_path, 'r') as f:
            workflow_data = json.load(f)
            
        print(f">>> Importing Workflow: {os.path.basename(pb_path)}...")
        res = make_request("/workflows", payload=workflow_data, token=token)
        if res and res.get("id"):
            imported_ids.append(res.get("id"))
            print(f">>> Successfully imported {os.path.basename(pb_path)} with ID: {res.get('id')}")
        else:
            print(f">>> Failed to import {os.path.basename(pb_path)}.")
            
    return imported_ids

def generate_webhook(token, workflow_id):
    res = make_request(f"/workflows/{workflow_id}", token=token, method="GET")
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
    token = register_and_login(password)
    if not token:
        print(">>> Could not retrieve auth token. Manual Shuffle setup required.")
        sys.exit(0)
        
    wf_ids = import_playbooks(token, playbooks_dir)
    
    found_webhook = False
    for wf_id in wf_ids:
        webhook_url = generate_webhook(token, wf_id)
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
