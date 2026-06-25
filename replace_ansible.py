import re

with open('ansible/site.yml', 'r') as f:
    content = f.read()

# We want to replace everything from "Install k8s-soar stack (split Helm releases)" to "Wait for nodes to become Ready"
replacement = """    - name: Install python3-yaml for rendering
      ansible.builtin.apt:
        name: python3-yaml
        state: present
      become: true
      delegate_to: localhost
      
    - name: Render Helm values
      ansible.builtin.command: ./scripts/render-helm-values.sh
      environment:
        K8S_SOAR_ENABLE_SOAR: "{{ enable_soar | bool | ternary('1', '0') }}"
        K8S_SOAR_ENABLE_OBSERVABILITY: "{{ enable_observability | default(true) | bool | ternary('1', '0') }}"
      args:
        chdir: "{{ k8s_soar_chart_path }}"

    - name: Load rendered Helm values
      ansible.builtin.slurp:
        src: "{{ k8s_soar_chart_path }}/.generated/helm-values.yaml"
      register: slurp_helm_values

    - name: Parse rendered values
      ansible.builtin.set_fact:
        helm_values: "{{ slurp_helm_values.content | b64decode | from_yaml }}"

    - name: Read chart versions from Chart.lock
      ansible.builtin.slurp:
        src: "{{ k8s_soar_chart_path }}/Chart.lock"
      register: slurp_chart_lock

    - name: Parse Chart.lock
      ansible.builtin.set_fact:
        chart_lock: "{{ slurp_chart_lock.content | b64decode | from_yaml }}"

    - name: Map chart versions
      ansible.builtin.set_fact:
        versions: >-
          {{
            chart_lock.dependencies | items2dict(key_name='name', value_name='version')
          }}

    - name: Add Shuffle Helm repo
      ansible.builtin.shell: helm repo add shuffle https://frikky.github.io/Shuffle 2>/dev/null || true
      changed_when: false

    - name: Install Cilium
      ansible.builtin.command: >
        helm upgrade --install cilium charts/cilium-{{ versions['cilium'] }}.tgz
        --namespace kube-system --create-namespace
        -f .generated/cilium-values.yaml
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"
      when: helm_values.cilium.enabled | default(false) | bool

    - name: Wait for nodes after Cilium
      ansible.builtin.command: kubectl wait --for=condition=Ready nodes --all --timeout=600s
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"
      when: helm_values.cilium.enabled | default(false) | bool

    - name: Install Kyverno
      ansible.builtin.command: >
        helm upgrade --install kyverno charts/kyverno-{{ versions['kyverno'] }}.tgz
        --namespace kyverno --create-namespace
        -f .generated/kyverno-values.yaml
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"
      when: helm_values.kyverno.enabled | default(false) | bool

    - name: Install Loki
      ansible.builtin.command: >
        helm upgrade --install loki charts/loki-{{ versions['loki'] }}.tgz
        --namespace monitoring --create-namespace
        -f .generated/loki-values.yaml
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"
      when: helm_values.observability.enabled | default(false) | bool

    - name: Install Promtail
      ansible.builtin.command: >
        helm upgrade --install promtail charts/promtail-{{ versions['promtail'] }}.tgz
        --namespace monitoring
        -f .generated/promtail-values.yaml
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"
      when: helm_values.observability.enabled | default(false) | bool

    - name: Install kube-prometheus-stack
      ansible.builtin.command: >
        helm upgrade --install kube-prometheus-stack charts/kube-prometheus-stack-{{ versions['kube-prometheus-stack'] }}.tgz
        --namespace monitoring
        -f .generated/kube-prometheus-stack-values.yaml
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"
      when: helm_values.observability.enabled | default(false) | bool

    - name: Install Falco
      ansible.builtin.command: >
        helm upgrade --install falco charts/falco-{{ versions['falco'] }}.tgz
        --namespace falco --create-namespace
        -f .generated/falco-values.yaml
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"
      when: helm_values.falco.enabled | default(false) | bool

    - name: Install Tetragon
      ansible.builtin.command: >
        helm upgrade --install tetragon charts/tetragon-{{ versions['tetragon'] }}.tgz
        --namespace kube-system
        -f .generated/tetragon-values.yaml
        --set crds.installMethod=operator
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"
      when: helm_values.tetragon.enabled | default(false) | bool

    - name: Install k8s-soar parent
      ansible.builtin.command: >
        helm upgrade --install k8s-soar .
        --namespace k8s-soar --create-namespace
        -f .generated/k8s-soar-values.yaml
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"

    - name: Apply policies and lab
      ansible.builtin.shell: |
        ./scripts/wait-for-policy-crds.sh
        ./scripts/apply-policies-lab.sh
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"

    - name: Install Shuffle
      ansible.builtin.command: >
        helm upgrade --install shuffle shuffle/shuffle
        --namespace shuffle --create-namespace
        --set opensearch.enabled=true --set worker.replicas=1
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"

    - name: Wait for all pods to be Ready (this may take minutes)
      ansible.builtin.shell: |
        kubectl get pods -A --no-headers | awk '{if ($4 != "Running" && $4 != "Completed") print $1"/"$2" ("$4")"}' | grep -v "^$" || true
      register: not_ready
      until: not_ready.stdout == ""
      retries: 90
      delay: 10
      changed_when: false
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"

    - name: Reconcile Falco metrics wiring
      ansible.builtin.command: >
        helm upgrade falco charts/falco-{{ versions['falco'] }}.tgz
        --namespace falco
        -f .generated/falco-values.yaml
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"
      when: helm_values.observability.enabled | default(false) | bool

    - name: Auto-setup Shuffle Playbooks (Background port-forward)
      ansible.builtin.shell: |
        kubectl port-forward svc/shuffle-frontend -n shuffle 3001:3000 > /dev/null 2>&1 &
        PF_PID=$!
        sleep 3
        python3 ./scripts/auto-setup-shuffle.py || true
        kill $PF_PID > /dev/null 2>&1 || true
      args:
        chdir: "{{ k8s_soar_chart_path }}"
      environment:
        KUBECONFIG: "{{ kubeconfig_dest }}"

"""

start_str = "    - name: Install k8s-soar stack (split Helm releases)"
end_str = "    - name: Run verify-stack script"

start_idx = content.find(start_str)
end_idx = content.find(end_str)

new_content = content[:start_idx] + replacement + content[end_idx:]

with open('ansible/site.yml', 'w') as f:
    f.write(new_content)

