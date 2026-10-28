# k8s-soar — one entry point for everything. `make help` lists targets.
SHELL := /usr/bin/env bash
ENV ?= default
HELMFILE := helmfile -f deploy/helmfile.yaml.gotmpl -e $(ENV)
SOAR_NS := k8s-soar
REGISTRY ?= ghcr.io/joesabbagh1
TAG ?= $(shell awk '/^appVersion:/ {gsub(/"/,"",$$2); print $$2}' charts/k8s-soar/Chart.yaml)
PY := services/soar/.venv/bin

.DEFAULT_GOAL := help

##@ Install
bootstrap: ## Bare metal: kubeadm cluster + full stack (runs deploy/ansible/setup.sh)
	cd deploy/ansible && ./setup.sh

preflight: ## Check tools and cluster prerequisites
	./scripts/preflight.sh

setup: ## Guided setup: questions, then install (./k8s-soar setup)
	./k8s-soar setup

configure: ## Change response, decisions, AI or notifications (./k8s-soar configure)
	./k8s-soar configure

update: ## Pull main and run its CI-built images, no release needed (./k8s-soar update)
	./k8s-soar update

dev: ## Dev mode: pods run services/soar/src from this checkout (./k8s-soar dev on)
	./k8s-soar dev on

dev-off: ## Leave dev mode
	./k8s-soar dev off

test-notify: ## Send a test message to every configured channel
	./k8s-soar test-notify

secrets: ## Create/update Kubernetes Secrets from deploy/secrets.env
	./scripts/secrets.sh

ai-key: ## Store the AI provider key: make ai-key KEY=sk-...
	@test -n "$(KEY)" || (echo "usage: make ai-key KEY=<provider api key>"; exit 1)
	AI_API_KEY="$(KEY)" K8S_SOAR_SECRETS_FILE=/dev/null ./scripts/secrets.sh
	kubectl rollout restart deploy/soar-agent -n $(SOAR_NS) 2>/dev/null || true

diff: ## Show what `make deploy` would change
	$(HELMFILE) diff

deploy: secrets ## Install/upgrade the whole stack on the current cluster (ENV=default|lab)
	$(HELMFILE) apply --skip-diff-on-install

deploy-soar: ## Upgrade only the k8s-soar chart (rules, policies, response, agent)
	$(HELMFILE) -l name=k8s-soar apply --skip-diff-on-install

destroy: ## Uninstall every release (CRDs and namespaces are kept)
	$(HELMFILE) destroy

##@ Operate
status: ## Health check of the deployed stack
	./scripts/verify.sh

verify: status

cases: ## List SOAR cases (Argo workflows)
	@kubectl get workflows -n $(SOAR_NS) --sort-by=.metadata.creationTimestamp \
	  -o custom-columns='CASE:.metadata.name,RULE:.metadata.labels.k8s-soar\.io/rule,NAMESPACE:.metadata.labels.k8s-soar\.io/namespace,POD:.metadata.labels.k8s-soar\.io/pod,STATUS:.status.phase,STARTED:.status.startedAt'

quarantined: ## List quarantined pods
	@kubectl get pods -A -l security.quarantine=true -L k8s-soar.io/case

# Listens on all interfaces so the UI is reachable from outside the operator
# machine (e.g. a remote lab box). Use ARGO_UI_ADDRESS=127.0.0.1 to keep it local.
ARGO_UI_ADDRESS ?= 0.0.0.0

argo-ui: ## Open the case list on http://<this machine>:2746/workflows/k8s-soar
	@echo "Cases:   http://$$(hostname -I 2>/dev/null | awk '{print $$1}' || echo localhost):2746/workflows/$(SOAR_NS)"
	kubectl port-forward --address $(ARGO_UI_ADDRESS) -n argo svc/argo-workflows-server 2746:2746

# Same reasoning as argo-ui: reachable from outside a remote lab box.
CONSOLE_ADDRESS ?= 0.0.0.0

console: ## Open the analyst console on http://<this machine>:8081
	@echo "Console: http://$$(hostname -I 2>/dev/null | awk '{print $$1}' || echo localhost):8081"
	kubectl port-forward --address $(CONSOLE_ADDRESS) -n $(SOAR_NS) svc/soar-console 8081:8080

GRAFANA_ADDRESS ?= 0.0.0.0

grafana: ## Open Grafana on http://<this machine>:3000 (the console links here)
	@echo "Grafana: http://$$(hostname -I 2>/dev/null | awk '{print $$1}' || echo localhost):3000  user: admin  password: make grafana-password"
	kubectl port-forward --address $(GRAFANA_ADDRESS) -n monitoring svc/kube-prometheus-stack-grafana 3000:80

grafana-password: ## Print the Grafana admin password
	@kubectl get secret -n monitoring grafana-admin -o jsonpath='{.data.admin-password}' | base64 -d; echo

smoke-test: ## End-to-end test: trigger a rule and check containment (ARGS=--keep keeps the test pod)
	./scripts/smoke-test.sh $(ARGS)

# Attack scenarios live in scenarios/<id>-<name>/run.sh.
# `make <name>` runs one (same shape as smoke-test). The numbered directory
# name is an alias: `make shell-in-container` and `make 01-shell-in-container`.
# Scenarios run in the default namespace.
SCENARIO_DIRS := $(patsubst scenarios/%/run.sh,%,$(wildcard scenarios/*/run.sh))
scenario_slug = $(patsubst $(firstword $(subst -, ,$(1)))-%,%,$(1))

define scenario_rule
.PHONY: $(call scenario_slug,$(1))
$(call scenario_slug,$(1)):
	SCENARIO_TARGET=$$(TARGET) ./scenarios/$(1)/run.sh $$(ARGS)
ifneq ($(1),$(call scenario_slug,$(1)))
.PHONY: $(1)
$(1): $(call scenario_slug,$(1))
endif
endef

$(foreach dir,$(SCENARIO_DIRS),$(eval $(call scenario_rule,$(dir))))

scenario-reset:
	./scripts/lab/reset-scenario-lab.sh

DEMO_FILE := deploy/demo/shop.yaml

demo-app: ## Install the demo customer app (web, API, db in namespace shop)
	kubectl apply -f $(DEMO_FILE)
	kubectl rollout status -n shop deploy/web deploy/api deploy/db --timeout=180s
	@echo "Demo app ready: kubectl get pods -n shop. Scenarios that support it now target it automatically (TARGET=own to opt out)"

demo-app-delete: ## Remove the demo app
	kubectl delete -f $(DEMO_FILE) --ignore-not-found

verify-attack: ## Check what k8s-soar did after an attack: make verify-attack ATTACK=crypto-miner (or all)
	@test -n "$(ATTACK)" || (echo "usage: make verify-attack ATTACK=<scenario>|all [ARGS=--since 30]"; exit 1)
	./scripts/verify-attack.py $(ATTACK) $(ARGS)

scenarios-all:
	./scenarios/run-all.sh

##@ Develop
venv: $(PY)/pytest ## Create the Python dev environment
$(PY)/pytest:
	python3 -m venv services/soar/.venv
	$(PY)/pip install -q -e "services/soar[agent,console,dev]"

test: venv ## Unit tests (Python services)
	cd services/soar && .venv/bin/pytest -q

lint: venv ## Lint Python, shell, chart and helmfile
	cd services/soar && .venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests
	shellcheck -x scripts/*.sh scripts/lab/*.sh deploy/ansible/*.sh deploy/ansible/lib/*.sh
	helm lint charts/k8s-soar
	helm template k8s-soar charts/k8s-soar --set ai.enabled=true --set lab.enabled=true >/dev/null

images: ## Build the service images (REGISTRY=..., TAG=...)
	docker build --target actions -t $(REGISTRY)/k8s-soar-actions:$(TAG) services/soar
	docker build --target console -t $(REGISTRY)/k8s-soar-console:$(TAG) services/soar
	docker build --target agent -t $(REGISTRY)/k8s-soar-agent:$(TAG) services/soar

push: images ## Push the service images
	docker push $(REGISTRY)/k8s-soar-actions:$(TAG)
	docker push $(REGISTRY)/k8s-soar-console:$(TAG)
	docker push $(REGISTRY)/k8s-soar-agent:$(TAG)

help:
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target> [ENV=default|lab]\n"} \
	  /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
	@printf "\n\033[1mScenarios\033[0m  (make deploy first; make <attack> runs one, like smoke-test)\n"
	@for dir in scenarios/[0-9][0-9]-*/run.sh; do \
	  name=$$(basename "$$(dirname "$$dir")"); \
	  slug=$${name#[0-9][0-9]-}; \
	  printf "  \033[36m%-32s\033[0m %s\n" "$$slug" "$$name"; \
	done
	@printf "  \033[36m%-32s\033[0m %s\n" "scenario-reset" "delete scenario pods and clear victim quarantine"
	@printf "  \033[36m%-32s\033[0m %s\n" "scenarios-all" "run every attack in sequence"

.PHONY: setup configure update dev dev-off test-notify bootstrap preflight secrets ai-key diff deploy deploy-soar destroy status verify cases quarantined \
	argo-ui console grafana grafana-password smoke-test scenario-reset demo-app demo-app-delete verify-attack scenarios-all venv test lint images push help
