# attache developer entry points.
#   v0.1 minikube path (explicit sidecars):  make minikube-up build deploy demo
#   v0.2 minikube path (Helm, injection):    make demo-helm
#   v0.2 one machine (Docker Compose):       make compose-up / make compose-down
SHELL := /bin/bash
NS ?= attache-demo
PROFILE ?= minikube
# Every cluster call names the context explicitly: this kubeconfig may also hold production clusters.
KUBE_CONTEXT ?= $(PROFILE)
KUBECTL := kubectl --context $(KUBE_CONTEXT)
ATTACHE := ./target/debug/attache
EMBASSY := ./target/debug/embassy
# The control-plane namespace and Helm release of the v0.2 chart.
CP_NS ?= attache-system
HELM_RELEASE ?= agent-sidecar
CHART := deploy/helm/agent-sidecar
COMPOSE := docker compose -f deploy/compose/docker-compose.yml
COMPOSE_ENV := deploy/compose/.env
# Tests of the chart, the Compose stack, the Dockerfile and the release workflow (throwaway uv env).
PACKAGING_PYTEST := uv run --no-project --with pytest==8.4.2 --with pyyaml==6.0.2 python -m pytest -q
.PHONY: local-demo all build-host test test-rust test-python fmt lint proto schema validate \
        minikube-up minikube-down build deploy charters undeploy demo logs logs-denied secret-anthropic clean dev-certs \
        compose-up compose-down helm-lint helm-template demo-helm packaging-test

all: build-host test

# ---- host builds and tests --------------------------------------------------------------------
build-host:
	cargo build --workspace
	cd runtime && uv sync

test: test-rust test-python

test-rust:
	cargo test --workspace --no-fail-fast

test-python:
	cd runtime && uv run pytest -q

fmt:
	cargo fmt --all
	cd runtime && uv run ruff format src tests

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cd runtime && uv run ruff check src tests

# Regenerate the Python gRPC stubs (committed) from proto/. `-i.bak` is the in-place form GNU and BSD sed share.
PB_DIR := runtime/src/attache_runtime/pb/attache/v1alpha1
proto:
	cd runtime && uv run python -m grpc_tools.protoc -I ../proto \
	  --python_out=src/attache_runtime/pb --grpc_python_out=src/attache_runtime/pb --pyi_out=src/attache_runtime/pb \
	  ../proto/attache/v1alpha1/common.proto ../proto/attache/v1alpha1/app.proto \
	  ../proto/attache/v1alpha1/mesh.proto ../proto/attache/v1alpha1/runtime.proto \
	  ../proto/attache/v1alpha1/controlplane.proto
	sed -i.bak -E 's/^from attache\.v1alpha1 import/from attache_runtime.pb.attache.v1alpha1 import/' $(PB_DIR)/*_pb2*.py
	rm -f $(PB_DIR)/*.bak

# Regenerate schemas/charter.schema.json from the Rust types (a test fails when it drifts).
schema:
	cargo run -q -p attache-cli -- charter schema > schemas/charter.schema.json

validate:
	cargo run -q -p attache-cli -- charter validate examples/charters/orders.charter.yaml
	cargo run -q -p attache-cli -- charter validate examples/charters/inventory.charter.yaml
	@echo "expecting a rejection:"
	@! cargo run -q -p attache-cli -- charter validate examples/charters/invalid-unknown-field.charter.yaml

# Local certificates for running two sidecars on this machine (not needed for minikube).
dev-certs:
	cargo run -q -p embassy -- ca-init --out .local/ca
	cargo run -q -p embassy -- cert-issue --ca .local/ca --namespace $(NS) --service orders --out .local/tls/orders
	cargo run -q -p embassy -- cert-issue --ca .local/ca --namespace $(NS) --service inventory --out .local/tls/inventory

# ---- minikube ---------------------------------------------------------------------------------
minikube-up:
	@minikube -p $(PROFILE) status >/dev/null 2>&1 || minikube start -p $(PROFILE) --driver=docker --cpus=4 --memory=6g
	$(KUBECTL) get nodes

minikube-down:
	minikube -p $(PROFILE) delete

# Build the four images inside minikube's docker daemon so no registry is needed.
build:
	eval $$(minikube -p $(PROFILE) docker-env) && \
	  docker build -f docker/Dockerfile --target attached -t attache/attached:dev . && \
	  docker build -f docker/Dockerfile --target embassy  -t attache/embassy:dev . && \
	  docker build -t attache/orders:dev examples/orders && \
	  docker build -t attache/inventory:dev examples/inventory
	eval $$(minikube -p $(PROFILE) docker-env) && docker images 'attache/*'

# The committed charters become ConfigMaps (CONTRACT.md §7).
charters: validate
	kubectl -n $(NS) create configmap orders-charter --from-file=charter.yaml=examples/charters/orders.charter.yaml --dry-run=client -o yaml | $(KUBECTL) apply -f -
	kubectl -n $(NS) create configmap inventory-charter --from-file=charter.yaml=examples/charters/inventory.charter.yaml --dry-run=client -o yaml | $(KUBECTL) apply -f -

deploy:
	$(KUBECTL) apply -f deploy/namespace.yaml
	$(MAKE) charters
	$(KUBECTL) -n $(NS) delete job embassy-bootstrap --ignore-not-found
	$(KUBECTL) apply -k deploy/
	$(KUBECTL) -n $(NS) wait --for=condition=complete job/embassy-bootstrap --timeout=180s
	$(KUBECTL) -n $(NS) rollout restart deployment/orders deployment/inventory
	$(KUBECTL) -n $(NS) rollout status deployment/orders --timeout=300s
	$(KUBECTL) -n $(NS) rollout status deployment/inventory --timeout=300s
	$(KUBECTL) -n $(NS) get pods,svc,secrets

undeploy:
	$(KUBECTL) delete -k deploy/ --ignore-not-found

# Optional: real Claude instead of the mock model (make deploy and make demo-helm). Pods pick the key
# up on their next restart. The key goes through stdin, not the command line.
secret-anthropic:
	@test -n "$$ANTHROPIC_API_KEY" || (echo "ANTHROPIC_API_KEY is not set" && exit 1)
	printf %s "$$ANTHROPIC_API_KEY" | kubectl -n $(NS) create secret generic attache-anthropic --from-file=ANTHROPIC_API_KEY=/dev/stdin --dry-run=client -o yaml | $(KUBECTL) apply -f -
	$(KUBECTL) -n $(NS) rollout restart deployment/orders deployment/inventory

# ---- v0.2: Helm chart (docs/design/agent-platform.md §13) ------------------------------------
# The chart's files/crds/charters.attache.io.yaml is a symbolic link to deploy/crds/, so the CRD it
# renders is always the generated one (helm notes the link on stderr).
helm-lint:
	helm lint --strict $(CHART)
	for f in $(CHART)/ci/*-values.yaml; do helm lint --strict $(CHART) -f "$$f" || exit 1; done

# make helm-template [HELM_ARGS='-f my-values.yaml']
helm-template:
	helm template $(HELM_RELEASE) $(CHART) --namespace $(CP_NS) $(HELM_ARGS)

# The v0.2 demo on minikube: the four images in minikube's docker, the chart, an injection-enabled
# namespace, Charter resources made with `attache charter to-cr`, the two apps with the inject label
# and annotations (no sidecar in their spec), then the demo calls of scripts/demo.sh.
demo-helm: minikube-up build
	cargo build -q -p attache-cli -p embassy
	KUBE_CONTEXT=$(KUBE_CONTEXT) CP_NS=$(CP_NS) RELEASE=$(HELM_RELEASE) ATTACHE=$(ATTACHE) EMBASSY=$(EMBASSY) \
	  ./deploy/helm/demo.sh

# ---- v0.2: Docker Compose on one machine (docs/design/agent-platform.md §14) ------------------
# The embassy image is built first: gen-env.sh makes the tokens with `embassy token create`.
compose-up:
	docker build -f docker/Dockerfile --target embassy -t attache/embassy:dev .
	EMBASSY="docker run --rm attache/embassy:dev" ./deploy/compose/gen-env.sh $(COMPOSE_ENV)
	$(COMPOSE) up -d --build
	@echo "console http://localhost:8080 (ATTACHE_ADMIN_TOKEN in $(COMPOSE_ENV)), orders http://localhost:8081, jaeger http://localhost:16686"

# Volumes (CA, store, sidecar state) and .env are kept; `docker compose -p attache down -v` and
# deleting $(COMPOSE_ENV) start over.
compose-down:
	if [[ -f $(COMPOSE_ENV) ]]; then $(COMPOSE) down; else docker compose -p attache down; fi

# Chart (lint, render, RBAC, webhooks, CRD link), Compose (config, flags, gen-env.sh), Dockerfile and
# release workflow checks. Needs helm and docker for the parts that use them (skipped otherwise).
# The release workflow runs this target before it builds anything.
PACKAGING_TESTS := docker/tests deploy/helm/tests deploy/compose/tests
packaging-test:
	cargo build -q -p embassy
	cd runtime && uv run ruff check $(addprefix ../,$(PACKAGING_TESTS)) && uv run ruff format --check $(addprefix ../,$(PACKAGING_TESTS))
	if command -v shellcheck >/dev/null; then shellcheck deploy/helm/demo.sh deploy/compose/gen-env.sh docker/attache-http-ready docker/attache-ready; fi
	EMBASSY_BIN=$(EMBASSY) $(PACKAGING_PYTEST) $(PACKAGING_TESTS)

# The same demo on this machine without Kubernetes (two sidecars, mTLS, real runtime, both apps).
local-demo:
	./scripts/local-demo.sh

demo: $(ATTACHE)
	ATTACHE=$(ATTACHE) NS=$(NS) KUBE_CONTEXT=$(KUBE_CONTEXT) ./scripts/demo.sh

# make logs [TRACE=<trace id prefix>] [AGENT=<agent>]
logs: $(ATTACHE)
	$(ATTACHE) logs orders,inventory -n $(NS) --context $(KUBE_CONTEXT) $(if $(TRACE),--trace $(TRACE)) $(if $(AGENT),--agent $(AGENT))

logs-denied: $(ATTACHE)
	$(ATTACHE) logs orders,inventory -n $(NS) --context $(KUBE_CONTEXT) --denied

$(ATTACHE):
	cargo build -p attache-cli

$(EMBASSY):
	cargo build -p embassy

clean:
	cargo clean
	rm -rf runtime/.venv .local
