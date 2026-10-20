# attache developer entry points. The minikube path is: make minikube-up build deploy demo
SHELL := /bin/bash
NS ?= attache-demo
PROFILE ?= minikube
ATTACHE := ./target/debug/attache
.PHONY: local-demo all build-host test test-rust test-python fmt lint proto schema validate \
        minikube-up minikube-down build deploy charters undeploy demo logs logs-denied secret-anthropic clean dev-certs

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

# Regenerate the Python gRPC stubs (committed) from proto/.
proto:
	cd runtime && uv run python -m grpc_tools.protoc -I ../proto \
	  --python_out=src/attache_runtime/pb --grpc_python_out=src/attache_runtime/pb --pyi_out=src/attache_runtime/pb \
	  ../proto/attache/v1alpha1/common.proto ../proto/attache/v1alpha1/app.proto \
	  ../proto/attache/v1alpha1/mesh.proto ../proto/attache/v1alpha1/runtime.proto
	sed -i '' -E 's/^from attache\.v1alpha1 import/from attache_runtime.pb.attache.v1alpha1 import/' runtime/src/attache_runtime/pb/attache/v1alpha1/*_pb2*.py

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
	kubectl config use-context $(PROFILE)
	kubectl get nodes

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
	kubectl -n $(NS) create configmap orders-charter --from-file=charter.yaml=examples/charters/orders.charter.yaml --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n $(NS) create configmap inventory-charter --from-file=charter.yaml=examples/charters/inventory.charter.yaml --dry-run=client -o yaml | kubectl apply -f -

deploy:
	kubectl apply -f deploy/namespace.yaml
	$(MAKE) charters
	kubectl -n $(NS) delete job embassy-bootstrap --ignore-not-found
	kubectl apply -k deploy/
	kubectl -n $(NS) wait --for=condition=complete job/embassy-bootstrap --timeout=180s
	kubectl -n $(NS) rollout restart deployment/orders deployment/inventory
	kubectl -n $(NS) rollout status deployment/orders --timeout=300s
	kubectl -n $(NS) rollout status deployment/inventory --timeout=300s
	kubectl -n $(NS) get pods,svc,secrets

undeploy:
	kubectl delete -k deploy/ --ignore-not-found

# Optional: real Claude instead of the mock model. Pods pick the key up on their next restart.
secret-anthropic:
	@test -n "$$ANTHROPIC_API_KEY" || (echo "ANTHROPIC_API_KEY is not set" && exit 1)
	kubectl -n $(NS) create secret generic attache-anthropic --from-literal=ANTHROPIC_API_KEY="$$ANTHROPIC_API_KEY" --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n $(NS) rollout restart deployment/orders deployment/inventory

# The same demo on this machine without Kubernetes (two sidecars, mTLS, real runtime, both apps).
local-demo:
	./scripts/local-demo.sh

demo: $(ATTACHE)
	ATTACHE=$(ATTACHE) NS=$(NS) ./scripts/demo.sh

# make logs [TRACE=<trace id prefix>] [AGENT=<agent>]
logs: $(ATTACHE)
	$(ATTACHE) logs orders,inventory -n $(NS) $(if $(TRACE),--trace $(TRACE)) $(if $(AGENT),--agent $(AGENT))

logs-denied: $(ATTACHE)
	$(ATTACHE) logs orders,inventory -n $(NS) --denied

$(ATTACHE):
	cargo build -p attache-cli

clean:
	cargo clean
	rm -rf runtime/.venv .local
