.PHONY: all clean build-bpf build-policy build-daemon generate test help \
	deploy deploy-audit undeploy status logs policy-check upgrade

NAMESPACE ?= warmor-system
RELEASE ?= warmor
CHART ?= deploy/helm/warmor
POLICY ?= examples/policies/kubernetes-hardening.yaml

# Default target
all: build-bpf generate build-policy build-daemon

# Help target
help:
	@echo "warmor - WASM-powered security enforcer"
	@echo ""
	@echo "Build Targets:"
	@echo "  all           - Build everything (default)"
	@echo "  build-bpf     - Compile eBPF program"
	@echo "  generate      - Generate eBPF Go bindings"
	@echo "  build-policy  - Build WASM policy"
	@echo "  build-daemon  - Build warmor daemon"
	@echo "  test          - Run tests"
	@echo "  clean         - Clean build artifacts"
	@echo ""
	@echo "Deploy Targets:"
	@echo "  deploy        - Deploy to Kubernetes (enforce mode)"
	@echo "  deploy-audit  - Deploy in audit-only mode (safe, no blocking)"
	@echo "  undeploy      - Remove from cluster"
	@echo "  upgrade       - Upgrade existing deployment"
	@echo "  status        - Show deployment status"
	@echo "  logs          - Tail daemon logs"
	@echo "  policy-check  - Validate a policy file"
	@echo ""
	@echo "Variables:"
	@echo "  NAMESPACE     - Target namespace (default: warmor-system)"
	@echo "  RELEASE       - Helm release name (default: warmor)"
	@echo "  POLICY        - Policy file to use (default: examples/policies/kubernetes-hardening.yaml)"
	@echo ""
	@echo "Examples:"
	@echo "  make deploy-audit                              # Safe first deploy"
	@echo "  make deploy POLICY=examples/policies/block-crypto-miners.yaml"
	@echo "  make logs                                      # Watch events"
	@echo "  make upgrade                                   # Apply changes"

# Build eBPF program
build-bpf:
	@echo "==> Building eBPF program..."
	cd bpf && $(MAKE)

# Generate eBPF Go bindings
generate: build-bpf
	@echo "==> Generating eBPF Go bindings..."
	go generate ./internal/ebpf

# Build WASM policy
build-policy:
	@echo "==> Building WASM policy..."
	cd policies/example && $(MAKE)

# Build warmor daemon
build-daemon:
	@echo "==> Building warmor daemon..."
	go build -o warmor-daemon ./cmd/warmor-daemon

# Build test tools
build-tests:
	@echo "==> Building test tools..."
	go build -o test-ebpf ./cmd/test-ebpf
	go build -o test-wasm ./cmd/test-wasm

# Run tests
test:
	@echo "==> Running tests..."
	go test ./...

# Clean build artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	cd bpf && $(MAKE) clean
	cd policies/example && $(MAKE) clean
	rm -f warmor-daemon test-ebpf test-wasm
	rm -f internal/ebpf/execve_monitor_bpfeb.go
	rm -f internal/ebpf/execve_monitor_bpfeb.o
	rm -f internal/ebpf/execve_monitor_bpfel.go
	rm -f internal/ebpf/execve_monitor_bpfel.o
	go clean

# Install dependencies
deps:
	@echo "==> Installing Go dependencies..."
	go mod download
	@echo "==> Installing Rust WASI target..."
	rustup target add wasm32-unknown-unknown

# --- Deployment Targets ---

# Deploy in enforce mode
deploy:
	@echo "==> Deploying warmor (enforce mode)..."
	helm upgrade --install $(RELEASE) $(CHART) \
		--namespace $(NAMESPACE) --create-namespace \
		--set daemon.auditMode=false \
		--set-file policy.yaml=$(POLICY)

# Deploy in audit-only mode (safe for initial rollout)
deploy-audit:
	@echo "==> Deploying warmor (audit mode - no blocking)..."
	helm upgrade --install $(RELEASE) $(CHART) \
		--namespace $(NAMESPACE) --create-namespace \
		--set daemon.auditMode=true \
		--set-file policy.yaml=$(POLICY)

# Upgrade existing deployment
upgrade:
	@echo "==> Upgrading warmor..."
	helm upgrade $(RELEASE) $(CHART) \
		--namespace $(NAMESPACE) \
		--reuse-values

# Remove from cluster
undeploy:
	@echo "==> Removing warmor..."
	helm uninstall $(RELEASE) --namespace $(NAMESPACE)

# Show status
status:
	@echo "==> Warmor Status"
	@echo ""
	@echo "--- Helm Release ---"
	@helm status $(RELEASE) -n $(NAMESPACE) 2>/dev/null || echo "Not deployed"
	@echo ""
	@echo "--- Pods ---"
	@kubectl get pods -n $(NAMESPACE) -l app.kubernetes.io/name=warmor -o wide 2>/dev/null || true
	@echo ""
	@echo "--- DaemonSet ---"
	@kubectl get ds -n $(NAMESPACE) -l app.kubernetes.io/name=warmor 2>/dev/null || true

# Tail logs
logs:
	kubectl logs -n $(NAMESPACE) -l app.kubernetes.io/name=warmor -f --tail=50

# Validate a policy file
policy-check:
	@echo "==> Validating policy: $(POLICY)"
	@go run ./cmd/warmor-daemon --validate-policy $(POLICY)