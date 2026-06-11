.PHONY: all clean build-bpf build-policy build-daemon generate test help

# Default target
all: build-bpf generate build-policy build-daemon

# Help target
help:
	@echo "warmor - WASM-powered security enforcer"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build everything (default)"
	@echo "  build-bpf     - Compile eBPF program"
	@echo "  generate      - Generate eBPF Go bindings"
	@echo "  build-policy  - Build WASM policy"
	@echo "  build-daemon  - Build warmor daemon"
	@echo "  test          - Run tests"
	@echo "  clean         - Clean build artifacts"
	@echo ""
	@echo "Usage:"
	@echo "  make all              # Build everything"
	@echo "  sudo ./warmor-daemon  # Run enforcer"

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