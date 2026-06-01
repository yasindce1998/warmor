#!/bin/bash
set -e

echo "=== Warmor WSL2 Setup Script ==="
echo ""

# Update system
echo "[1/6] Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

# Install build dependencies
echo "[2/6] Installing build dependencies..."
sudo apt-get install -y -qq \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    wget \
    curl \
    git

# Install Go
echo "[3/6] Installing Go 1.21.5..."
if ! command -v go &> /dev/null; then
    cd /tmp
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    rm go1.21.5.linux-amd64.tar.gz
else
    echo "Go already installed: $(go version)"
fi

# Install Rust
echo "[4/6] Installing Rust..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q
    source ~/.cargo/env
    rustup target add wasm32-unknown-unknown
else
    echo "Rust already installed: $(rustc --version)"
    rustup target add wasm32-unknown-unknown 2>/dev/null || true
fi

# Verify installations
echo "[5/6] Verifying installations..."
echo "  Go: $(go version)"
echo "  Rust: $(rustc --version)"
echo "  Clang: $(clang --version | head -n1)"
echo "  LLVM: $(llvm-config --version)"

# Check kernel version
echo "[6/6] Checking kernel compatibility..."
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
echo "  Kernel: $(uname -r)"
if (( $(echo "$KERNEL_VERSION >= 5.8" | bc -l) )); then
    echo "  ✅ Kernel version is compatible with eBPF"
else
    echo "  ⚠️  Kernel version may not support all eBPF features"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Reload shell: source ~/.bashrc"
echo "  2. Build eBPF programs: cd bpf && make"
echo "  3. Build WASM policies: cd policies/example && cargo build --release --target wasm32-unknown-unknown"
echo "  4. Build warmor: go build -o warmor cmd/warmor/main.go"
echo "  5. Run tests: go test ./... -v"


