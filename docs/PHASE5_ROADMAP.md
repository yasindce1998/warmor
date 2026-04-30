# Phase 5: Testing & Validation Roadmap

**Duration:** Weeks 15-16  
**Status:** 🚧 In Progress  
**Goal:** Comprehensive testing and validation of warmor across all implemented features

## Overview

Phase 5 focuses on thorough testing of all warmor components, from unit tests to integration tests, performance benchmarks, and security validation. This phase ensures production readiness.

## Tasks

### Task 5.1: Unit Testing ✅
**Objective:** Test individual components in isolation

**Components to Test:**
- [ ] WASM runtime (`internal/wasm/`)
- [ ] Policy evaluation (`internal/wasm/context.go`)
- [ ] Decision cache (`internal/cache/cache.go`)
- [ ] Pattern matching (`internal/patterns/matcher.go`)
- [ ] Action enforcement (`internal/enforcer/actions.go`)
- [ ] Metrics collection (`internal/metrics/collector.go`)

**Test Coverage Goal:** >80%

**Files to Create:**
- `internal/wasm/runtime_test.go`
- `internal/cache/cache_test.go`
- `internal/patterns/matcher_test.go`
- `internal/enforcer/actions_test.go`
- `internal/metrics/collector_test.go`

### Task 5.2: Integration Testing
**Objective:** Test component interactions

**Test Scenarios:**
- [ ] eBPF → Event → WASM → Decision → Action flow
- [ ] Multi-syscall event handling
- [ ] Cache hit/miss scenarios
- [ ] Metrics collection and export
- [ ] Logging integration
- [ ] Error handling and recovery

**Files to Create:**
- `tests/integration/ebpf_test.go`
- `tests/integration/policy_test.go`
- `tests/integration/cache_test.go`
- `tests/integration/metrics_test.go`

### Task 5.3: Policy Testing
**Objective:** Validate WASM policies work correctly

**Test Policies:**
- [ ] Example policy (basic allow/deny)
- [ ] Advanced policy (7 rules)
- [ ] Multi-syscall policy (14 rules)
- [ ] Cross-platform policy (7 rules)

**Test Cases:**
- [ ] Allow scenarios
- [ ] Deny scenarios
- [ ] Log scenarios
- [ ] Edge cases (null events, invalid JSON)
- [ ] Performance (evaluation time)

**Files to Create:**
- `policies/example/policy_test.go`
- `policies/advanced/policy_test.go`
- `policies/cross-platform/policy_test.go`

### Task 5.4: Platform Testing
**Objective:** Test platform-specific implementations

**Linux Testing:**
- [ ] eBPF program loading
- [ ] Event collection (execve, openat, connect)
- [ ] Enforcement capabilities
- [ ] Kernel compatibility (5.8+, 5.15+, 6.0+)
- [ ] Performance overhead

**Windows Testing:**
- [ ] Stub functionality
- [ ] Test event generation
- [ ] Build on Windows
- [ ] Cross-compilation

**macOS Testing:**
- [ ] Stub functionality
- [ ] Test event generation
- [ ] Build on macOS
- [ ] Cross-compilation

**Files to Create:**
- `internal/platform/linux_test.go`
- `internal/platform/windows_test.go`
- `internal/platform/darwin_test.go`

### Task 5.5: Performance Benchmarking
**Objective:** Measure and optimize performance

**Benchmarks:**
- [ ] Policy evaluation latency
- [ ] Cache lookup performance
- [ ] Pattern matching speed
- [ ] Event processing throughput
- [ ] Memory usage
- [ ] CPU overhead

**Metrics to Collect:**
- Events per second
- Average latency (p50, p95, p99)
- Memory footprint
- CPU utilization
- Cache hit rate

**Files to Create:**
- `benchmarks/policy_bench_test.go`
- `benchmarks/cache_bench_test.go`
- `benchmarks/patterns_bench_test.go`
- `benchmarks/e2e_bench_test.go`

### Task 5.6: Security Validation
**Objective:** Ensure security guarantees

**Security Tests:**
- [ ] WASM sandbox isolation
- [ ] Memory safety (no buffer overflows)
- [ ] Input validation (malformed events)
- [ ] Privilege escalation prevention
- [ ] Race condition testing
- [ ] Denial of service resistance

**Attack Scenarios:**
- [ ] Malicious WASM policy
- [ ] Event flooding
- [ ] Cache poisoning
- [ ] Resource exhaustion
- [ ] Bypass attempts

**Files to Create:**
- `tests/security/sandbox_test.go`
- `tests/security/fuzzing_test.go`
- `tests/security/dos_test.go`

### Task 5.7: End-to-End Testing
**Objective:** Test complete workflows

**Scenarios:**
- [ ] Install → Configure → Run → Monitor
- [ ] Policy update without restart
- [ ] Graceful shutdown
- [ ] Error recovery
- [ ] Multi-policy support
- [ ] Metrics export to Prometheus

**Files to Create:**
- `tests/e2e/install_test.go`
- `tests/e2e/runtime_test.go`
- `tests/e2e/monitoring_test.go`

### Task 5.8: Documentation Testing
**Objective:** Verify documentation accuracy

**Validation:**
- [ ] All code examples compile
- [ ] All commands work as documented
- [ ] Installation instructions are correct
- [ ] Configuration examples are valid
- [ ] Troubleshooting guides are accurate

## Test Environment Setup

### WSL2 Ubuntu Setup
```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install build dependencies
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    pkg-config

# Install Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup target add wasm32-unknown-unknown

# Verify installations
go version
rustc --version
clang --version
```

### Build eBPF Programs
```bash
cd bpf
make clean
make
```

### Build WASM Policies
```bash
# Example policy
cd policies/example
cargo build --release --target wasm32-unknown-unknown

# Advanced policy
cd ../advanced
cargo build --release --target wasm32-unknown-unknown

# Multi-syscall policy
cd ../multi
cargo build --release --target wasm32-unknown-unknown

# Cross-platform policy
cd ../cross-platform
cargo build --release --target wasm32-unknown-unknown
```

### Build warmor
```bash
cd ../..
go generate ./internal/ebpf/...
go build -o warmor cmd/warmor/main.go
```

## Test Execution

### Run Unit Tests
```bash
go test ./internal/... -v -cover
```

### Run Integration Tests
```bash
go test ./tests/integration/... -v
```

### Run Benchmarks
```bash
go test ./benchmarks/... -bench=. -benchmem
```

### Run Security Tests
```bash
go test ./tests/security/... -v
```

### Run E2E Tests
```bash
sudo go test ./tests/e2e/... -v
```

## Success Criteria

### Code Coverage
- [ ] Unit test coverage >80%
- [ ] Integration test coverage >70%
- [ ] Critical paths covered 100%

### Performance
- [ ] Policy evaluation <100μs (p99)
- [ ] Event processing >10,000 events/sec
- [ ] CPU overhead <5%
- [ ] Memory usage <50MB

### Security
- [ ] All security tests pass
- [ ] No memory leaks detected
- [ ] No race conditions found
- [ ] WASM sandbox verified

### Reliability
- [ ] All tests pass consistently
- [ ] No flaky tests
- [ ] Graceful error handling
- [ ] Clean shutdown

## Deliverables

1. **Test Suite** - Comprehensive test coverage
2. **Benchmark Results** - Performance metrics
3. **Security Report** - Security validation results
4. **Test Documentation** - How to run tests
5. **CI/CD Integration** - Automated testing

## Timeline

### Week 15
- Days 1-2: Unit testing (Task 5.1)
- Days 3-4: Integration testing (Task 5.2)
- Day 5: Policy testing (Task 5.3)

### Week 16
- Days 1-2: Platform testing (Task 5.4)
- Day 3: Performance benchmarking (Task 5.5)
- Day 4: Security validation (Task 5.6)
- Day 5: E2E testing and documentation (Task 5.7-5.8)

## Dependencies

- WSL2 Ubuntu with kernel 5.8+
- Go 1.21+
- Rust 1.70+
- Clang/LLVM 14+
- libbpf-dev
- Linux headers

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| eBPF not available in WSL2 | High | Use native Linux VM or cloud instance |
| Test flakiness | Medium | Implement retry logic and better isolation |
| Performance issues | Medium | Profile and optimize hot paths |
| Security vulnerabilities | High | Thorough security testing and fuzzing |

## Next Phase

After Phase 5 completion:
- **Phase 6:** Documentation & Deployment
- Focus on production deployment guides
- Create installation packages
- Write operational runbooks

---

**Phase 5 Status:** 🚧 In Progress  
**Started:** April 30, 2026  
**Target Completion:** May 14, 2026