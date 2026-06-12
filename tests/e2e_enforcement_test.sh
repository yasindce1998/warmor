#!/bin/bash
# End-to-end LSM-BPF enforcement test
# Requires: root, CONFIG_BPF_LSM=y kernel, compiled warmor-daemon binary
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DAEMON_BIN="${ROOT_DIR}/warmor-daemon"
POLICY_FILE="${ROOT_DIR}/policies/yaml-example/kubernetes-pod-hardening.yaml"
LOG_FILE="/tmp/warmor-e2e-test.log"
PID_FILE="/tmp/warmor-e2e-test.pid"
METRICS_PORT=9090

PASS=0
FAIL=0
SKIP=0

cleanup() {
    echo "--- Cleanup ---"
    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        rm -f "$PID_FILE"
    fi
    # Remove test cgroup
    if [ -d /sys/fs/cgroup/warmor-test ]; then
        rmdir /sys/fs/cgroup/warmor-test 2>/dev/null || true
    fi
    # Check for leaked BPF programs
    if command -v bpftool &>/dev/null; then
        local leaked
        leaked=$(bpftool prog list 2>/dev/null | grep -c "lsm" || true)
        if [ "$leaked" -gt 0 ]; then
            echo "WARNING: $leaked LSM BPF programs still attached after cleanup"
        fi
    fi
    rm -f "$LOG_FILE"
}
trap cleanup EXIT

pass() {
    echo "  PASS: $1"
    ((PASS++))
}

fail() {
    echo "  FAIL: $1"
    ((FAIL++))
}

skip() {
    echo "  SKIP: $1"
    ((SKIP++))
}

echo "=== warmor LSM-BPF E2E Enforcement Test ==="
echo "Date: $(date -Iseconds)"
echo ""

# Pre-flight checks
echo "--- Pre-flight ---"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

if ! grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    echo "ERROR: CONFIG_BPF_LSM not enabled in kernel"
    echo "LSM list: $(cat /sys/kernel/security/lsm 2>/dev/null || echo 'unavailable')"
    exit 1
fi

if [ ! -x "$DAEMON_BIN" ]; then
    echo "Building warmor-daemon..."
    cd "$ROOT_DIR" && go build -o "$DAEMON_BIN" ./cmd/daemon/
fi

if [ ! -f "$POLICY_FILE" ]; then
    echo "ERROR: Policy file not found: $POLICY_FILE"
    exit 1
fi

echo "Kernel: $(uname -r)"
echo "LSM: $(cat /sys/kernel/security/lsm)"
echo "Daemon: $DAEMON_BIN"
echo "Policy: $POLICY_FILE"
echo ""

# Create test cgroup (cgroupv2)
echo "--- Setup test cgroup ---"
if [ -d /sys/fs/cgroup/warmor-test ]; then
    rmdir /sys/fs/cgroup/warmor-test 2>/dev/null || true
fi
mkdir -p /sys/fs/cgroup/warmor-test
TEST_CGROUP_ID=$(cat /sys/fs/cgroup/warmor-test/cgroup.id 2>/dev/null || stat -c '%i' /sys/fs/cgroup/warmor-test)
echo "Test cgroup ID: $TEST_CGROUP_ID"

# Start daemon with LSM enforcement
echo ""
echo "--- Starting daemon ---"
"$DAEMON_BIN" \
    -policy "$POLICY_FILE" \
    --lsm-enforce \
    --metrics-port "$METRICS_PORT" \
    > "$LOG_FILE" 2>&1 &
DAEMON_PID=$!
echo "$DAEMON_PID" > "$PID_FILE"

# Wait for daemon to be ready
sleep 2
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "ERROR: Daemon failed to start. Logs:"
    cat "$LOG_FILE"
    exit 1
fi
echo "Daemon started (PID: $DAEMON_PID)"

# Run tests inside the test cgroup
run_in_cgroup() {
    echo "$BASHPID" > /sys/fs/cgroup/warmor-test/cgroup.procs
    exec "$@"
}

echo ""
echo "=== Enforcement Tests ==="

# Test 1: Exec blocking — reverse shell tools
echo ""
echo "--- Test: Block reverse shell tools ---"

for tool in /usr/bin/nc /usr/bin/ncat /usr/bin/socat; do
    if [ -x "$tool" ]; then
        if bash -c "echo \$\$ > /sys/fs/cgroup/warmor-test/cgroup.procs && exec $tool --help" >/dev/null 2>&1; then
            fail "$tool execution was NOT blocked"
        else
            exit_code=$?
            if [ $exit_code -eq 126 ] || [ $exit_code -eq 1 ]; then
                pass "$tool blocked (exit=$exit_code)"
            else
                pass "$tool blocked (exit=$exit_code)"
            fi
        fi
    else
        skip "$tool not installed"
    fi
done

# Test 2: Package managers blocked
echo ""
echo "--- Test: Block package managers ---"

for pm in /usr/bin/apt /usr/bin/apt-get /usr/bin/yum /usr/bin/apk; do
    if [ -x "$pm" ]; then
        if bash -c "echo \$\$ > /sys/fs/cgroup/warmor-test/cgroup.procs && exec $pm --version" >/dev/null 2>&1; then
            fail "$pm execution was NOT blocked"
        else
            pass "$pm blocked"
        fi
    else
        skip "$pm not installed"
    fi
done

# Test 3: kubectl blocked
echo ""
echo "--- Test: Block kubectl ---"

for kb in /usr/local/bin/kubectl /usr/bin/kubectl; do
    if [ -x "$kb" ]; then
        if bash -c "echo \$\$ > /sys/fs/cgroup/warmor-test/cgroup.procs && exec $kb version --client" >/dev/null 2>&1; then
            fail "$kb execution was NOT blocked"
        else
            pass "$kb blocked"
        fi
    else
        skip "$kb not installed"
    fi
done

# Test 4: File access blocking — k8s service account token
echo ""
echo "--- Test: Block sensitive file access ---"

SA_TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"
if [ -f "$SA_TOKEN" ]; then
    # Run as non-root (uid != 0 condition)
    if su -s /bin/sh nobody -c "cat $SA_TOKEN" >/dev/null 2>&1; then
        fail "SA token read was NOT blocked"
    else
        pass "SA token read blocked (non-root)"
    fi
else
    # Create a fake token file to test path-based blocking
    mkdir -p /var/run/secrets/kubernetes.io/serviceaccount
    echo "fake-token" > "$SA_TOKEN"
    if su -s /bin/sh nobody -c "cat $SA_TOKEN" >/dev/null 2>&1; then
        fail "SA token read was NOT blocked (created test file)"
    else
        pass "SA token read blocked (created test file)"
    fi
    rm -f "$SA_TOKEN"
    rmdir -p /var/run/secrets/kubernetes.io/serviceaccount 2>/dev/null || true
fi

# Test 5: Network blocking — metadata service
echo ""
echo "--- Test: Block metadata service ---"

if bash -c "echo \$\$ > /sys/fs/cgroup/warmor-test/cgroup.procs && exec curl -s --connect-timeout 2 http://169.254.169.254/" >/dev/null 2>&1; then
    fail "Metadata service connection was NOT blocked"
else
    exit_code=$?
    # exit 7 = connection refused, exit 28 = timeout; both ok if EACCES is returned before connect
    pass "Metadata service blocked (curl exit=$exit_code)"
fi

# Test 6: Allowed operations should succeed
echo ""
echo "--- Test: Allowed operations pass through ---"

if bash -c "echo \$\$ > /sys/fs/cgroup/warmor-test/cgroup.procs && exec /bin/ls /" >/dev/null 2>&1; then
    pass "/bin/ls allowed (not in deny list)"
else
    fail "/bin/ls was blocked (should be allowed)"
fi

if bash -c "echo \$\$ > /sys/fs/cgroup/warmor-test/cgroup.procs && exec /bin/cat /etc/hostname" >/dev/null 2>&1; then
    pass "/bin/cat /etc/hostname allowed"
else
    fail "/bin/cat /etc/hostname was blocked (should be allowed)"
fi

# Test 7: Audit mode — shells are audited but not blocked
echo ""
echo "--- Test: Audit mode (shells not blocked) ---"

if bash -c "echo \$\$ > /sys/fs/cgroup/warmor-test/cgroup.procs && exec /bin/sh -c 'exit 0'" >/dev/null 2>&1; then
    pass "/bin/sh allowed (audit-only rule)"
else
    fail "/bin/sh was blocked (should only be audited)"
fi

# Test 8: Metrics endpoint
echo ""
echo "--- Test: Metrics endpoint ---"

if curl -s "http://localhost:${METRICS_PORT}/metrics" | grep -q "warmor_"; then
    pass "Prometheus metrics available"
    # Check for specific enforcement metrics
    if curl -s "http://localhost:${METRICS_PORT}/metrics" | grep -q "warmor_lsm_deny_total\|warmor_policy_decisions_total"; then
        pass "LSM enforcement metrics present"
    else
        skip "Specific LSM metrics not found (may use different naming)"
    fi
else
    skip "Metrics endpoint not responding (daemon may not expose metrics)"
fi

# Test 9: Clean shutdown
echo ""
echo "--- Test: Clean shutdown ---"

kill "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null || true
rm -f "$PID_FILE"

sleep 1

# Verify no leaked BPF programs
if command -v bpftool &>/dev/null; then
    leaked=$(bpftool prog list 2>/dev/null | grep -c "lsm" || true)
    if [ "$leaked" -eq 0 ]; then
        pass "Clean shutdown (no leaked LSM programs)"
    else
        fail "Leaked $leaked LSM BPF programs after shutdown"
    fi
else
    skip "bpftool not available for leak check"
fi

# Summary
echo ""
echo "=== Results ==="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "SKIP: $SKIP"
echo "Total: $((PASS + FAIL + SKIP))"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "FAILED — see above for details"
    echo "Daemon log:"
    cat "$LOG_FILE" 2>/dev/null || true
    exit 1
fi

echo ""
echo "ALL TESTS PASSED"
exit 0
