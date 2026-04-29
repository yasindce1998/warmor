# Warmor Quick Start Guide

## Prerequisites

- Go 1.23 or higher
- Linux kernel 5.10+ (for eBPF support)
- Git

## Installation

```bash
# Clone the repository
git clone https://github.com/yasindce1998/warmor.git
cd warmor

# Install dependencies
go mod download

# Build the enforcer
go build -o warmor ./enforcer
```

## Running Warmor

### Basic Usage

```bash
# Run with default settings
./warmor

# The enforcer will:
# - Load policies from enforcer/policy.yaml
# - Start simulating events
# - Report statistics every 30 seconds
# - Log all policy decisions
```

### Custom Configuration

```bash
# Use a custom policy file
./warmor -policy /path/to/custom-policy.yaml

# Enable debug logging with console output
./warmor -log-level debug -log-format console

# Change statistics reporting interval
./warmor -stats-interval 10s

# Combine options
./warmor -policy custom.yaml -log-level debug -stats-interval 5s
```

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-policy` | `enforcer/policy.yaml` | Path to policy configuration file |
| `-log-level` | `info` | Log level: debug, info, warn, error |
| `-log-format` | `json` | Log format: json, console |
| `-stats-interval` | `30s` | Statistics reporting interval |

## Understanding the Output

### JSON Logs (default)
```json
{"level":"info","component":"enforcer","time":"2026-04-29T11:25:00Z","message":"Warmor Enforcer starting..."}
{"level":"warn","pid":1234,"uid":0,"process":"/bin/bash","decision":"DENIED","reason":"Prevent root shell access","duration":"45.2µs","message":"Policy enforcement: DENIED"}
```

### Console Logs
```
11:25:00 INF Warmor Enforcer starting... component=enforcer
11:25:00 WRN Policy enforcement: DENIED decision=DENIED duration=45.2µs pid=1234 process=/bin/bash reason="Prevent root shell access" uid=0
```

### Statistics Report
```
=== Warmor Statistics ===
Total Evaluations: 24
Allowed: 6 (25.0%)
Denied: 15 (62.5%)
Logged: 3 (12.5%)
Average Duration: 45.2µs
========================
```

## Policy Configuration

Edit `enforcer/policy.yaml` to customize policies:

```yaml
policies:
  - uid: 0
    process: "/bin/bash"
    action: "deny"
    reason: "Prevent root shell access"
    
  - uid: 1000
    process: "/usr/bin/python3"
    action: "deny"
    reason: "User 1000 denied to run Python scripts"
    
  - uid: 1001
    process: "/usr/bin/node"
    action: "allow"
    reason: "User 1001 allowed to run Node.js applications"
```

### Policy Fields

- **uid**: User ID to match (required)
- **process**: Process path or pattern (required)
- **action**: `deny`, `allow`, or `log` (required)
- **reason**: Human-readable explanation (optional but recommended)

### Pattern Matching

Warmor supports wildcard patterns:

- **Exact match**: `/bin/bash` matches only `/bin/bash`
- **Prefix wildcard**: `/tmp/go-build*` matches `/tmp/go-build123`, `/tmp/go-build456`, etc.
- **Suffix wildcard**: `*/bash` matches `/bin/bash`, `/usr/bin/bash`, etc.
- **Contains wildcard**: `*local*` matches `/usr/local/bin/node`, `/opt/local/app`, etc.

## Testing

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test ./... -v

# Run tests for specific package
go test ./enforcer/policy/... -v

# Run tests with coverage
go test ./... -cover
```

## Stopping Warmor

Press `Ctrl+C` to gracefully shutdown. Warmor will:
1. Stop processing events
2. Print final statistics
3. Clean up resources
4. Exit

## Troubleshooting

### "Failed to load policies"
- Check that the policy file exists
- Verify YAML syntax is correct
- Ensure all required fields are present

### "Permission denied"
- eBPF requires root privileges on Linux
- Run with `sudo ./warmor` if needed

### High CPU usage
- Reduce stats interval: `-stats-interval 60s`
- Lower log level: `-log-level warn`

## Next Steps

1. **Customize policies** - Edit `enforcer/policy.yaml` for your use case
2. **Review logs** - Analyze policy decisions and violations
3. **Monitor statistics** - Track enforcement patterns
4. **Integrate with monitoring** - Coming in Phase 2 (Prometheus/Grafana)

## Getting Help

- **Documentation**: See `docs/` directory
- **Implementation Plan**: `docs/implementation-plan.md`
- **Architecture**: `docs/architecture.md`
- **GitHub Issues**: Report bugs and request features

## What's Working

✅ Policy loading and validation  
✅ Policy evaluation with pattern matching  
✅ Structured logging (JSON and console)  
✅ Statistics tracking and reporting  
✅ Graceful shutdown  
✅ Policy hot-reloading  

## What's Coming

🔄 Phase 2: Prometheus metrics, Grafana dashboards, alerting  
🔄 Phase 3: Kubernetes deployment, Helm charts  
🔄 Phase 4: Network/file monitoring, multi-runtime support  
🔄 Phase 5: Comprehensive testing, Policy as Code framework  
🔄 Phase 6: Complete documentation, CI/CD pipeline  

---

**Version:** 0.1.0 (Phase 1 Complete)  
**Last Updated:** 2026-04-29