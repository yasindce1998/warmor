# Quick Start

Get warmor running in under 5 minutes.

## Install Options

### Option A: Kubernetes (Helm)

Deploy as a DaemonSet in **audit-only mode** — nothing is blocked, safe to try on any cluster.

**Prerequisites:**
- Kubernetes 1.25+ cluster with Linux nodes (kernel 5.8+)
- `helm` v3.10+
- `kubectl` configured for your cluster

### Option B: Standalone Binary

Run directly on a Linux host (bare-metal, VM, or for local testing).

**Prerequisites:**
- Linux kernel 5.8+ (x86_64 or arm64)
- Root access (required for eBPF)

```bash
# Download latest release
curl -LO https://github.com/yasindce1998/warmor/releases/latest/download/warmor-daemon-linux-amd64
chmod +x warmor-daemon-linux-amd64
sudo mv warmor-daemon-linux-amd64 /usr/local/bin/warmor-daemon

# Verify
warmor-daemon --version
```

For ARM64 (AWS Graviton, Raspberry Pi):
```bash
curl -LO https://github.com/yasindce1998/warmor/releases/latest/download/warmor-daemon-linux-arm64
chmod +x warmor-daemon-linux-arm64
sudo mv warmor-daemon-linux-arm64 /usr/local/bin/warmor-daemon
```

**Verify checksum:**
```bash
curl -LO https://github.com/yasindce1998/warmor/releases/latest/download/warmor-daemon-linux-amd64.sha256
sha256sum -c warmor-daemon-linux-amd64.sha256
```

**Run with a policy:**
```bash
sudo warmor-daemon --policy examples/policies/kubernetes-hardening.yaml
```

**Run as a systemd service:**
```bash
sudo tee /etc/systemd/system/warmor.service <<EOF
[Unit]
Description=Warmor eBPF Security Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/warmor-daemon --policy /etc/warmor/policy.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now warmor
```

---

## Kubernetes Deployment

## 1. Install (Audit Mode)

```bash
helm install warmor deploy/helm/warmor \
  --namespace warmor-system --create-namespace \
  --set daemon.auditMode=true
```

That's it. Warmor is now observing process executions, file access, and network connections without blocking anything.

## 2. Verify

```bash
# Check pods are running
kubectl -n warmor-system get pods -l app.kubernetes.io/name=warmor

# Check logs for events
kubectl -n warmor-system logs -l app.kubernetes.io/name=warmor --tail=20

# Check metrics endpoint
kubectl -n warmor-system port-forward ds/warmor 9090:9090 &
curl -s http://localhost:9090/metrics | grep warmor_events_total
```

## 3. Apply a Policy

Copy one of the [example policies](../examples/policies/) into your values:

```bash
helm upgrade warmor deploy/helm/warmor \
  --namespace warmor-system \
  --set daemon.auditMode=true \
  --set-file policy.yaml=examples/policies/block-crypto-miners.yaml
```

Review the audit logs — denied events are logged but **not enforced** in audit mode.

## 4. Switch to Enforce Mode

Once you're confident the policy won't disrupt workloads:

```bash
helm upgrade warmor deploy/helm/warmor \
  --namespace warmor-system \
  --set daemon.auditMode=false
```

## What's Next

| Goal | Guide |
|------|-------|
| Write custom policies | [Policy Authoring](policy-authoring.md) |
| Enable alerting | Set `alerting.enabled=true` — see [values.yaml](../deploy/helm/warmor/values.yaml) |
| Monitor with Grafana | Set `grafana.dashboardEnabled=true` and `serviceMonitor.enabled=true` |
| Restrict to specific containers | Use `daemon.cgroupFilter` to scope enforcement |
| Deploy per-namespace policies | Install the WarmorPolicy CRD — see [CRD guide](crd-usage.md) |

## Common Operations

```bash
# Check what warmor is seeing (top denied events)
kubectl -n warmor-system logs -l app.kubernetes.io/name=warmor | grep DENY

# Temporarily disable enforcement on a node
kubectl -n warmor-system delete pod <pod-name>  # respawns in audit mode if set

# Rollback
helm rollback warmor -n warmor-system

# Uninstall
helm uninstall warmor -n warmor-system
```

## Sizing Guide

| Cluster Size | CPU Request | Memory Request | Notes |
|-------------|-------------|----------------|-------|
| < 50 nodes  | 100m        | 128Mi          | Default values |
| 50-200 nodes | 200m       | 256Mi          | Increase if high event rate |
| 200+ nodes  | 500m        | 512Mi          | Consider per-namespace policies |

Warmor runs as a DaemonSet — one pod per node. Resource usage scales with event rate, not cluster size.
