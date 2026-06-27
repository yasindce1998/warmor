# Warmor Roadmap

This document outlines planned future enhancements beyond the current release.

## Cloud & Enterprise Integrations

- **Azure Security Center / Defender integration** — Forward policy decisions and threat signals to Azure Defender for unified SOC visibility.
- **MDM/Intune enterprise policy deployment** — Push Warmor policies to endpoints via Microsoft Intune device management profiles.
- **AWS Security Hub integration** — Emit findings in ASFF format for aggregation in Security Hub dashboards.

## Windows Platform

- **Hyper-V isolation for Windows containers** — Extend container binding and policy enforcement to Hyper-V isolated containers.
- **AppContainer full sandbox** — Restrict policy-violating processes to AppContainer isolation rather than process termination.
- **Windows Defender Application Control (WDAC) interop** — Generate supplemental WDAC policies from Warmor learned baselines.

## macOS Platform

- **System Extensions for network filtering** — Use Network Extension framework to enforce network-level policies on macOS.
- **Endpoint Security Framework deep file monitoring** — Extend ESF hooks beyond process events to file-create, file-rename, and mount operations.

## Linux Platform

- **ARM64 eBPF support** — Validate and optimize BPF programs for ARM64 (Graviton, Ampere) kernels.
- **io_uring syscall filtering** — Monitor and enforce policies on io_uring submissions to prevent sandbox bypass.
- **Landlock LSM integration** — Generate Landlock rulesets from Warmor policies for unprivileged sandboxing.

## Policy Engine

- **OPA/Rego policy language support** — Allow writing policies in Rego alongside WASM and YAML.
- **Policy versioning and rollback** — Maintain policy history with one-command rollback to previous versions.
- **Multi-cluster policy federation** — Synchronize policies across Kubernetes clusters with conflict resolution.

## Observability

- **OpenTelemetry trace export** — Emit per-decision traces with full causal chain (process → file → network).
- **Grafana dashboard templates** — Ship pre-built Grafana dashboards for common deployment patterns.
- **Slack/PagerDuty alerting** — Native alert routing for high-severity denials and anomaly detection.
