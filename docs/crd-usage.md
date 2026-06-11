# WarmorPolicy CRD Usage

The `WarmorPolicy` Custom Resource Definition lets you manage security policies as native Kubernetes objects, scoped per namespace.

## Prerequisites

- Warmor Helm chart installed (CRD is auto-installed from `crds/`)
- Optional: Enable the admission webhook for policy validation (`webhook.enabled=true`)

## Create a Policy

```yaml
apiVersion: warmor.io/v1alpha1
kind: WarmorPolicy
metadata:
  name: block-miners
  namespace: production
spec:
  name: block-crypto-miners
  version: 1
  description: "Block cryptocurrency miners in production namespace"
  selector:
    matchLabels:
      team: backend
  rules:
    - name: block-known-miners
      event: process
      conditions:
        all:
          - comm: { any_of: ["xmrig", "minerd", "cpuminer"] }
      action: deny
      reason: "Cryptocurrency miner blocked"
    - name: block-mining-ports
      event: network
      conditions:
        all:
          - remote_port: { any_of: [3333, 4444, 14444] }
      action: deny
      reason: "Connection to mining pool blocked"
  defaultAction: allow
```

```bash
kubectl apply -f policy.yaml
```

## Check Status

```bash
# List all policies
kubectl get warmorpolicies -A
# or shorthand:
kubectl get wp -A

# Describe a specific policy
kubectl describe wp block-miners -n production
```

The status section shows:

| Field | Description |
|-------|-------------|
| `phase` | `Pending`, `Active`, or `Error` |
| `nodesApplied` | Number of nodes enforcing this policy |
| `lastApplied` | When the policy was last pushed to nodes |
| `conditions` | Detailed status conditions |

## Scope with Selectors

Use `spec.selector` to target specific pods:

```yaml
spec:
  selector:
    matchLabels:
      app: payment-service
    matchExpressions:
      - key: environment
        operator: In
        values: ["production", "staging"]
```

Pods without matching labels are not affected by the policy.

## Update a Policy

Increment the `spec.version` field when updating:

```yaml
spec:
  version: 2  # was 1
  rules:
    # updated rules...
```

```bash
kubectl apply -f policy.yaml
```

The daemon detects the version change and reloads without restart.

## Delete a Policy

```bash
kubectl delete wp block-miners -n production
```

The daemon reverts to the ConfigMap-based default policy for affected pods.

## Enable Admission Webhook

The webhook validates policies before they're stored in etcd:

```bash
helm upgrade warmor deploy/helm/warmor \
  --set webhook.enabled=true \
  --set webhook.certManager.enabled=true \
  --set webhook.certManager.issuerRef.name=cluster-issuer \
  --set webhook.certManager.issuerRef.kind=ClusterIssuer
```

Invalid policies are rejected with a clear error message at `kubectl apply` time.

## Multiple Policies per Namespace

You can apply multiple `WarmorPolicy` objects in the same namespace. Rules are merged in order of `spec.version` (lowest first). If rules conflict, the policy with the higher version wins.

## Migration from ConfigMap

To move from the Helm values-based policy to CRD-based:

1. Deploy the CRD (automatic with chart install)
2. Create a `WarmorPolicy` resource matching your current ConfigMap policy
3. Set `policySync.source: crd` in values
4. The daemon will prefer CRD policies over the ConfigMap when both exist
