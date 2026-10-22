# nats-oidc-callout Helm chart

Deploys [nats-oidc-callout](https://github.com/sylr/nats-oidc-callout) — a NATS
auth-callout service that authenticates clients with OIDC tokens and mints signed
NATS user JWTs.

The service is a **NATS client**: it connects *out* to your NATS server and
answers requests on `$SYS.REQ.USER.AUTH`. It exposes no inbound application
traffic — only an optional Prometheus metrics endpoint — so the chart ships no
Ingress and no client-facing Service.

## Install

```sh
# from a local checkout
helm install my-callout contribs/chart -f my-values.yaml

# or from the OCI registry (once published; --version is the release tag without its `v`)
helm install my-callout oci://ghcr.io/sylr/helm-charts/nats-oidc-callout --version 0.0.6 -f my-values.yaml
```

## Configuration model

The binary is driven by a single config file (`-config`). That file contains
secrets (`issuer_account_seed`, `xkey_seed`, `nats.password`), so the chart
renders the **whole config into a Secret**.

`config.values` is passed through *verbatim* as `config.yaml` — use the exact
schema from [`examples/config.yaml`](../../examples/config.yaml) (snake_case
keys, nested `issuers`, etc.).

### Provide secrets safely

Don't commit seeds into `values.yaml`. Either inject at install time:

```sh
helm install my-callout deploy/chart \
  --set-file config.values.issuer_account_seed=./issuer.seed \
  --set config.values.xkey_seed="$XKEY_SEED" \
  --set config.values.nats.password="$NATS_PASSWORD"
```

…or manage the Secret yourself and reference it:

```yaml
config:
  existingSecret: my-callout-config   # must hold the full config YAML
  existingSecretKey: config.yaml
```

### Policy: inline or separate ConfigMap

By default the policy is inline under `config.values.policy`. To keep it in a
separate (non-secret) ConfigMap instead, set `policy.values` and point the config
at the mounted file:

```yaml
config:
  values:
    policy_file: /etc/nats-oidc-callout/policy.yaml   # replaces config.values.policy
policy:
  values:
    rules:
    - name: k8s-app
      match: { issuer: "https://...", sub: "system:serviceaccount:team:app" }
      grant: { account: APP, publish: { allow: ["app.>"] } }
```

## Key values

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` / `image.tag` | `ghcr.io/sylr/nats-oidc-callout` / `appVersion` | Container image. Released charts set `appVersion` to the git tag with its `v` (e.g. `v0.0.6`), matching the published image tag |
| `replicaCount` | `1` | Replicas (multiple instances share work via the NATS callout queue group) |
| `logLevel` | `info` | `-log-level` flag |
| `config.values` | demo values | Rendered verbatim into the config Secret |
| `config.existingSecret` | `""` | Use an existing Secret instead of rendering one |
| `policy.values` | `{}` | Optional separate policy ConfigMap |
| `metrics.enabled` | `true` | Create the metrics Service + container port/probes |
| `metrics.port` | `9090` | Must match `config.values.metrics.address` |
| `metrics.serviceMonitor.enabled` | `false` | Create a Prometheus Operator ServiceMonitor |
| `restartOnConfigChange` | `true` | Roll pods when the rendered config/policy changes |
| `podDisruptionBudget.enabled` | `false` | Create a PDB (useful with >1 replica) |
| `resources` | 25m / 32Mi req | Container resources |

See [`values.yaml`](./values.yaml) for the complete list.

## Config reload

With `restartOnConfigChange: true` a checksum annotation rolls the pods on every
`helm upgrade` that changes the config or policy. The binary also hot-reloads on
`SIGHUP`, but the distroless image has no shell, so `kubectl exec ... kill` is
not possible — use a controller that signals PID 1 (e.g. `stakater/reloader`
with a signal strategy) if you want zero-restart reloads.
