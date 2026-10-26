# nats-oidc-callout Helm chart

Deploys [nats-oidc-callout](https://github.com/sylr/nats-oidc-callout) — a NATS
auth-callout service that authenticates clients with OIDC tokens and mints signed
NATS user JWTs.

The service is a **NATS client**: it connects *out* to your NATS server and
answers requests on `$SYS.REQ.USER.AUTH`. It exposes no inbound application
traffic — only an optional Prometheus metrics endpoint, which also serves the
health probes — so the chart ships no Ingress and no client-facing Service.

## Install

```sh
# from a local checkout
helm install my-callout contribs/chart -f my-values.yaml

# or from the OCI registry (once published; --version is the release tag without its `v`)
helm install my-callout oci://ghcr.io/sylr/helm-charts/nats-oidc-callout --version 0.0.6 -f my-values.yaml
```

## Configuration model

The binary is driven by a single config file (`-config`). That file contains
secrets (`issuer_account_seed`, `xkey_seed`, `nats.password` or
`nats.nkey_seed`), so the chart
renders the **whole config into a Secret**.

`config.values` is passed through *verbatim* as `config.yaml` — use the exact
schema from [`examples/config.yaml`](../../examples/config.yaml) (snake_case
keys, nested `issuers`, etc.).

### Provide secrets safely

Don't commit seeds into `values.yaml`. Either inject at install time:

```sh
helm install my-callout contribs/chart \
  --set-file config.values.issuer_account_seed=./issuer.seed \
  --set config.values.xkey_seed="$XKEY_SEED" \
  --set config.values.nats.username=auth \
  --set config.values.nats.password="$NATS_PASSWORD"
```

The chart sets no NATS authentication by default. Set exactly one of
`nats.username`/`nats.password`, `nats.nkey_seed` or `nats.credentials`; the
service refuses to start with more than one. For an nkey, replace the two
`nats.*` flags above with:

```sh
  --set-file config.values.nats.nkey_seed=./auth-user.seed
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
    policy_file: /etc/nats-oidc-callout/policy/policy.yaml   # replaces config.values.policy
policy:
  values:
    rules:
    - name: k8s-app
      match: { issuer: "https://...", sub: "system:serviceaccount:team:app" }
      grant:
        account: APP
        publish: { allow: ["app.>"] }
        subscribe: { allow: ["app.>", "_INBOX.>"] }  # omit a direction to deny it entirely
```

The binary decodes the config and policy strictly: an unknown or misspelt key
(e.g. `alow`, `require_claim`) makes the pod fail to start, and a hot reload
with such a key is rejected while the previous config keeps serving.

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
| `livenessProbe.enabled` | `true` | HTTP `GET /healthz` on the metrics port (requires `metrics.enabled`) |
| `readinessProbe.enabled` | `true` | HTTP `GET /readyz` on the metrics port (requires `metrics.enabled`) |
| `restartOnConfigChange` | `true` | Roll pods when the rendered config/policy changes |
| `podDisruptionBudget.enabled` | `false` | Create a PDB (useful with >1 replica) |
| `resources` | 25m / 32Mi req | Container resources |

See [`values.yaml`](./values.yaml) for the complete list.

## Health probes

The probes are served by the same HTTP server as the metrics, so they need
`metrics.enabled: true` (and `config.values.metrics.enabled: true`).

- **Liveness** (`/healthz`) answers 200 while the process is up. It does not
  depend on NATS, so a broker outage does not restart the pod.
- **Readiness** (`/readyz`) answers 200 only while the service's NATS
  connection is up and the callout service is running, 503 otherwise. During a
  broker outage the pod turns unready and the client keeps reconnecting; it
  becomes ready again on its own once the broker is back.

The service never gives up reconnecting. If the connection is closed for good
anyway (for instance the broker rejects the service's credentials twice in a
row), or the broker revokes the service's subscription to `$SYS.REQ.USER.AUTH`,
the process exits non-zero and Kubernetes restarts the container.

## Config reload

Two ways to apply a config or policy change:

**Rollout (default).** With `restartOnConfigChange: true` a checksum annotation
rolls the pods on every `helm upgrade` that changes the *chart-rendered* config
Secret or policy ConfigMap. The chart cannot see the content of resources it does
not render, so with `config.existingSecret` or `policy.existingConfigMap` no
checksum is added and a change to them does **not** restart anything — roll the
pods yourself (`kubectl rollout restart`) or use the hot reload below.

**Hot reload (`SIGHUP`, no restart).** The binary re-reads the config and policy
files on `SIGHUP`, but the distroless image has no shell, so
`kubectl exec ... kill` is not possible — use a controller that signals PID 1
(e.g. `stakater/reloader` with a signal strategy). Things to know:

- The config Secret is mounted at `/etc/nats-oidc-callout/config/config.yaml` and
  the policy ConfigMap under `/etc/nats-oidc-callout/policy/` (one file per key:
  `policy.yaml`, or your `policy.existingConfigMapKey`), both as whole
  directories (no `subPath`) so Kubernetes refreshes them in running pods.
  `subPath` mounts are never updated, which would make a `SIGHUP` re-read stale
  content while logging a successful reload. Do not mount over these paths with
  `subPath` in `extraVolumeMounts`.
- Propagation is not instant: the kubelet syncs mounted Secrets/ConfigMaps
  periodically (sync period, 1m by default) plus the kubelet's cache TTL, so a
  change can take on the order of a minute or more to appear in the pod. Send the
  `SIGHUP` only **after** the new file content is visible; a signal sent earlier
  re-reads the old content. If you use a reload controller, make sure it waits for
  propagation (or signals again later).
- A reload affects *new* authorizations only. Already-issued user JWTs / existing
  NATS connections are not revoked.
- Signing keys (`issuer_account_seed`, `xkey_seed`) and NATS connection settings
  cannot be hot-reloaded and still require a restart.

Upgrading from a chart version that mounted `/etc/nats-oidc-callout/policy.yaml`:
change `policy_file` to `/etc/nats-oidc-callout/policy/<key>` (`policy.yaml`
unless you set `policy.existingConfigMapKey`). With `config.existingSecret`, edit
`policy_file` inside **your** Secret before upgrading; the chart cannot rewrite
it, and pods would otherwise fail to load the policy. The `-config` path is
handled by the chart itself. `extraVolumeMounts` that reused the chart's `policy`
or `config` volume via `subPath` keep working, but their files will not refresh
either.

## Upgrading

### NATS authentication no longer has defaults

The chart used to default `config.values.nats.username` to `auth` and
`config.values.nats.password` to `change-me`. It now sets neither, so that an
override can pick `nats.nkey_seed` or `nats.credentials` without inheriting a
username. If your values only set `config.values.nats.password` and relied on the
default username, add it explicitly before upgrading:

```yaml
config:
  values:
    nats:
      username: auth
```

Otherwise the pod fails to start with `nats.password requires nats.username`.
With `config.existingSecret` the chart defaults do not apply, but the service
applies the same check to your Secret's config: a `password` without a
`username` there fails too.
