# nats-oidc-callout production readiness review

## Decision and scope

**Recommendation: hold general production rollout until F01–F04 are resolved.** Four P1 findings affect permission safety, authentication availability, recovery after a broker outage, and installation of the released Helm chart. Three P2 findings concern Kubernetes reloads, AWS credential caching, and the broad-policy guardrail. All seven are open at the reviewed revision.

The existing race suites and static checks pass. The authentication flow has useful safeguards: trusted issuers are configured in advance, token signatures and audiences are checked, unmatched identities are denied, and issued user JWTs cannot outlive the source token. Those safeguards do not prevent the configuration and availability failures below. No signature-verification bypass was confirmed.

This report follows the handoff structure used by [sylr/fix2's production readiness review](https://github.com/sylr/fix2/blob/HEAD/docs/audits/production-readiness-review.md). It preserves findings, evidence boundaries, recommended changes, and acceptance criteria for remediation.

- **Reviewed revision:** `b13ae914f09ccf0a013702b7be128cbfc8b7c897`.
- **Review date:** 22 October 2026.
- **Environment:** macOS arm64. Broad race tests passed with Go 1.27.3 and again with the project's Go 1.26.10 toolchain. Vulnerability scans covered both standard-library versions.
- **Scope:** the service entry point, configuration loading, OIDC verification, claim normalization, policy and CEL evaluation, user-JWT issuance, metrics, both nested client modules, tests, Helm chart, systemd packaging, container packaging, CI, release automation, and operational documentation.
- **Method:** leader inspection, two independent review lanes for authentication/client behavior and deployment/release behavior, existing race suites, vet, lint, isolated diagnostic tests, Helm rendering, GoReleaser validation, coverage measurement, and current vulnerability scans.
- **Repository state:** the audited tree was clean. Diagnostic tests were created outside the repository. This handoff adds only this report; production sources, dependencies, and permanent tests remain unchanged.

Project source links are pinned to the reviewed commit. Dependency links identify the versions inspected. Recheck both before applying a fix to a later revision.

## Remediation status

Every finding has a merged fix on `master`. Each pull request states its own testing and the scenarios it did not exercise.

| Finding | Fix |
| --- | --- |
| F01 — permission typos grant unrestricted access | [#11](https://github.com/sylr/nats-oidc-callout/pull/11) — strict config and policy decoding; omitted permissions deny all |
| F02 — remote key fetches block unrelated authentications | [#14](https://github.com/sylr/nats-oidc-callout/pull/14) — async workers, throttled key set, `verify_timeout` below the broker budget |
| F03 — exhausted reconnects leave an unusable service | [#13](https://github.com/sylr/nats-oidc-callout/pull/13) — reconnect forever, exit on terminal failure, `/healthz` and `/readyz` probes |
| F04 — released charts select an unpublished image tag | [#6](https://github.com/sylr/nats-oidc-callout/pull/6) — `appVersion` keeps the `v` prefix; CI checks the packaged chart against the published tag |
| F05 — Kubernetes reloads read stale files | [#7](https://github.com/sylr/nats-oidc-callout/pull/7) — config and policy mounted as directories; reload contract documented |
| F06 — AWS credential switches reuse the previous token | [#10](https://github.com/sylr/nats-oidc-callout/pull/10) — cache entries bound to the minting credentials |
| F07 — regex alternation bypasses broad-policy acknowledgement | [#9](https://github.com/sylr/nats-oidc-callout/pull/9) — regex subjects and shifted globs no longer count as account pins |
| Dependency observations | [#8](https://github.com/sylr/nats-oidc-callout/pull/8) — bumps `x/crypto`, `klauspost/compress` and `cel-go`; GO-2026-5932 has no fixed version |

[#12](https://github.com/sylr/nats-oidc-callout/pull/12) fixes a related reload bug found while reviewing this report: repeated `SIGHUP` reloads stopped warning about restart-only settings.

## How to use this handoff

1. Inspect the current revision and record whether each finding still applies.
2. Convert each applicable reproduction into a permanent regression test that fails against the reviewed behavior.
3. Fix the underlying cause and preserve the stated compatibility and security constraints.
4. Run the relevant acceptance checks and the project/module verification commands below.
5. Report every finding as resolved, still reproducible, or explicitly constrained by the supported deployment contract.

P1 means a high-priority rollout blocker for the affected deployment. P2 means a material risk requiring remediation or an explicit, tested deployment restriction. These priorities are not CVSS scores.

## High-priority findings

### F01 — P1: permission typos silently grant unrestricted access

**Fixed by:** [#11](https://github.com/sylr/nats-oidc-callout/pull/11).

**Confidence:** high; reproduced through a real embedded NATS server and the callout service.

**Sources:** [policy decoding](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/internal/authz/authz.go#L114), [permission conversion](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/internal/authz/authz.go#L253), [inline configuration decoding](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/internal/config/config.go#L113), [subscribe-only README example](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/README.md#L194).

Both configuration loaders use `yaml.Unmarshal`, which ignores unknown fields. Policy validation checks the account and identity matcher, but does not reject unknown grant fields or require explicit permission intent. A missing allow/deny list becomes an empty NATS permission, which is unrestricted rather than deny-all.

**Reproduction:** load the following standalone policy, authenticate the matching identity, subscribe to `forbidden.topic`, and publish a message there:

```yaml
rules:
- match:
    sub: "arn:aws:iam::123456789012:role/AppRole"
  grant:
    account: APP
    publish:
      alow: ["app.>"]
    subscribe:
      allow: [">"]
```

The misspelled `alow` is accepted. The diagnostic receives the message on `forbidden.topic`, proving unrestricted publishing beyond the intended `app.>` grant. A separate unit diagnostic confirms the resulting publish allow/deny lists are both empty.

**Impact and limits:** an operator mistake can broaden an otherwise narrowly matched grant. Omitting `publish` entirely has the same permission semantics; the README's subscribe-only example does so. This is a configuration-safety failure, not proof that a remote client can change policy or bypass token verification. NATS's empty-permission semantics are intentional; their unsafe implicit use in this configuration surface is the issue.

**Recommended change:** enable strict field validation for inline and external policies, including nested match and grant fields. Require explicit permission intent or make omitted permission directions deny by default. Document migration for existing users who intentionally rely on unrestricted permissions, and correct the examples.

**Acceptance criteria:**

- Unknown fields at every configuration and policy level fail startup; an invalid reload retains the last valid configuration.
- Misspelled permission fields cannot produce a usable grant.
- Omitted publish/subscribe permissions have explicit, documented behavior that cannot accidentally grant unrestricted access.
- End-to-end tests prove restricted, deny-all, and explicitly unrestricted behavior for publishing and subscribing.

### F02 — P1: remote key fetches block unrelated valid authentications

**Fixed by:** [#14](https://github.com/sylr/nats-oidc-callout/pull/14).

**Confidence:** high; reproduced with a warmed key cache, a gated JWKS endpoint, and an embedded NATS server.

**Sources:** [callout service options](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/cmd/nats-oidc-callout/main.go#L118), [token verification](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/internal/verifier/verifier.go#L149), [request timeout](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/internal/callout/callout.go#L55), [pinned callout implementation](https://github.com/synadia-io/callout.go/blob/v0.2.3/authservice.go), [pinned remote key-set implementation](https://github.com/coreos/go-oidc/blob/v3.19.0/oidc/jwks.go).

The service does not configure asynchronous workers or additional endpoints. The pinned callout library therefore invokes the authorizer synchronously on one subscription. An unknown key ID or failed cached signature verification triggers a remote JWKS refresh. While that network request waits, later authentication requests queue, including requests whose signing key is already cached.

The pinned remote key set coalesces concurrent refreshes, but has no cooldown between completed failed lookups. Sequential invalid tokens can each cause another fetch.

**Reproduction:** authenticate a valid token to warm the key cache. Gate the issuer's JWKS handler, submit a token with an unknown `kid`, and wait until its fetch enters the gate. Attempt a second connection with the original valid token. That connection is rejected with `nats: Authorization Violation` after approximately **2.005 seconds**, while the first request still waits for JWKS. Separately, a warm-cache diagnostic followed by four identical unknown-key tokens records **five total JWKS requests**: the initial load plus one per invalid token.

**Impact and limits:** slow or unavailable issuer endpoints cause head-of-line blocking across the instance. Unauthenticated connection attempts can repeatedly exercise the fetch path; a valid issuer signature is not necessary to request an unknown key. The configured ten-second verification budget also exceeds the approximately two-second broker authentication budget in the reproduction. The test demonstrates availability loss, not token acceptance, unbounded memory growth, or a measured production throughput ceiling. Additional replicas increase capacity but do not eliminate the mechanism.

**Recommended change:** provide bounded request concurrency and queue admission, throttle key refreshes after misses, and align verification deadlines with the broker's authentication budget. Preserve legitimate key-rotation recovery and fail-closed behavior. Worker concurrency alone does not prevent repeated failed lookups from saturating all workers.

**Acceptance criteria:**

- A stalled fetch cannot prevent a cached valid identity from authenticating within the supported latency budget.
- Repeated identical and varying invalid key IDs produce bounded outbound JWKS traffic.
- Queue size, concurrency, overload behavior, and verification deadlines are explicit and tested.
- Legitimate rotation recovers within a documented interval, while invalid signatures remain rejected.

### F03 — P1: exhausted reconnects leave an apparently healthy but unusable service

**Fixed by:** [#13](https://github.com/sylr/nats-oidc-callout/pull/13).

**Confidence:** high from application and pinned dependency source inspection; no full-duration outage reproduction was run.

**Sources:** [NATS connection setup](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/cmd/nats-oidc-callout/main.go#L221), [process wait](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/cmd/nats-oidc-callout/main.go#L135), [metrics-based probes](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/contribs/chart/templates/deployment.yaml#L59), [systemd restart policy](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/contribs/systemd/nats-oidc-callout.service#L14), [pinned NATS client defaults](https://github.com/nats-io/nats.go/blob/v1.52.0/nats.go).

`connectNATS` configures credentials and TLS but inherits the client's finite reconnect policy: 60 attempts per server with a two-second base wait. It installs no terminal-closure handler. Once the client gives up, the NATS connection remains closed, while `run` continues waiting only for the OS shutdown context.

The metrics server runs independently. Kubernetes liveness and readiness probes only open its TCP port, so they continue succeeding. Systemd's `Restart=on-failure` also cannot help while the process remains alive.

**Failure scenario:** start the service successfully, make all configured NATS servers unavailable until the reconnect policy is exhausted, then restore them. The closed client does not resume connecting, the process remains alive, and the metrics listener remains available. Outage duration depends on the server pool, failed dial durations, and reconnect jitter; a fixed two-minute failure threshold was not measured.

**Impact and limits:** new client authorizations remain unavailable until the callout process is restarted. Existing authorized connections can continue until their own expiration or other disconnection. This finding concerns terminal closure after successful startup, not ordinary short-outage recovery.

**Recommended change:** reconnect indefinitely under an explicit policy, or terminate with a failure when the connection becomes permanently unusable. Expose readiness based on NATS connectivity and callout-service state, with useful connection lifecycle metrics and logs. Keep liveness distinct from transient dependency readiness to avoid unnecessary restart storms.

**Acceptance criteria:**

- Restore the broker after an outage longer than the configured reconnect budget; authorization recovers automatically without manual intervention.
- Readiness becomes false when the instance cannot serve authorization and returns only when it can.
- Terminal connection closure either starts recovery or exits unsuccessfully so the supervisor can restart the process.
- Tests cover startup failure, transient disconnect, terminal closure, recovery, and shutdown.

### F04 — P1: released Helm charts select an unpublished image tag

**Fixed by:** [#6](https://github.com/sylr/nats-oidc-callout/pull/6).

**Confidence:** high; reproduced by packaging and rendering with the release workflow's arguments.

**Sources:** [release version normalization](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/.github/workflows/release.yml#L84), [chart packaging](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/.github/workflows/release.yml#L101), [chart image selection](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/contribs/chart/templates/deployment.yaml#L43), [published image tag](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/.goreleaser.yaml#L96).

The release workflow strips the leading `v` from the release tag and uses the result for both the chart version and `appVersion`. The Deployment uses `appVersion` verbatim when `image.tag` is unset. GoReleaser publishes only `v{{ .Version }}` image tags.

**Reproduction:** package the chart with `--version 0.0.6 --app-version 0.0.6`, then render the package with no image override. It requests:

```text
ghcr.io/sylr/nats-oidc-callout:0.0.6
```

The corresponding image publication is `ghcr.io/sylr/nats-oidc-callout:v0.0.6`. Helm lint still passes because both references are syntactically valid.

**Impact and limits:** installing artifacts produced solely by this pipeline cannot pull the chart's default image and will encounter an image-pull failure. An explicit `image.tag` override or a separately published unprefixed alias can work around it. The audit did not pull the image or inspect the live registry; the confirmed defect is the mismatch between the two publication paths.

**Recommended change:** preserve the `v` prefix in the chart's application version or consistently publish and select the same tag format. Add a release-contract check using the packaged chart, not only the source chart's default values.

**Acceptance criteria:**

- A chart packaged for a release renders an image reference actually produced by that release.
- A clean install works without `image.tag` overrides.
- Stable and prerelease versions use consistent tags.
- CI detects a future disagreement between chart packaging and image publication.

## Additional production risks

### F05 — P2: Kubernetes signal reloads read stale configuration and policy

**Fixed by:** [#7](https://github.com/sylr/nats-oidc-callout/pull/7).

**Confidence:** high from rendered mount configuration and documented Kubernetes behavior; no live-cluster update test was run.

**Sources:** [file mounts](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/contribs/chart/templates/deployment.yaml#L76), [checksum exclusions](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/contribs/chart/templates/deployment.yaml#L15), [reload guidance](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/contribs/chart/README.md#L88).

Both config and policy files use `subPath` mounts. Kubernetes does not propagate updates into [Secret subPath mounts](https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod) or [ConfigMap subPath mounts](https://kubernetes.io/docs/concepts/configuration/configmap/#mounted-configmaps-are-updated-automatically). A subsequent `SIGHUP` therefore rereads old content and can log a successful reload without applying the changed source resource.

**Failure scenario:** update the mounted Secret or policy ConfigMap without recreating the pod, then signal a reload. The pod still sees the earlier files. With `existingSecret` or `existingConfigMap`, chart checksum annotations do not detect content changes either.

**Impact and limits:** policy revocations and reloadable issuer restrictions can remain stale until pod recreation. Chart-managed changes applied through `helm upgrade` with `restartOnConfigChange: true` can already trigger replacement pods; that path is not the defective zero-restart reload path. Signing keys and NATS connection credentials separately require restart by the binary's documented contract.

**Recommended change:** mount directories or projected volumes that receive updates, then trigger reload after propagation; alternatively support and document restart-based updates consistently. Define the update contract for externally managed resources.

**Acceptance criteria:**

- Update chart-managed and external resources and demonstrate the selected reload or restart behavior in a cluster.
- A removed grant stops authorizing new connections after the documented update interval.
- Tests distinguish successful loading of new content from a successful signal that rereads old content.
- Document that policy changes affect new authorizations; immediate revocation of already-issued sessions is a separate guarantee.

### F06 — P2: AWS credential switches can reuse the previous principal's token

**Fixed by:** [#10](https://github.com/sylr/nats-oidc-callout/pull/10).

**Confidence:** high for cache selection; reproduced with distinct stub STS clients. Real AWS profile switching was not exercised.

**Sources:** [cache use](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/lib/awsauth/awsauth.go#L239), [cache validation](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/lib/awsauth/awsauth.go#L311), [default cache naming](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/lib/awsauth/awsauth.go#L402).

The cache is accepted when its audience matches and it has not expired. No check ties it to the current AWS credentials or principal. `DefaultCachePath` hashes only the audience, so processes running as the same OS user naturally share a path even when their AWS profile or assumed role changes.

**Reproduction:** construct an Admin token source with caching enabled and request a token. Construct a second Reader source with the same audience and cache path, backed by a different stub STS client that would return a Reader token. The second source returns the Admin token; the Reader client's STS call count remains **zero**.

**Impact and limits:** changing AWS credentials can leave NATS operations running under the previous principal until cache replacement or expiry. The wrong identity can be more privileged, or can cause unexpected denial. Caching is optional and disabled when no cache path is configured. This is credential-context confusion within a user's cache, not an established cross-OS-user attack or token-signature bypass. Server verification would still validate any real cached credential normally.

**Recommended change:** scope caching to an explicit credential-identity namespace or bind entries to the intended principal. Avoid presenting an audience-only path as sufficient isolation for multiple profiles. Preserve file permissions and atomic writes.

**Acceptance criteria:**

- Switching between distinct credential contexts cannot silently reuse the prior context's token.
- Processes intentionally sharing one credential context can still reuse its cache.
- Tests cover profile/role separation, audience mismatch, expiry, refresh, and concurrent access.
- Documentation explains cache scope and how to invalidate it after credential changes.

### F07 — P2: regex alternation bypasses broad-policy acknowledgement

**Fixed by:** [#9](https://github.com/sylr/nats-oidc-callout/pull/9).

**Confidence:** high; reproduced by policy validation and evaluation against another account.

**Sources:** [strong-pin decision](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/internal/authz/authz.go#L228), [ARN account extraction](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/internal/authz/authz.go#L277), [subject matcher](https://github.com/sylr/nats-oidc-callout/blob/b13ae914f09ccf0a013702b7be128cbfc8b7c897/internal/authz/authz.go#L294).

`accountPinnedInARN` strips the regex prefix and anchors, then checks only the fifth colon-separated field for a literal account ID. It does not reason about regex alternatives that can match outside that apparent prefix.

**Reproduction:** validate a rule with this subject expression and without `allow_broad`:

```text
re:^arn:aws:iam::123456789012:role/.*|.*$
```

Validation succeeds. Evaluating the rule against `arn:aws:iam::999999999999:role/Other` also succeeds because the second alternative matches the entire subject.

**Impact and limits:** the broad-rule acknowledgement does not enforce its advertised scope for regex rules. An operator-written broad expression can pass as account-pinned. This does not let a token alter policy, and the runtime matcher follows the expression's actual meaning. Independent issuer or required-claim restrictions can still narrow the effective trust set.

**Recommended change:** do not infer account pinning from textual regex splitting. Require broad acknowledgement for regex rules unless structural analysis proves a pin, or require a separate explicit account constraint. Keep glob and exact-subject behavior clear.

**Acceptance criteria:**

- The reproduced expression requires `allow_broad: true` unless another verified constraint provides a valid strong pin.
- Tests cover alternation, grouping, and escaped syntax around apparent ARN prefixes.
- Literal account-pinned globs and intentionally broad acknowledged rules retain their documented behavior.
- Runtime matches remain fully scoped to the subject as documented.

## Dependency observations

**Addressed by:** [#8](https://github.com/sylr/nats-oidc-callout/pull/8).

`govulncheck` completed across the root module and both nested client modules using Go 1.26.10, and also using Go 1.27.3. Neither scan found a reachable vulnerable symbol. Each reported **six distinct advisory IDs** at package or module level:

| Advisory | Dependency and observed scope | Reported fixed version |
| --- | --- | --- |
| [GO-2026-5841](https://pkg.go.dev/vuln/GO-2026-5841) | `github.com/klauspost/compress v1.18.6`; affected `s2` package imported, no affected-symbol trace | `v1.18.7` |
| [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) | `golang.org/x/crypto v0.52.0`; module observation for SSH | `v0.56.0` |
| [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) | `golang.org/x/crypto v0.52.0`; module observation for SSH | `v0.56.0` |
| [GO-2026-6303](https://pkg.go.dev/vuln/GO-2026-6303) | `golang.org/x/crypto v0.52.0`; module observation for SSH | `v0.55.0` |
| [GO-2026-6094](https://pkg.go.dev/vuln/GO-2026-6094) | `github.com/google/cel-go v0.28.1`; module observation for native-type field exposure | `v0.30.0` |
| [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) | `golang.org/x/crypto v0.52.0`; module observation for unmaintained OpenPGP | No fixed version reported |

These are dependency-maintenance observations, not six demonstrated exploitable vulnerabilities in the service. In particular, the CEL advisory is not evidence that this project's string-map CEL environment exposes native struct fields. Update compatible affected dependencies and rerun the scan; assess OpenPGP by actual package usage rather than assuming an unrelated module upgrade removes that advisory. The absence of a symbol trace is not a general security certification.

## Verification completed during the review

| Check | Result |
| --- | --- |
| All three modules, uncached race suites with Go 1.27.3 | Passed, including hermetic callout end-to-end tests |
| All three modules, uncached race suites with Go 1.26.10 | Passed |
| Root and both nested modules, `go vet` | Passed |
| AWS-tagged end-to-end package, `go vet` with `GOWORK=off` | Passed; does not execute real AWS tests |
| Root and both nested modules, `golangci-lint run ./...` | Passed with zero issues |
| `helm lint contribs/chart` | Passed |
| `goreleaser check` | Passed |
| Release-style chart packaging and rendering | Reproduced F04 despite successful lint |
| End-to-end permission-typo diagnostic | Reproduced F01; forbidden publish delivered |
| Gated JWKS end-to-end diagnostic | Reproduced F02; cached valid token's connection rejected |
| Repeated unknown-key diagnostic | Reproduced F02's repeated remote fetches |
| Distinct-principal cache diagnostic | Reproduced F06; Reader source returned Admin token |
| Regex guardrail diagnostic | Reproduced F07; another account matched without broad acknowledgement |
| Root and client dependency scans, both Go versions | No reachable vulnerable symbols; six advisory observations described above |

The diagnostic tests assert the defective behavior and therefore **pass when they reproduce it**. Their successful exit status is not remediation evidence. Permanent regressions should assert the corrected behavior instead.

Coverage measured with `-coverpkg=./internal/...` across the existing root suite was **82.8%** of internal statements, including mock OIDC support. Selected combined coverage was 93.5% for `Authorize` and 92.6% for `Verifier.Verify`. Configuration `Load` and `Validate` had **0%** coverage; the command package has no tests. The existing policy-reload end-to-end test swaps the in-memory ruleset and does not exercise OS signals, file loading, or Kubernetes propagation. Ordinary per-package coverage reports undercount the callout package because its principal coverage comes from the separate end-to-end package.

Initial restricted attempts encountered network/build-cache setup failures, and one overlapping nested lint invocation was refused by the linter's lock. Checks were rerun with the required access or sequentially and passed. Those setup failures are not classified as product defects.

Real GitHub OIDC authentication skipped locally because no Actions token endpoint was present. The real AWS suite is opt-in and was not executed. No live Kubernetes update, registry pull, production systemd installation, full-duration broker outage, Linux execution, long-duration load/soak, or production traffic capacity campaign was performed. No fuzz campaign was run. F03 and F05 are explicitly source/documentation findings rather than completed fault-injection tests.

## Commands for a remediation agent

Run the project's current toolchain from the repository root. Root `./...` does not include tests belonging to nested modules; the explicit workspace paths below do.

```sh
GOTOOLCHAIN=go1.26.10 go test -race -count=1 \
  ./... ./lib/awsauth/... ./lib/k8sauth/...
go vet ./... ./lib/awsauth/... ./lib/k8sauth/...
GOWORK=off go vet -tags e2e_aws ./test/e2e/...

# Run these sequentially: the linter prevents concurrent runs by default.
golangci-lint run ./...
(cd lib/awsauth && golangci-lint run ./...)
(cd lib/k8sauth && golangci-lint run ./...)

helm lint contribs/chart
goreleaser check
GOTOOLCHAIN=go1.26.10 govulncheck -show verbose \
  ./... ./lib/awsauth/... ./lib/k8sauth/...
```

For F04, use a temporary output directory, package with the release arguments, and inspect the rendered reference:

```sh
audit_chart_dir=$(mktemp -d)
helm package contribs/chart --version 0.0.6 --app-version 0.0.6 \
  -d "$audit_chart_dir"
helm template audit "$audit_chart_dir/nats-oidc-callout-0.0.6.tgz"
```

The audited workflow emits the unprefixed tag. A remediation test must compare the rendered reference with the actual image publication contract, including prereleases. Passing Helm schema validation alone does not resolve F04.

## Local reproduction evidence

These paths were created during the audit and may be absent on another machine. The scenarios above are the portable reference; retain useful diagnostics as permanent regression tests during remediation.

| Evidence | Location |
| --- | --- |
| Disposable archive of the audited source | `/private/tmp/nats-audit-source-u6g66hl7` |
| End-to-end permission and gated-JWKS diagnostics | `/private/tmp/nats-audit-source-u6g66hl7/test/e2e/audit_test.go` |
| Principal-switch diagnostic | `/private/tmp/nats-audit-source-u6g66hl7/lib/awsauth/audit_cache_test.go` |
| Permission-decoding and regex diagnostics | `/private/tmp/nats-audit-authz-test.go` |
| Repeated JWKS-fetch diagnostic | `/private/tmp/nats-audit-verifier-test.go` |
| Overlay used for the preceding two diagnostics | `/private/tmp/nats-audit-overlay.json` |
| Combined internal coverage profile | `/private/tmp/nats-audit-coverage.out` |
| Release-style packaged chart | `/private/tmp/nats-readiness-helm/nats-oidc-callout-0.0.6.tgz` |

To rerun the diagnostics in the disposable archive:

```sh
cd /private/tmp/nats-audit-source-u6g66hl7
go test -race -count=1 -run '^TestAudit' -v ./test/e2e
(cd lib/awsauth && go test -race -count=1 \
  -run '^TestAuditPrincipalSwitchReusesPreviousCredentials$' -v ./...)
```

The overlay contains machine-specific absolute paths. Recreate it for a new checkout, or copy the two diagnostic files into their respective packages in a fresh disposable archive. Do not treat these diagnostics as part of the permanent suite or as fixes.

## Conditions for production approval

- F01–F04 are resolved with regression evidence, or affected use cases are explicitly excluded from the supported production contract.
- F05–F07 have a tested disposition for the chosen Kubernetes update mechanism, AWS credential contexts, and policy forms.
- Configuration and signal-based reload tests cover invalid updates, retention of the last good ruleset, and successful application of new restrictions.
- The actual deployment verifies TLS, secret handling, issuer/claim binding, connection recovery, health reporting, and alerting for authorization failures and latency.
- Load and outage tests establish concurrency, queue limits, issuer-fetch behavior, reconnect recovery, and latency relative to the broker's authentication timeout.
- The released chart installs using the corresponding published image without manual tag repair.
- Relevant race, module, lint, vet, packaging, and vulnerability checks pass with remaining observations and external-test skips stated explicitly.

The follow-up report should name the final revision, disposition of each finding, supported deployment assumptions, verification evidence, and remaining production risks.
