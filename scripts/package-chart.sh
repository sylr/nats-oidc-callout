#!/usr/bin/env bash
# Package the Helm chart exactly the way the release workflow does, then assert
# that the packaged chart's default image is one goreleaser actually publishes.
#
# usage: scripts/package-chart.sh <git-tag> <output-dir>   (e.g. v1.2.3-rc.1)
#
# Prints the path of the packaged .tgz on stdout; diagnostics go to stderr.
# Used by both release.yml (before `helm push`) and the CI helm job (with
# sample tags), so the packaging flags live in exactly one place.
#
# Contract: goreleaser publishes ghcr.io/sylr/nats-oidc-callout:v{{ .Version }}
# where .Version is the git tag minus its leading "v". The chart `version` must
# be plain SemVer (no "v"), but `appVersion` -- the default image tag -- must
# keep the "v", i.e. equal the git tag verbatim. Stable and prerelease tags
# follow the same rule.
set -euo pipefail

tag="${1:?usage: $0 <git-tag> <output-dir>}"
out="${2:?usage: $0 <git-tag> <output-dir>}"
root="$(cd "$(dirname "$0")/.." && pwd)"

case "$tag" in
v[0-9]*) ;;
*) echo "tag '$tag' must look like v<semver>" >&2; exit 1 ;;
esac

# Read the publication contract from goreleaser's dockers_v2 block, and fail if
# the tag template drifts from what the chart's appVersion convention assumes.
block="$(sed -n '/^dockers_v2:/,/^[a-z]/p' "$root/.goreleaser.yaml")"
if ! grep -qxF -- '  - "v{{ .Version }}"' <<<"$block"; then
  echo "goreleaser dockers_v2 tags are no longer exactly v{{ .Version }}; update scripts/package-chart.sh and the chart appVersion convention" >&2
  exit 1
fi
repo="$(sed -n 's/^  - "\(ghcr\.io\/[^"]*\)"$/\1/p' <<<"$block")"

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
helm package "$root/contribs/chart" \
  --version "${tag#v}" --app-version "$tag" -d "$out" >"$log"
cat "$log" >&2
pkg="$(sed -n 's/.*saved it to: //p' "$log")"
test -f "$pkg"

# Render the *packaged* chart (not the source dir) with no image override.
want="$repo:$tag"
got="$(helm template check "$pkg" | sed -n 's/^ *image: "\{0,1\}\([^" ]*\)"\{0,1\}$/\1/p' | sort -u)"
if [ "$got" != "$want" ]; then
  echo "chart for $tag renders image '$got', but goreleaser publishes '$want'" >&2
  exit 1
fi
echo "ok: chart $tag -> $want" >&2
echo "$pkg"
