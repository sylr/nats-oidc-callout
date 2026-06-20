# syntax=docker/dockerfile:1
# Build image for the k8s e2e (kind). Unlike the release Dockerfile (which
# consumes goreleaser's pre-staged binary), this compiles from source.
#
# The module download and `go build` use BuildKit cache mounts so the Go module
# and build caches survive across builds. In CI they are persisted between runs
# via buildkit-cache-dance (see .github/workflows/ci.yml); locally they reuse
# the builder's cache. This caches the compile, which Docker layer caching
# cannot once `COPY . .` changes.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
# The root module replaces lib/awsauth with the in-tree nested module, so its
# go.mod must be present for `go mod download` to read the build list (the full
# source arrives with COPY . . below). GOWORK=off keeps this in plain module
# mode; go.work is not copied at this layer anyway.
COPY lib/awsauth/go.mod lib/awsauth/go.sum lib/awsauth/
RUN --mount=type=cache,target=/go/pkg/mod \
    GOWORK=off go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nats-jwt-callout ./cmd/nats-jwt-callout

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/nats-jwt-callout /usr/bin/nats-jwt-callout
ENTRYPOINT ["/usr/bin/nats-jwt-callout"]
