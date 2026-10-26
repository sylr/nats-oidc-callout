# syntax=docker/dockerfile:1
# Build image for the k8s e2e Go client (kind). Compiles ./test/k8s/client from
# source, mirroring the callout image's build (see Dockerfile). The client reads
# its projected service-account token via lib/k8sauth and connects to NATS.
FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
# The root module replaces the in-tree nested modules, so their go.mod files
# must be present for `go mod download` to read the build list (full source
# arrives with COPY . . below). GOWORK=off keeps this in plain module mode.
COPY lib/awsauth/go.mod lib/awsauth/go.sum lib/awsauth/
COPY lib/k8sauth/go.mod lib/k8sauth/go.sum lib/k8sauth/
RUN --mount=type=cache,target=/go/pkg/mod \
    GOWORK=off go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/k8s-client ./test/k8s/client

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/k8s-client /usr/bin/k8s-client
ENTRYPOINT ["/usr/bin/k8s-client"]
