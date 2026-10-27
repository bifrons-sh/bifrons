# syntax=docker/dockerfile:1.7
# Multi-stage build for mysql-proxy.
# Build from repo root: docker build -f cmd/mysql-proxy/Dockerfile -t mysql-proxy:dev .

ARG GO_IMAGE=golang:1.27-alpine
FROM ${GO_IMAGE} AS build

# Build metadata injected via --build-arg; mirrors Makefile ldflags.
ARG VERSION=dev
ARG COMMIT_HASH=dev
ARG BUILD_TIMESTAMP=dev

WORKDIR /src

# Cache modules separately for better layer reuse.
COPY go.mod go.sum ./
RUN go mod download

# Bring in the full source tree; .dockerignore trims noise.
COPY . .

# CGO off for a fully static binary compatible with distroless/static.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.CommitHash=${COMMIT_HASH} -X main.BuildTimestamp=${BUILD_TIMESTAMP} -X main.Builder=docker" \
    -o /out/mysql-proxy ./cmd/mysql-proxy

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/babs/poc-proxies" \
      org.opencontainers.image.title="mysql-proxy" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/mysql-proxy /mysql-proxy

USER nonroot:nonroot
# 13306 = MySQL proxy listener, 9091 = Prometheus metrics sidecar.
EXPOSE 13306 9091

ENTRYPOINT ["/mysql-proxy"]
