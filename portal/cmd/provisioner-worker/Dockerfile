# syntax=docker/dockerfile:1.7
# Multi-stage build for provisioner-worker.
# Build from repo root: docker build -f portal/cmd/provisioner-worker/Dockerfile -t provisioner-worker:dev .

ARG GO_IMAGE=golang:1.26-alpine
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
    -o /out/provisioner-worker ./portal/cmd/provisioner-worker

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VERSION=dev
ARG COMMIT_HASH=dev
ARG BUILD_TIMESTAMP=dev
LABEL org.opencontainers.image.source="https://github.com/babs/poc-proxies" \
      org.opencontainers.image.title="provisioner-worker" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT_HASH}" \
      org.opencontainers.image.created="${BUILD_TIMESTAMP}"

COPY --from=build /out/provisioner-worker /provisioner-worker

USER nonroot:nonroot
# No HTTP surface toward users/proxies (spec §8.2); the store is the only
# ingress. A Prometheus metrics port will be added with Workstream F.

ENTRYPOINT ["/provisioner-worker"]
