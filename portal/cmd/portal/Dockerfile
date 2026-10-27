# syntax=docker/dockerfile:1.7
# Multi-stage build for portal.
#   Stage 1 (ui-build) — Vite SPA bundle.
#   Stage 2 (go-build) — static portal binary embedding the bundle.
#   Stage 3 (runtime)  — distroless non-root.
# Build from repo root: docker build -f portal/cmd/portal/Dockerfile -t portal:dev .

ARG NODE_IMAGE=node:22-alpine
ARG GO_IMAGE=golang:1.27-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

# ---- Stage 1: build the operator SPA -----------------------------------
FROM ${NODE_IMAGE} AS ui-build

WORKDIR /ui

# Pin pnpm via corepack — reproducible across hosts and CI runners.
RUN corepack enable

# Manifest-first copy so the heavy install layer caches independently of
# source edits. Subsequent edits to *.ts only invalidate the build step.
COPY portal/ui/package.json portal/ui/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY portal/ui/ ./

# Override Vite's outDir so the bundle lands in a clean, predictable
# location regardless of the host repo's relative layout assumption in
# vite.config.ts. The Go stage copies from /out/dist verbatim.
RUN pnpm exec vite build --outDir /out/dist

# ---- Stage 2: build the Go binary --------------------------------------
FROM ${GO_IMAGE} AS go-build

ARG VERSION="v0.0.0"
ARG COMMIT_HASH="00000000-dirty"
ARG BUILD_TIMESTAMP="1970-01-01T00:00:00+00:00"

WORKDIR /src

# Module-graph layer cached independently of source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Drop the freshly-built bundle into the embedded dist/. Anything that
# may have leaked in from the build context (real or stale) is wiped
# first so `go:embed all:dist` only sees the artefacts we just built.
RUN rm -rf portal/internal/api/ui/dist && mkdir -p portal/internal/api/ui/dist
COPY --from=ui-build /out/dist/ portal/internal/api/ui/dist/

ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.CommitHash=${COMMIT_HASH} -X main.BuildTimestamp=${BUILD_TIMESTAMP} -X main.Builder=docker" \
    -o /out/portal ./portal/cmd/portal

# ---- Stage 3: distroless runtime ---------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime

ARG VERSION="v0.0.0"
ARG COMMIT_HASH="00000000-dirty"
ARG BUILD_TIMESTAMP="1970-01-01T00:00:00+00:00"
ARG PROJECT_URL="https://github.com/babs/poc-proxies"

LABEL org.opencontainers.image.source=${PROJECT_URL}
LABEL org.opencontainers.image.created=${BUILD_TIMESTAMP}
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${COMMIT_HASH}
LABEL org.opencontainers.image.title="portal"

COPY --from=go-build /out/portal /portal

USER nonroot:nonroot
# 8080 = portal HTTP API, 9095 = Prometheus metrics sidecar.
EXPOSE 8080 9095

ENTRYPOINT ["/portal"]
