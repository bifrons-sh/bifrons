# syntax=docker/dockerfile:1.7
# Demo portal image with operator SPA included.
#
# Upstream portal/cmd/portal/Dockerfile lets corepack pick whatever pnpm it
# wants, which currently resolves to pnpm 11 and rejects the repo's
# lockfile (v6.0, pnpm 8). We pin pnpm 8 explicitly here.

ARG NODE_IMAGE=node:22-alpine
ARG GO_IMAGE=golang:1.27-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

# ---- Stage 1: build the operator SPA -----------------------------------
FROM ${NODE_IMAGE} AS ui-build

WORKDIR /ui

# Pin pnpm to the version that produced the committed lockfile (v9.0).
RUN corepack enable && corepack prepare pnpm@9.12.3 --activate

COPY portal/ui/package.json portal/ui/pnpm-lock.yaml ./
# --ignore-scripts: defense-in-depth against compromised maintainer accounts
# pushing malicious postinstall payloads. None of the SPA deps need native
# build steps so this is safe to keep on permanently.
RUN pnpm install --frozen-lockfile --ignore-scripts

COPY portal/ui/ ./
RUN pnpm exec vite build --outDir /out/dist

# ---- Stage 2: build the Go binary --------------------------------------
FROM ${GO_IMAGE} AS go-build

ARG VERSION="v0.0.0"
ARG COMMIT_HASH="00000000-dirty"
ARG BUILD_TIMESTAMP="1970-01-01T00:00:00+00:00"
ARG PROJECT_URL="https://github.com/babs/bifrons-sh"

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# .dockerignore strips portal/internal/api/ui/dist/, so recreate it from the
# Vite build output.
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
ARG PROJECT_URL="https://github.com/babs/bifrons-sh"

LABEL org.opencontainers.image.source=${PROJECT_URL} \
      org.opencontainers.image.created=${BUILD_TIMESTAMP} \
      org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.revision=${COMMIT_HASH} \
      org.opencontainers.image.title="portal"

COPY --from=go-build /out/portal /portal

USER nonroot:nonroot
EXPOSE 8080 9095

ENTRYPOINT ["/portal"]
