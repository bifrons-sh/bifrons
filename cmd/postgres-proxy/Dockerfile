# syntax=docker/dockerfile:1.7
# Multi-stage build for postgres-proxy.
# Build from repo root: docker build -f cmd/postgres-proxy/Dockerfile -t postgres-proxy:dev .

ARG GO_IMAGE=golang:1.26-alpine
FROM ${GO_IMAGE} AS build

ARG VERSION=dev
ARG COMMIT=dev
ARG BUILD_TIMESTAMP=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTimestamp=${BUILD_TIMESTAMP} -X main.Builder=docker" \
    -o /out/postgres-proxy ./cmd/postgres-proxy

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/babs/poc-proxies" \
      org.opencontainers.image.title="postgres-proxy" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/postgres-proxy /postgres-proxy

USER nonroot:nonroot
# 15432 = Postgres proxy listener, 9091 = Prometheus metrics sidecar.
EXPOSE 15432 9091

ENTRYPOINT ["/postgres-proxy"]
