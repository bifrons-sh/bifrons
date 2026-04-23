# syntax=docker/dockerfile:1.7
# Multi-stage build for mongo-proxy.
# Build from repo root: docker build -f cmd/mongo-proxy/Dockerfile -t mongo-proxy:dev .

ARG GO_IMAGE=golang:1.26-alpine
FROM ${GO_IMAGE} AS build

ARG VERSION=dev
ARG COMMIT_HASH=dev
ARG BUILD_TIMESTAMP=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.CommitHash=${COMMIT_HASH} -X main.BuildTimestamp=${BUILD_TIMESTAMP} -X main.Builder=docker" \
    -o /out/mongo-proxy ./cmd/mongo-proxy

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/babs/poc-proxies" \
      org.opencontainers.image.title="mongo-proxy" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/mongo-proxy /mongo-proxy

USER nonroot:nonroot
# 37017 = Mongo proxy listener, 9091 = Prometheus metrics sidecar.
EXPOSE 37017 9091

ENTRYPOINT ["/mongo-proxy"]
