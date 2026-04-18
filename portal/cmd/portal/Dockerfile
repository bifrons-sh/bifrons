# syntax=docker/dockerfile:1.7
# Multi-stage build for portal.
# Build from repo root: docker build -f portal/cmd/portal/Dockerfile -t portal:dev .

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
    -o /out/portal ./portal/cmd/portal

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/babs/poc-proxies" \
      org.opencontainers.image.title="portal" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/portal /portal

USER nonroot:nonroot
# 8080 = portal HTTP API, 9095 = Prometheus metrics sidecar.
EXPOSE 8080 9095

ENTRYPOINT ["/portal"]
