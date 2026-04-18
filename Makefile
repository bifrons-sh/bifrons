SHELL := /bin/bash
GO      ?= go
PKGS    := ./...

VERSION         ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
COMMIT          ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_TIMESTAMP ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILDER         ?= $(shell whoami)@$(shell hostname)

LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.Commit=$(COMMIT)' \
	-X 'main.BuildTimestamp=$(BUILD_TIMESTAMP)' \
	-X 'main.Builder=$(BUILDER)'

PROXY_BINS  := mysql-proxy postgres-proxy mongo-proxy
PORTAL_BIN  := portal

.PHONY: all build proxies portal test race vet e2e cover lint tidy clean \
        docker docker-mysql-proxy docker-postgres-proxy docker-mongo-proxy docker-portal

all: vet test build

build: proxies portal

proxies: $(addprefix bin/,$(PROXY_BINS))

portal: bin/$(PORTAL_BIN)

bin:
	mkdir -p $@

bin/mysql-proxy bin/postgres-proxy bin/mongo-proxy: bin/%: cmd/% | bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $@ ./$<

bin/$(PORTAL_BIN): portal/cmd/portal | bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $@ ./$<

vet:
	$(GO) vet $(PKGS)
	$(GO) vet -tags=e2e $(PKGS)

test:
	$(GO) test -count=1 $(PKGS)

race:
	$(GO) test -race -count=1 $(PKGS)

e2e:
	$(GO) test -tags=e2e -timeout=600s -count=1 ./e2e/...

# Merged unit + e2e coverage across all packages. Requires gocovmerge:
#   go install github.com/wadey/gocovmerge@latest
cover:
	$(GO) test -covermode=atomic -coverprofile=coverage-unit.out -coverpkg=./... -count=1 $(PKGS)
	$(GO) test -tags=e2e -covermode=atomic -coverprofile=coverage-e2e.out -coverpkg=./... -count=1 -timeout=600s ./e2e/...
	gocovmerge coverage-unit.out coverage-e2e.out > coverage.out
	$(GO) tool cover -func=coverage.out | tail -3

lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin/ coverage*.out

# Docker image builds. Each Dockerfile is invoked from the repo root so the
# build context covers the whole module tree (cmd/, portal/, internal/).
DOCKER_BUILD_ARGS := \
	--build-arg VERSION=$(VERSION) \
	--build-arg COMMIT=$(COMMIT) \
	--build-arg BUILD_TIMESTAMP=$(BUILD_TIMESTAMP)

docker: docker-mysql-proxy docker-postgres-proxy docker-mongo-proxy docker-portal

docker-mysql-proxy:
	docker build $(DOCKER_BUILD_ARGS) -f cmd/mysql-proxy/Dockerfile -t mysql-proxy:$(VERSION) -t mysql-proxy:dev .

docker-postgres-proxy:
	docker build $(DOCKER_BUILD_ARGS) -f cmd/postgres-proxy/Dockerfile -t postgres-proxy:$(VERSION) -t postgres-proxy:dev .

docker-mongo-proxy:
	docker build $(DOCKER_BUILD_ARGS) -f cmd/mongo-proxy/Dockerfile -t mongo-proxy:$(VERSION) -t mongo-proxy:dev .

docker-portal:
	docker build $(DOCKER_BUILD_ARGS) -f portal/cmd/portal/Dockerfile -t portal:$(VERSION) -t portal:dev .
