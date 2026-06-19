SHELL := /bin/bash
GO      ?= go
PKGS    := ./...

VERSION         ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
COMMIT_HASH     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_TIMESTAMP ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILDER         ?= $(shell whoami)@$(shell hostname)

LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.CommitHash=$(COMMIT_HASH)' \
	-X 'main.BuildTimestamp=$(BUILD_TIMESTAMP)' \
	-X 'main.Builder=$(BUILDER)'

PROXY_BINS  := mysql-proxy postgres-proxy mongo-proxy
PORTAL_BIN  := portal
ENTRA_SYNC_BIN := entra-sync
PROVISIONER_WORKER_BIN := provisioner-worker

DEV_COMPOSE := dev/compose.yml

.PHONY: all build proxies portal entra-sync provisioner-worker test race vet e2e cover lint tidy clean ui \
        docker docker-mysql-proxy docker-postgres-proxy docker-mongo-proxy docker-portal dev-worker dev-worker-logs

all: vet test build

build: proxies portal entra-sync provisioner-worker

proxies: $(addprefix bin/,$(PROXY_BINS))

portal: bin/$(PORTAL_BIN)

entra-sync: bin/$(ENTRA_SYNC_BIN)

provisioner-worker: bin/$(PROVISIONER_WORKER_BIN)

bin:
	mkdir -p $@

bin/mysql-proxy bin/postgres-proxy bin/mongo-proxy: bin/%: cmd/% | bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $@ ./$<

bin/$(PORTAL_BIN): portal/cmd/portal | bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $@ ./$<

bin/$(ENTRA_SYNC_BIN): portal/cmd/entra-sync | bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $@ ./$<

bin/$(PROVISIONER_WORKER_BIN): portal/cmd/provisioner-worker | bin
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

# Build the operator SPA. Intentionally decoupled from `build` so the Go
# binary always compiles regardless of the frontend pipeline's state —
# the embed under portal/internal/api/ui/dist/ falls back to a sibling
# placeholder/ FS (see ui.go) when this target has never been run.
#
# Pre-step prunes stale build artefacts but preserves the tracked
# .gitkeep stub that keeps the directory present on fresh clones (so
# `go:embed all:dist` compiles without ever running pnpm).
UI_DIST := portal/internal/api/ui/dist
ui:
	pnpm -C portal/ui install
	find $(UI_DIST) -mindepth 1 ! -name .gitkeep -delete
	pnpm -C portal/ui build

clean:
	rm -rf bin/ coverage*.out

# Docker image builds. Each Dockerfile is invoked from the repo root so the
# build context covers the whole module tree (cmd/, portal/, internal/).
DOCKER_BUILD_ARGS := \
	--build-arg VERSION=$(VERSION) \
	--build-arg COMMIT_HASH=$(COMMIT_HASH) \
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

# One-command provisioner-worker standup against the SAME store the dev portal
# uses. The dev portal's SQLite lives inside the `portal_data` named volume
# (not bind-mounted to the host), so the only way to share that exact store is
# to run the worker as a compose service on the same volume — a host-local
# `bin/provisioner-worker` couldn't reach the file. This (re)builds and (re)
# starts BOTH demo worker services (worker-1 = mysql+postgres, worker-2 = mongo;
# each beats its own provisioning_workers heartbeat row); run it after
# dev/seed.sh has written dev/worker-config.json + dev/worker-{1,2}.env with the
# real backend IDs so the workers reload them.
dev-worker:
	docker compose -f $(DEV_COMPOSE) up -d --build provisioner-worker provisioner-worker-2

# Tail both workers' logs — watch provisioning happen + the ~10s liveness
# heartbeat. Pairs with `curl …/api/v1/provisioning/workers` for the read-side.
dev-worker-logs:
	docker compose -f $(DEV_COMPOSE) logs -f provisioner-worker provisioner-worker-2
