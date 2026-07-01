# MazeDNS — build & dev tasks
CP_PKG    := ./cmd/control-plane
AGENT_PKG := ./cmd/dns-agent
BIN_DIR   := bin
CP_IMAGE    ?= ghcr.io/ipmaze/mazedns-control-plane
AGENT_IMAGE ?= ghcr.io/ipmaze/mazedns-dns-agent
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: fmt
fmt: ## gofmt -s -w
	gofmt -s -w ./cmd ./internal

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: test
test: ## run Go tests
	go test ./...

.PHONY: web
web: ## install + build the frontend (web/dist)
	npm --prefix web install
	npm --prefix web run build

.PHONY: build
build: ## build the dns-agent binary (lean, no UI)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/dns-agent $(AGENT_PKG)

.PHONY: build-cp
build-cp: web ## build the control-plane binary with the embedded web UI
	CGO_ENABLED=0 go build -tags embed_dist -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/control-plane $(CP_PKG)

.PHONY: run-cp
run-cp: web ## run the control plane with the embedded UI (:8080, no DNS)
	go run -tags embed_dist $(CP_PKG) --config configs/mazedns.yaml

.PHONY: run-agent
run-agent: ## run a dns-agent (resolver + /metrics, no UI/API) on :5300
	MAZEDNS_LISTEN_PORT=5300 go run $(AGENT_PKG) --config configs/mazedns.yaml

.PHONY: docker
docker: ## build both container images (control-plane + dns-agent)
	docker build --target control-plane --build-arg VERSION=$(VERSION) -t $(CP_IMAGE):$(VERSION) -t $(CP_IMAGE):latest .
	docker build --target dns-agent     --build-arg VERSION=$(VERSION) -t $(AGENT_IMAGE):$(VERSION) -t $(AGENT_IMAGE):latest .

.PHONY: compose-dev
compose-dev: ## build + run the dev cluster (control plane UI on :8080 + 2 agents)
	docker compose up --build

.PHONY: compose-cp
compose-cp: ## build + run only the control plane (UI on :8080)
	docker compose up --build control-plane

.PHONY: compose-prod
compose-prod: ## run the production compose (control plane + agent, pulls the images)
	docker compose -f docker-compose.prod.yml up -d

.PHONY: clean
clean: ## remove build artifacts
	rm -rf $(BIN_DIR) web/dist
