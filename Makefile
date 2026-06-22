# MazeDNS — build & dev tasks
BINARY  := mazedns
PKG     := ./cmd/mazedns
BIN_DIR := bin
IMAGE   ?= ghcr.io/ipmaze/mazedns
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
build: ## build the binary (no embedded UI)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: build-ui
build-ui: web ## build the binary with the embedded web UI
	CGO_ENABLED=0 go build -tags embed_dist -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: run
run: ## run in master mode without the UI (API only)
	go run $(PKG) --config configs/mazedns.yaml

.PHONY: run-ui
run-ui: web ## run in master mode with the embedded UI
	go run -tags embed_dist $(PKG) --config configs/mazedns.yaml

.PHONY: run-worker
run-worker: ## run in worker mode (resolver + /metrics, no UI/API)
	go run $(PKG) --config configs/mazedns.yaml --mode worker

.PHONY: docker
docker: ## build the container image (single image, master/worker via MAZEDNS_MODE)
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

.PHONY: compose-dev
compose-dev: ## build + run the dev compose (master, UI on :8080)
	docker compose up --build

.PHONY: compose-prod
compose-prod: ## run the production compose (master + worker, pulls the image)
	docker compose -f docker-compose.prod.yml up -d

.PHONY: clean
clean: ## remove build artifacts
	rm -rf $(BIN_DIR) web/dist
