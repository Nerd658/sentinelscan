.PHONY: all build test clean docker-up docker-down lint run-api run-scanner

GO ?= /usr/local/go/bin/go

all: test build

build:
	@echo "Building binaries..."
	$(GO) build -o bin/api ./cmd/api
	$(GO) build -o bin/scanner ./cmd/scanner

test:
	@echo "Running unit tests..."
	$(GO) test -v ./...

test-e2e:
	@echo "Running E2E Lab Test Suite..."
	$(GO) test -v ./tests/e2e/...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/ /tmp/api /tmp/scanner

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down -v

run-api:
	$(GO) run ./cmd/api

run-scanner:
	$(GO) run ./cmd/scanner
