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

test-e2e-docker:
	@echo "Running True Docker E2E System Test Suite..."
	$(GO) test -v ./tests/e2e/...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/ /tmp/api /tmp/scanner

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down -v

lab-up:
	@echo "Spinning up Docker Lab Environment..."
	docker compose -f tests/e2e/docker-compose.lab.yml up -d --build

lab-down:
	@echo "Tearing down Docker Lab Environment..."
	docker compose -f tests/e2e/docker-compose.lab.yml down -v

run-api:
	$(GO) run ./cmd/api

run-scanner:
	$(GO) run ./cmd/scanner
