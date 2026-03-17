BINARY   := k8s-eu-audit
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE     ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS  := -s -w \
  -X github.com/letzcode/k8s-eu-audit/internal/cli.version=$(VERSION) \
  -X github.com/letzcode/k8s-eu-audit/internal/cli.commit=$(COMMIT) \
  -X github.com/letzcode/k8s-eu-audit/internal/cli.date=$(DATE)

.PHONY: build test test-unit test-integration test-coverage lint clean dev-setup install build-all

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/k8s-eu-audit

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/k8s-eu-audit

# All tests
test:
	go test ./... -v -race -count=1

# Unit tests only (fast, no integration)
test-unit:
	go test ./internal/scanner/... ./internal/mapping/... ./internal/scoring/... -v -race -count=1

# Integration tests only
test-integration:
	go test ./internal/integration/... -v -race -count=1

# Tests with coverage report
test-coverage:
	go test ./... -race -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ coverage.out

dev-setup:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go mod download

build-all:
	GOOS=linux   GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)_linux_amd64   ./cmd/k8s-eu-audit
	GOOS=linux   GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)_linux_arm64   ./cmd/k8s-eu-audit
	GOOS=darwin  GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)_darwin_amd64  ./cmd/k8s-eu-audit
	GOOS=darwin  GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)_darwin_arm64  ./cmd/k8s-eu-audit
	GOOS=windows GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)_windows_amd64.exe ./cmd/k8s-eu-audit