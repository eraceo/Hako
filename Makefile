# ==============================================================================
# Hako - Secure CLI Password Manager
# ==============================================================================

.PHONY: all build build-linux build-windows build-static deps test-unit test-integration test-coverage benchmark lint security-check check fmt clean install uninstall dev-build run-dev release snapshot help

# Variables
GO ?= go
BINARY_NAME = hako
BUILD_DIR = build
MAIN_PATH = ./cmd/hako
MODULE_NAME := $(shell $(GO) list -m)

# Versioning and Build Metadata
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Build Flags
# -s -w: Strip debug information and symbol tables (reduces binary size and reverse-engineering surface).
# -X: Inject build metadata into the internal/version package.
LDFLAGS = -s -w \
	-X $(MODULE_NAME)/internal/version.Version=$(VERSION) \
	-X $(MODULE_NAME)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE_NAME)/internal/version.Date=$(DATE)

# Security Flags:
# -trimpath: Removes local file system paths from the compiled executable.
SECURE_BUILD_FLAGS = -trimpath -ldflags="$(LDFLAGS)"
STATIC_BUILD_FLAGS = -trimpath -ldflags="$(LDFLAGS) -extldflags '-static'"

# Default target
all: help

## build: Build the application (native OS)
build:
	@echo "=> Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(SECURE_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

## build-linux: Cross-compile for Linux (amd64)
build-linux:
	@echo "=> Building Linux $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(SECURE_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PATH)

## build-windows: Cross-compile for Windows (amd64)
build-windows:
	@echo "=> Building Windows $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(SECURE_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PATH)

## build-static: Build static binary for release (Used by CI)
build-static:
	@echo "=> Building static $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux $(GO) build $(STATIC_BUILD_FLAGS) -a -tags netgo -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

## deps: Install and tidy dependencies
deps:
	@echo "=> Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy

## test-unit: Run unit tests
test-unit:
	@echo "=> Running unit tests..."
	$(GO) test -v -short ./...

## test-integration: Run integration tests (located in test/)
test-integration:
	@echo "=> Running integration tests..."
	$(GO) test -v ./test/...

## test-coverage: Run unit tests and generate HTML coverage report
test-coverage:
	@echo "=> Running tests with coverage..."
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

## benchmark: Run memory allocation benchmarks (Check Zero-Allocations)
benchmark:
	@echo "=> Running benchmarks..."
	$(GO) test -bench . -benchmem ./internal/crypto/... ./internal/memory/...

## lint: Run golangci-lint
lint:
	@echo "=> Running linters..."
	golangci-lint run

## security-check: Run gosec and govulncheck
security-check:
	@echo "=> Running security checks..."
	gosec -exclude-dir=test ./...
	govulncheck ./...

## check: Run format, lint, security checks, and unit tests (Pre-commit)
check: fmt lint security-check test-unit

## fmt: Format code using go fmt
fmt:
	@echo "=> Formatting code..."
	$(GO) fmt ./...

## clean: Clean build artifacts
clean:
	@echo "=> Cleaning artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

## install: Install the binary to standard Go bin directory ($GOPATH/bin)
install:
	@echo "=> Installing $(BINARY_NAME)..."
	$(GO) install $(SECURE_BUILD_FLAGS) $(MAIN_PATH)

## dev-build: Build development version with Race Detector
dev-build:
	@echo "=> Building development version (with race detector)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 $(GO) build -race -trimpath -ldflags="-X $(MODULE_NAME)/internal/version.Version=dev" -o $(BUILD_DIR)/$(BINARY_NAME)-dev $(MAIN_PATH)

## dev-run: Build and run development version
dev-run: dev-build
	./$(BUILD_DIR)/$(BINARY_NAME)-dev

## release: Create release with goreleaser
release:
	@echo "=> Creating release..."
	goreleaser release --clean

## snapshot: Create snapshot release with goreleaser
snapshot:
	@echo "=> Creating snapshot release..."
	goreleaser release --snapshot --clean

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)