.PHONY: build install clean test test-coverage test-unit test-integration test-integration-compile integrations-setup integrations integrations-debug integrations-cli lint lint-python fmt tidy help check-deps

# Binary name
BINARY_NAME=coi

# Build directory
BUILD_DIR=.

# Installation directory
INSTALL_DIR=/usr/local/bin

# Coverage directory
COVERAGE_DIR=coverage

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Version injection
VERSION ?= $(shell (git describe --tags --always --dirty 2>/dev/null || echo "dev") | sed 's/^v//')
LDFLAGS=-ldflags "-X github.com/mensfeld/coi/internal/cli.Version=$(VERSION)"

# Check required system build dependencies.
# - Go toolchain (coi is written in Go).
# - On Linux: pkg-config and libsystemd headers, because coi links libsystemd
#   via cgo (internal/nftmonitor/journalctl.go) for NFT monitoring.
check-deps:
	@if ! command -v go >/dev/null 2>&1; then \
		echo ""; \
		echo "Error: Go toolchain not found"; \
		echo ""; \
		echo "  coi is written in Go and requires the Go compiler to build."; \
		echo ""; \
		echo "  Install options:"; \
		echo "    Official tarball:  https://go.dev/doc/install"; \
		echo "    Ubuntu/Debian:     sudo apt install -y golang-go"; \
		echo "    Fedora/RHEL:       sudo dnf install -y golang"; \
		echo "    Arch:              sudo pacman -S --needed go"; \
		echo "    mise:              mise use -g go@latest"; \
		echo ""; \
		echo "  Note: if Go is installed for your user (e.g. via mise, asdf, or"; \
		echo "  \$$HOME/go/bin) but you are seeing this error, you probably ran"; \
		echo "  'sudo make ...'. sudo strips PATH by default. Run 'make build'"; \
		echo "  as your user instead — the install target copies with sudo only"; \
		echo "  where needed, so rebuilding under sudo is not required."; \
		echo ""; \
		exit 1; \
	fi
	@if [ "$$(uname -s)" = "Linux" ]; then \
		missing=""; \
		if ! command -v pkg-config >/dev/null 2>&1; then \
			missing="pkg-config"; \
		elif ! pkg-config --exists libsystemd 2>/dev/null; then \
			missing="libsystemd development headers"; \
		fi; \
		if [ -n "$$missing" ]; then \
			echo ""; \
			echo "Error: missing build dependency ($$missing)"; \
			echo ""; \
			echo "  coi uses cgo to read the systemd journal for NFT monitoring,"; \
			echo "  so building from source requires pkg-config and the libsystemd"; \
			echo "  development headers."; \
			echo ""; \
			echo "  Ubuntu/Debian:"; \
			echo "    sudo apt install -y pkg-config libsystemd-dev"; \
			echo ""; \
			echo "  Fedora/RHEL:"; \
			echo "    sudo dnf install -y pkgconf-pkg-config systemd-devel"; \
			echo ""; \
			echo "  Arch:"; \
			echo "    sudo pacman -S --needed pkgconf systemd-libs"; \
			echo ""; \
			exit 1; \
		fi; \
	fi

# Build the project
build: check-deps
	@echo "Building $(BINARY_NAME) version $(VERSION)..."
	@mkdir -p internal/image/embedded
	@mkdir -p internal/config/embedded
	@cp profiles/default/config.toml internal/config/embedded/default_config.toml
	@cp testdata/dummy/dummy internal/image/embedded/dummy
	@$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/coi

# Install to system
install: build
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)

# Clean build artifacts
clean:
	@$(GOCLEAN)
	@rm -f $(BUILD_DIR)/$(BINARY_NAME)
	@rm -f $(BUILD_DIR)/claude-on-incus # transitional: pre-0.10 builds created this symlink
	@rm -rf $(COVERAGE_DIR)
	@rm -rf dist
	@rm -rf internal/image/embedded
	@rm -rf internal/config/embedded
	@bash scripts/cleanup-pycache.sh

# Run all tests (unit tests only)
test:
	@echo "Running unit tests (fast tier; Incus-requiring tests are behind //go:build integration)..."
	$(GOTEST) -v -race -short ./...

# Go integration tier: tests tagged //go:build integration. These drive a real
# Incus daemon (and self-skip when it or the coi-default image is absent), so
# they are excluded from the default `make test`. Run this on a host with Incus.
test-integration:
	@echo "Running Go integration tests (-tags integration; needs a local Incus)..."
	$(GOTEST) -v -race -tags integration ./...

# Compile-check the integration tier without running it (no Incus needed). Keeps
# the tagged tests from rotting now that `make test` no longer builds them.
test-integration-compile:
	@echo "Compile-checking Go integration tier (-tags integration)..."
	$(GOVET) -tags integration ./...

# Setup integration test dependencies
integrations-setup:
	@echo "Installing integration test dependencies..."
	@pip install -r tests/support/requirements.txt
	@pip install ruff

# Run integration tests (requires Incus)
integrations: build
	@echo "Running integration tests..."
	@incus info >/dev/null 2>&1 || { echo "Error: cannot reach Incus. Ensure you are in the incus-admin group (log out/in after usermod -aG)."; exit 1; }
	@bash scripts/cleanup-pycache.sh
	@pytest tests/ -v

# Run integration tests with output (for debugging)
integrations-debug: build
	@echo "Running integration tests with output..."
	@incus info >/dev/null 2>&1 || { echo "Error: cannot reach Incus. Ensure you are in the incus-admin group (log out/in after usermod -aG)."; exit 1; }
	@bash scripts/cleanup-pycache.sh
	@pytest tests/ -v -s

# Run only CLI tests (no Incus required)
integrations-cli:
	@echo "Running CLI integration tests..."
	@pytest tests/cli/ -v

# Lint Python tests
lint-python:
	@echo "Linting Python tests..."
	@ruff check tests/
	@ruff format --check tests/

# Run unit tests only (fast)
test-unit:
	@echo "Running unit tests..."
	$(GOTEST) -v -short -race ./...

# Run tests with coverage (unit tests only)
test-coverage:
	@mkdir -p $(COVERAGE_DIR)
	@echo "Running unit tests with coverage..."
	@$(GOTEST) -v -short -race -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	@$(GOCMD) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@$(GOCMD) tool cover -func=$(COVERAGE_DIR)/coverage.out | grep total | awk '{print "Test Coverage: " $$3}'
	@echo "Report: $(COVERAGE_DIR)/coverage.html"

# Tidy dependencies
tidy:
	@$(GOMOD) tidy

# Format code
fmt:
	@$(GOFMT) ./...

# Check formatting
fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "Files need formatting:" && gofmt -l . && exit 1)

# Run linter
lint:
	@which golangci-lint > /dev/null || (echo "Error: golangci-lint not installed" && exit 1)
	@golangci-lint run --timeout 5m

# Run go vet
vet:
	@$(GOVET) ./...

# Check documentation coverage
doc-coverage:
	@bash scripts/doc-coverage.sh

# Run all checks (CI)
check: fmt-check vet lint test

# Run all checks including doc coverage
check-all: check doc-coverage

# Build for multiple platforms
build-all: check-deps
	@echo "Building $(BINARY_NAME) version $(VERSION) for all platforms..."
	@mkdir -p dist
	@mkdir -p internal/image/embedded
	@mkdir -p internal/config/embedded
	@cp profiles/default/config.toml internal/config/embedded/default_config.toml
	@cp testdata/dummy/dummy internal/image/embedded/dummy
	@GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/coi
	@GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/coi
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 ./cmd/coi
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 ./cmd/coi

# Help
help:
	@echo "Available targets:"
	@echo ""
	@echo "Build:"
	@echo "  build         - Build the binary"
	@echo "  build-all     - Build for all platforms"
	@echo "  install       - Install to $(INSTALL_DIR)"
	@echo "  clean         - Remove build artifacts"
	@echo ""
	@echo "Testing (Go):"
	@echo "  test          - Run Go unit tests (fast, no Incus)"
	@echo "  test-unit     - Same as test"
	@echo "  test-coverage - Unit tests with coverage report"
	@echo ""
	@echo "Testing (Integration):"
	@echo "  integrations-setup - Install integration test dependencies"
	@echo "  integrations       - Run integration tests (requires Incus)"
	@echo "  integrations-debug - Run integration tests with output (for debugging)"
	@echo "  integrations-cli   - Run CLI integration tests only (no Incus required)"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt         - Format Go code"
	@echo "  fmt-check   - Check Go code formatting"
	@echo "  vet         - Run go vet"
	@echo "  lint        - Run golangci-lint"
	@echo "  lint-python - Lint and format check Python tests"
	@echo "  check       - Run all checks (fmt, vet, lint, test)"
	@echo ""
	@echo "Maintenance:"
	@echo "  tidy        - Tidy dependencies"
	@echo "  help        - Show this help"

# Default target
.DEFAULT_GOAL := build
