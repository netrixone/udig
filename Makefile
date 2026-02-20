# Go
GO       ?= go
GOFLAGS  ?=
BINARY   := udig
MAIN     := ./cmd/udig
MODULE   := github.com/netrixone/udig

# GeoIP (optional; binary works without it)
GEODB    := IP2LOCATION-LITE-DB1.IPV6.BIN
GEODB_URL := https://download.ip2location.com/lite/$(GEODB).ZIP

# Install location (go install puts binary here)
GOPATH_BIN := $(shell $(GO) env GOPATH)/bin

.PHONY: all build test test-race install release clean fmt vet lint mod-tidy geoip help

all: build test

# Build the binary. Dependencies come from go.mod; no separate download step.
build:
	$(GO) build $(GOFLAGS) -v -o $(BINARY) $(MAIN)

# Run tests (whole module). Use -count=1 to disable cache when needed.
test:
	$(GO) test $(GOFLAGS) -v ./...

# Run tests with race detector (slower, use for local checks).
test-race:
	$(GO) test $(GOFLAGS) -v -race ./...

# Install binary to $(GOPATH)/bin and copy GeoIP DB there if present.
install: test
	$(GO) install $(MAIN)
	@if [ -f $(GEODB) ]; then cp $(GEODB) "$(GOPATH_BIN)"; fi

# Release build: stripped, compressed with UPX. Run tests first.
release: test
	$(GO) build $(GOFLAGS) -ldflags="-s -w" -o $(BINARY)_min $(MAIN)
	upx --brute $(BINARY)_min

# Remove built binaries, GeoIP DB, and test cache.
clean:
	rm -f $(BINARY) $(BINARY)_min $(GEODB)
	$(GO) clean -testcache

# Format code (gofmt -s).
fmt:
	$(GO) fmt ./...
	@gofmt -s -w .

# Run go vet.
vet:
	$(GO) vet ./...

# Run golangci-lint (install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest).
lint:
	golangci-lint run ./...

# Tidy go.mod and go.sum.
mod-tidy:
	$(GO) mod tidy

# Download GeoIP database if missing. Optional for build; needed for full Geo resolution.
geoip:
	@if [ ! -f $(GEODB) ]; then \
		echo "Downloading $(GEODB)..."; \
		wget -q -O tmp.zip "$(GEODB_URL)" && unzip -p tmp.zip $(GEODB) > $(GEODB) && rm tmp.zip; \
	else \
		echo "$(GEODB) already present"; \
	fi

help:
	@echo "Targets:"
	@echo "  all        build + test (default)"
	@echo "  build      compile $(BINARY)"
	@echo "  test       run tests"
	@echo "  test-race  run tests with -race"
	@echo "  install    test, install binary, copy GeoIP if present"
	@echo "  release    stripped + UPX binary"
	@echo "  clean      remove binaries, GeoIP, test cache"
	@echo "  fmt        format code"
	@echo "  vet        go vet"
	@echo "  lint       golangci-lint"
	@echo "  mod-tidy   go mod tidy"
	@echo "  geoip      download GeoIP DB if missing"
	@echo "  help       this message"
