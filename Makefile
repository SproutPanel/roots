.PHONY: build build-release build-all clean install test tidy

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 'dev')
LDFLAGS := -s -w -X github.com/sproutpanel/roots/internal/version.Version=$(VERSION)

# Build the roots binary for current platform
build:
	go build -o roots ./cmd/roots

# Build with version info for current platform
build-release:
	go build -ldflags "$(LDFLAGS)" -o roots ./cmd/roots

# Build for a specific platform (usage: make build-platform GOOS=linux GOARCH=amd64)
build-platform:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o roots_$(GOOS)_$(GOARCH)/roots ./cmd/roots

# Build for all release platforms
build-all: build-linux-amd64 build-linux-arm64

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o roots_linux_amd64/roots ./cmd/roots

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o roots_linux_arm64/roots ./cmd/roots

# Create release tarballs
release: build-all
	tar -czvf roots_linux_amd64.tar.gz roots_linux_amd64
	tar -czvf roots_linux_arm64.tar.gz roots_linux_arm64

# Clean build artifacts
clean:
	rm -f roots
	rm -rf roots_linux_amd64 roots_linux_arm64
	rm -f roots_*.tar.gz

# Install to /usr/local/bin (requires sudo)
install: build
	sudo cp roots /usr/local/bin/roots

# Run tests
test:
	go test ./...

# Run go mod tidy
tidy:
	go mod tidy
