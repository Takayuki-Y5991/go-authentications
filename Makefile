.PHONY: generate test clean build

# Go build tags
BUILD_TAGS := 

# Build settings
GOPATH := $(shell go env GOPATH)
VERSION := $(shell git describe --tags --always --dirty)
COMMIT_HASH := $(shell git rev-parse --short HEAD)

# Build the application
build:
	go build -tags '$(BUILD_TAGS)' -o bin/auth-service ./cmd/auth-service

# Generate code from protobuf
generate:
	buf generate

# Run tests
test:
	go test -v -race ./...

# Run unit tests only
test-unit:
	go test -v ./test/unit/...

# Run integration tests
test-integration:
	go test -v ./test/integration/...

# Clean build artifacts
clean:
	rm -rf bin
	rm -rf gen

# Install development tools
tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/bufbuild/buf/cmd/buf@latest

# Run linter
lint:
	golangci-lint run

# Run linter
lint-fix:
	golangci-lint run --fix

# Run the service locally
run:
	go run ./cmd/auth-service/main.go