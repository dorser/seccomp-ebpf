BINARY_NAME=seccomp-ebpf
BUILD_DIR=bin

# Create the build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build the Go binary
build: $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/

# Clean up build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Run tests
test:
	go test ./... -v

# Run linting
lint:
	golangci-lint run

# Format the code
fmt:
	go fmt ./...

# Default target to build the binary
all: fmt lint test build

.PHONY: build clean test lint fmt
